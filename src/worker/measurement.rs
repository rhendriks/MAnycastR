use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::{Finished, Instruction, Origin, ReplyBatch};
use crate::net::packet::is_in_prefix;
use crate::worker::config::{set_unicast_origins, Worker};
use crate::worker::inbound::{inbound, InboundConfig};
use crate::worker::outbound::{outbound, OutboundConfig};
use crate::worker::SocketChannel;
use crate::ICMP_ID;
use log::{error, info, warn};
use pnet::datalink;
use std::error::Error;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

impl Worker {
    /// Initialize a new measurement by creating outbound and inbound threads, and ensures task results are sent back to the orchestrator.
    ///
    /// Extracts the protocol type from the measurement definition, and determines which source address to use.
    /// Creates a socket to send out probes and receive replies with, calls the appropriate inbound & outbound functions.
    /// Creates an additional thread that forwards task results to the orchestrator.
    ///
    /// # Arguments
    ///
    /// * `instruction` - Instruction containing a definition for a new measurement
    /// * `worker_id` - the unique ID of this worker
    /// * `abort_s` - an optional boolean that is used to signal the outbound thread to stop sending probes
    pub(crate) fn init(
        &mut self,
        instruction: Instruction,
        worker_id: u16,
        abort_s: Option<Arc<AtomicBool>>,
    ) -> Result<(), Box<dyn Error>> {
        let start = match instruction.instruction_type {
            Some(InstructionType::Start(s)) => s,
            _ => return Err("Received non-start packet for init".into()),
        };

        let m_id = start.m_id;
        let is_ipv6 = start.is_ipv6;
        let m_type = start.m_type as u8;
        let is_probing = !start.tx_origins.is_empty();

        // Channel for forwarding tasks to outbound
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(1000);
        self.outbound_tx = Some(outbound_tx);

        // Channel for sending from inbound to the orchestrator forwarder thread
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Replace unspecified unicast addresses in rx_origins, tx_origins with local addresses
        let rx_origins = set_unicast_origins(start.rx_origins, is_ipv6);
        let tx_origins = set_unicast_origins(start.tx_origins, is_ipv6);

        // Look for the interface that uses the listening IP address
        let addr = rx_origins[0].src.unwrap().to_string();
        let interface = self.select_interface(&addr)?;

        // Create raw sockets
        let config = datalink::Config {
            write_buffer_size: 10 * 1024 * 1024, // 10 MB
            read_buffer_size: 10 * 1024 * 1024,  // 10 MB
            ..Default::default()
        };
        let (socket_tx, socket_rx) = match datalink::channel(&interface, config)? {
            SocketChannel::Ethernet(tx, rx) => (tx, rx),
            _ => return Err("Unsupported channel type (expected Ethernet)".into()),
        };

        // Start inbound listening thread
        inbound(
            InboundConfig {
                m_id,
                worker_id,
                m_type,
                origin_map: rx_origins.clone(),
                abort_s: self.abort_s.clone(),
                is_traceroute: start.is_traceroute,
                is_ipv6,
                is_record: start.is_record,
            },
            tx,
            socket_rx,
        );

        // Start outbound sending thread (if this worker is probing)
        if is_probing {
            self.log_probe_details(m_type, &tx_origins);
            outbound(
                OutboundConfig {
                    worker_id,
                    tx_origins,
                    abort_s: abort_s.ok_or("Abort signal required for probing")?,
                    is_latency: start.is_latency,
                    m_id,
                    m_type,
                    qname: start.record,
                    info_url: start.url,
                    if_name: interface.name.clone(),
                    probing_rate: start.rate,
                    origin_map: Some(rx_origins),
                    is_ipv6,
                },
                outbound_rx,
                socket_tx,
            );
        } else {
            info!("[Worker] Not sending probes");
        }

        // Spawn thread to forward reply batches to the CLI
        let m_id_handle = self.current_m_id.clone();
        let mut grpc_client_clone = self.grpc_client.clone();
        tokio::spawn(async move {
            while let Some(batch) = rx.recv().await {
                if batch == ReplyBatch::default() {
                    // Set the current measurement ID to None (no active measurement)
                    if let Ok(mut guard) = m_id_handle.lock() {
                        *guard = None;
                    }
                    info!("[Worker] Letting the orchestrator know that this worker finished the measurement");
                    let _ = grpc_client_clone
                        .measurement_finished(Finished {
                            m_id,
                            worker_id: worker_id.into(),
                        })
                        .await;
                    break;
                }

                if let Err(e) = grpc_client_clone.send_result(batch).await {
                    error!("[Worker] Failed to forward batch: {e}");
                    break;
                }
            }
            rx.close();
        });

        Ok(())
    }

    /// Find the appropriate interface to use.
    /// 1. Use the user-defined parameter interface if present
    /// 2. If not present, attempt to find the interface associated with the address.
    /// 3. Fallback to default interface
    ///
    /// # Arguments
    /// `addr` - Address used to send probes for the new measurement being started
    fn select_interface(&self, addr: &str) -> Result<datalink::NetworkInterface, Box<dyn Error>> {
        let interfaces = datalink::interfaces();

        // Force interface (using parameter)
        if let Some(ref forced_name) = self.interface {
            return interfaces
                .into_iter()
                .find(|i| &i.name == forced_name)
                .ok_or_else(|| format!("Forced interface {} not found", forced_name).into());
        }

        // Find prefix matching the measurement address, return its interface
        if let Some(matched) = interfaces
            .iter()
            .find(|i| i.ips.iter().any(|ip| is_in_prefix(addr, ip)))
        {
            info!(
                "[Worker] Found interface: {} for address {}",
                matched.name, addr
            );
            return Ok(matched.clone());
        }

        //Use default interface (non-loopback)
        let default = interfaces
            .into_iter()
            .find(|i| !i.is_loopback())
            .ok_or("No usable network interfaces found")?;

        warn!(
            "[Worker] No interface found for {}, using default {}",
            addr, default.name
        );
        Ok(default)
    }

    /// Print the Origins (i.e., source address and port values) used for this measurement
    ///
    /// # Arguments
    /// * `m_type` - Measurement type (e.g., ICMP, TCP)
    /// * `origins` - Sending origins used by this Worker
    fn log_probe_details(&self, m_type: u8, origins: &[Origin]) {
        for origin in origins {
            match m_type {
                ICMP_ID => info!(
                    "[Worker] Sending on: {} using ICMP ID {}",
                    origin.src.unwrap(),
                    origin.dport
                ),
                _ => info!(
                    "[Worker] Sending on: {}, {}:{}",
                    origin.src.unwrap(),
                    origin.sport,
                    origin.dport
                ),
            }
        }
    }
}
