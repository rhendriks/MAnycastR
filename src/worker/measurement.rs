use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::{
    Finished, Instruction, MeasurementType, Origin, ProtocolType, ReplyBatch,
};
use crate::worker::config::{set_unicast_origins, Worker};
use crate::worker::inbound::{inbound, InboundConfig};
use crate::worker::outbound::{outbound, OutboundConfig};
use log::{error, info};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
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
    /// * `instruction` - Instruction containing a definition for a new measurement
    /// * `worker_id` - the unique ID of this worker
    /// * `abort_outbound` - Forcefully signal the outbound thread to stop sending probes
    pub(crate) fn init(
        &mut self,
        instruction: Instruction,
        worker_id: u16,
        abort_outbound: Arc<AtomicBool>,
    ) -> Result<(), Box<dyn Error>> {
        let start = match instruction.instruction_type {
            Some(InstructionType::Start(s)) => s,
            _ => return Err("Received non-start packet for init".into()),
        };

        let m_id = start.m_id;
        let is_ipv6 = start.is_ipv6;
        let p_type = start.p_type();
        let m_type = start.m_type();

        // Channel for sending from inbound to the orchestrator forwarder thread
        let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::unbounded_channel();

        // Replace unspecified unicast addresses in rx_origins, tx_origins with local addresses
        let rx_origins = set_unicast_origins(start.rx_origins, is_ipv6);
        let tx_origins = set_unicast_origins(start.tx_origins, is_ipv6);

        let tx_origin_ids: std::collections::HashSet<_> =
            tx_origins.iter().map(|o| o.origin_id).collect();

        // Start inbound/outbound threads for each origin
        for rx_origin in rx_origins {
            let socket = Self::get_socket(is_ipv6, p_type, rx_origin);

            inbound(
                InboundConfig {
                    m_id,
                    worker_id,
                    p_type,
                    abort_s: self.abort_inbound.clone(),
                    is_traceroute: m_type == MeasurementType::AnycastTraceroute,
                    is_ipv6,
                    is_record: start.is_record,
                    origin_id: rx_origin.origin_id,
                },
                inbound_tx.clone(),
                socket.clone(),
            );

            // See if this origin_id is in tx_origins
            if tx_origin_ids.contains(&rx_origin.origin_id) {
                self.log_probe_details(p_type, &tx_origins);

                // Channel for forwarding tasks to outbound
                let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(1000);
                self.outbound_txs.push(outbound_tx);

                outbound(
                    OutboundConfig {
                        worker_id,
                        abort_outbound: abort_outbound.clone(),
                        m_id,
                        p_type,
                        qname: start.record.clone(),
                        info_url: start.url.clone(),
                        probing_rate: start.rate / tx_origins.len() as u32, // Adjust probing rate for multiple origins
                        is_record: start.is_record,
                        src: rx_origin.src.unwrap(),
                        sport: rx_origin.sport as u16,
                        dport: rx_origin.dport as u16,
                    },
                    outbound_rx,
                    socket,
                );
            }
        }

        // Spawn thread to forward reply batches to the CLI
        let m_id_handle = self.current_m_id.clone();
        let mut grpc_client_clone = self.grpc_client.clone();
        tokio::spawn(async move {
            while let Some(batch) = inbound_rx.recv().await {
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
            inbound_rx.close();
        });

        Ok(())
    }

    /// Print the Origins (i.e., source address and port values) used for this measurement
    ///
    /// # Arguments
    /// * `p_type` - Protocol used
    /// * `origins` - Sending origins used by this Worker
    fn log_probe_details(&self, p_type: ProtocolType, origins: &[Origin]) {
        for origin in origins {
            match p_type {
                ProtocolType::Icmp => info!(
                    "[Worker] Sending {p_type} packets on: {} using ICMP ID {}",
                    origin.src.unwrap(),
                    origin.dport
                ),
                _ => info!(
                    "[Worker] Sending {p_type} on: {}, {}:{}",
                    origin.src.unwrap(),
                    origin.sport,
                    origin.dport
                ),
            }
        }
    }

    /// Obtain a socket.
    /// Type of socket depends on the IP version (IPv4 or IPv6)
    /// And the protocol type (ICMP, UDP, TCP)
    ///
    /// # Arguments
    /// `is_ipv6` - IP version used (true: IPv6)
    /// `p_type` - Protocol type used (ICMP, UDP, or TCP)
    /// `addr` - Addressed used in this measurement (anycast or local unicast address)
    ///
    /// # Returns
    /// Arc<Socket> containing a Socket to send/receive from
    fn get_socket(is_ipv6: bool, p_type: ProtocolType, origin: Origin) -> Arc<Socket> {
        let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };

        // Specify the protocol so the kernel performs this matching
        let protocol = match p_type {
            ProtocolType::Icmp => {
                if is_ipv6 {
                    Protocol::ICMPV6
                } else {
                    Protocol::ICMPV4
                }
            }
            ProtocolType::Tcp => Protocol::TCP,
            ProtocolType::ADns | ProtocolType::ChaosDns => Protocol::UDP,
        };

        // Bind to used source address and source port
        let socket = Socket::new(domain, Type::RAW, Some(protocol))
            .expect("Failed to create raw socket. sudo or raw socket permissions required");

        let addr: IpAddr = (origin.src.as_ref().expect("no src")).into();
        let sock_addr = SockAddr::from(SocketAddr::new(addr, origin.sport as u16));
        socket
            .bind(&sock_addr)
            .expect("Failed to bind socket to address.");

        if is_ipv6 {
            // Receive hop count for incoming IPv6 packets
            socket
                .set_recv_hoplimit_v6(true)
                .expect("Failed to set recv_hop_limit");
            // Send packets with our own IPv6 header (cannot receive IPv6 headers :( )
            socket
                .set_header_included_v6(true)
                .expect("Failed to set header_included_v6");
        } else {
            // Write our own headers (and receive IPv4 headers)
            socket
                .set_header_included_v4(true)
                .expect("Failed to set header_included");
        }

        // Set large buffer sizes
        let buf_size = 10 * 1024 * 1024; // 10  MB
        socket.set_send_buffer_size(buf_size).ok();
        socket.set_recv_buffer_size(buf_size).ok();

        // Set socket as non-blocking
        socket.set_nonblocking(true).expect("Failed to set non-blocking");

        Arc::new(socket)
    }
}
