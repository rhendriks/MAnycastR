use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::{Address, Finished, Instruction, MeasurementType, Origin, ProtocolType, ReplyBatch};
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
        let is_probing = !start.tx_origins.is_empty();
        let p_type = start.p_type();
        let m_type = start.m_type();

        // Channel for forwarding tasks to outbound
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(1000);
        self.outbound_tx = Some(outbound_tx);

        // Channel for sending from inbound to the orchestrator forwarder thread
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Replace unspecified unicast addresses in rx_origins, tx_origins with local addresses
        let rx_origins = set_unicast_origins(start.rx_origins, is_ipv6);
        let tx_origins = set_unicast_origins(start.tx_origins, is_ipv6);

        let socket = Self::get_socket(is_ipv6, p_type, rx_origins.clone());
        // Start inbound listening thread
        inbound(
            InboundConfig {
                m_id,
                worker_id,
                p_type,
                origin_map: rx_origins.clone(),
                abort_s: self.abort_inbound.clone(),
                is_traceroute: m_type == MeasurementType::AnycastTraceroute,
                is_ipv6,
                is_record: start.is_record,
            },
            tx,
            socket.clone(),
        );

        // Start outbound sending thread (if this worker is probing)
        if is_probing {
            self.log_probe_details(p_type, &tx_origins);
            outbound(
                OutboundConfig {
                    worker_id,
                    tx_origins,
                    abort_outbound,
                    m_id,
                    p_type,
                    qname: start.record,
                    info_url: start.url,
                    probing_rate: start.rate,
                    origin_map: Some(rx_origins),
                    is_record: start.is_record,
                },
                outbound_rx,
                socket,
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

    /// Print the Origins (i.e., source address and port values) used for this measurement
    ///
    /// # Arguments
    /// * `p_type` - Protocol used
    /// * `origins` - Sending origins used by this Worker
    fn log_probe_details(&self, p_type: ProtocolType, origins: &[Origin]) {
        for origin in origins {
            match p_type {
                ProtocolType::Icmp => info!(
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
    fn get_socket(is_ipv6: bool, p_type: ProtocolType, origins: Vec<Origin>) -> Arc<Socket> {
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
        let origin = origins.first().expect("nothing to listen for"); // TODO support multiple protocols
        let socket = Socket::new(domain, Type::RAW, Some(protocol))
            .expect("Failed to create raw socket. sudo or raw socket permissions required");

        let addr: IpAddr = (origin.src.as_ref().expect("no src")).into();
        println!("using address {addr}");
        let sock_addr = SockAddr::from(SocketAddr::new(addr, origin.sport as u16));
        println!("binding to {:?}" , &sock_addr);
        socket.bind(&sock_addr).expect("Failed to bind socket to address.");

        if is_ipv6 {
            // Receive hop count for incoming IPv6 packets
            socket.set_recv_hoplimit_v6(true).expect("Failed to set recv_hop_limit");
            socket.set_header_included_v6(true).expect("Failed to set header_included_v6");

            // Allow for setting custom flow labels TODO not used (how to set the flow header instead?)
            // socket.set_tclass_v6(15037).ok();
        } else {
            // Write our own headers
            socket
                .set_header_included_v4(true)
                .expect("Failed to set header_included");
            //Receive TTL for incoming IPv4 packets
            socket
                .set_recv_tos_v4(true)
                .expect("Failed to set recv_ttl");
        }

        // Set large buffer sizes
        let buf_size = 10 * 1024 * 1024; // 10  MB
        socket.set_send_buffer_size(buf_size).ok();
        socket.set_recv_buffer_size(buf_size).ok();

        Arc::new(socket)
    }
}
