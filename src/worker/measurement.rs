use crate::worker::SocketChannel;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;
use local_ip_address::{local_ip, local_ipv6};
use log::{info, warn};
use pnet::datalink;
use crate::custom_module::manycastr::{Address, Finished, Instruction, Origin, TaskResult};
use crate::custom_module::manycastr::instruction::InstructionType;
use crate::{ALL_ID, A_ID, CHAOS_ID, ICMP_ID, TCP_ID};
use crate::net::packet::is_in_prefix;
use crate::worker::config::Worker;
use crate::worker::inbound::{inbound, InboundConfig};
use crate::worker::outbound::{outbound, OutboundConfig};

impl Worker {
    /// Initialize a new measurement by creating outbound and inbound threads, and ensures task results are sent back to the orchestrator.
    ///
    /// Extracts the protocol type from the measurement definition, and determines which source address to use.
    /// Creates a socket to send out probes and receive replies with, calls the appropriate inbound & outbound functions.
    /// Creates an additional thread that forwards task results to the orchestrator.
    ///
    /// # Arguments
    ///
    /// * 'task' - the first 'Task' message sent by the orchestrator, that contains the measurement definition
    ///
    /// * 'worker_id' - the unique ID of this worker
    ///
    /// * 'abort_s' - an optional boolean that is used to signal the outbound thread to stop sending probes
    pub(crate) fn init(&mut self, start_instruction: Instruction, worker_id: u16, abort_s: Option<Arc<AtomicBool>>) {
        let start_measurement = if let InstructionType::Start(start) = start_instruction.instruction_type.unwrap() {
            start
        } else {
            panic!("Received non-start packet for init")
        };
        let m_id = start_measurement.m_id;
        let is_ipv6 = start_measurement.is_ipv6;
        let mut rx_origins: Vec<Origin> = start_measurement.rx_origins;
        let is_unicast = start_measurement.is_unicast;
        let is_probing = !start_measurement.tx_origins.is_empty();
        let qname = start_measurement.record;
        let info_url = start_measurement.url;
        let probing_rate = start_measurement.rate;
        let is_latency = start_measurement.is_latency;
        let is_trace = start_measurement.is_traceroute;

        // Channel for forwarding tasks to outbound
        let outbound_rx = if is_probing {
            let (tx, rx) = tokio::sync::mpsc::channel(1000);
            self.outbound_tx = Some(tx);
            Some(rx)
        } else {
            None
        };

        let tx_origins: Vec<Origin> = if !is_probing {
            vec![]
        } else if is_unicast {
            // Use the local unicast address and CLI defined ports
            let sport = start_measurement.tx_origins[0].sport;
            let dport = start_measurement.tx_origins[0].dport;

            // Get the local unicast address
            let unicast_ip = Address::from(if is_ipv6 {
                local_ipv6().expect("Unable to get local unicast IPv6 address")
            } else {
                local_ip().expect("Unable to get local unicast IPv4 address")
            });

            let unicast_origin = Origin {
                src: Some(unicast_ip), // Unicast IP
                sport,                 // CLI defined source port
                dport,                 // CLI defined destination port
                origin_id: u32::MAX,   // ID for unicast address
            };

            // We only listen to our own unicast address (each worker has its own unicast address)
            rx_origins = vec![unicast_origin];

            info!("[Worker] Using local unicast IP address: {unicast_ip}");
            // Use the local unicast address
            vec![unicast_origin]
        } else {
            // Use the sender origins set by the orchestrator
            start_measurement.tx_origins
        };

        // Channel for sending from inbound to the orchestrator forwarder thread
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Get the network interface to use
        let interfaces = datalink::interfaces();

        // Look for the interface that uses the listening IP address
        let addr = rx_origins[0].src.unwrap().to_string();
        let interface = if let Some(interface) = interfaces
            .iter()
            .find(|iface| iface.ips.iter().any(|ip| is_in_prefix(&addr, ip)))
        {
            info!(
                "[Worker] Found interface: {}, for address {addr}",
                interface.name
            );
            interface // Return the found interface
        } else {
            // Use the default interface (first non-loopback interface)
            let interface = interfaces
                .iter()
                .find(|iface| !iface.is_loopback())
                .expect("Failed to find default interface");
            warn!(
                "[Worker] No interface found for address: {addr}, using default interface {}",
                interface.name
            );
            interface
        };

        // Create a socket to send out probes and receive replies with
        let config = datalink::Config {
            write_buffer_size: 10 * 1024 * 1024, // 10 MB
            read_buffer_size: 10 * 1024 * 1024,  // 10 MB
            ..Default::default()
        };
        let (socket_tx, socket_rx) = match datalink::channel(interface, config) {
            Ok(SocketChannel::Ethernet(socket_tx, socket_rx)) => (socket_tx, socket_rx),
            Ok(_) => panic!("Unsupported channel type"),
            Err(e) => panic!("Failed to create datalink channel: {e}"),
        };

        // Start listening thread (except if it is a unicast measurement and we are not probing)
        if !is_unicast || is_probing {
            if !is_trace {
                let config = InboundConfig {
                    m_id,
                    worker_id,
                    is_ipv6,
                    m_type: start_measurement.m_type as u8,
                    origin_map: rx_origins.clone(),
                    abort_s: self.abort_s.clone(),
                    is_traceroute: start_measurement.is_traceroute,
                };

                inbound(config, tx, socket_rx);
            } else {
                // Trace listening thread TODO
            }
        }

        if is_probing {
            match start_measurement.m_type as u8 {
                ICMP_ID => {
                    // Print all probe origin addresses
                    for origin in tx_origins.iter() {
                        info!(
                            "[Worker] Sending on address: {} using ICMP identifier {}",
                            origin.src.unwrap(),
                            origin.dport
                        );
                    }
                }
                A_ID | TCP_ID | CHAOS_ID | ALL_ID => {
                    // Print all probe origin addresses
                    for origin in tx_origins.iter() {
                        info!(
                            "[Worker] Sending on address: {}, from src port {}, to dst port {}",
                            origin.src.unwrap(),
                            origin.sport,
                            origin.dport
                        );
                    }
                }
                _ => (),
            }

            if !is_trace {
                let config = OutboundConfig {
                    worker_id,
                    tx_origins,
                    abort_s: abort_s.unwrap(),
                    is_ipv6,
                    is_symmetric: is_latency || is_unicast,
                    m_id,
                    m_type: start_measurement.m_type as u8,
                    qname,
                    info_url,
                    if_name: interface.name.clone(),
                    probing_rate,
                    origin_map: Some(rx_origins),
                };

                // Start sending thread
                outbound(config, outbound_rx.unwrap(), socket_tx);
            } else {
                // Trace sending thread TODO
            }
        } else {
            info!("[Worker] Not sending probes");
        }

        let mut self_clone = self.clone(); // TODO can we avoid this clone?
        // Thread that listens for task results from inbound and forwards them to the orchestrator
        thread::Builder::new()
            .name("forwarder_thread".to_string())
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let _enter = rt.enter();

                rt.block_on(async {
                    // Obtain TaskResults from the unbounded channel and send them to the orchestrator
                    while let Some(packet) = rx.recv().await {
                        // A default TaskResult notifies this sender that there will be no more results
                        if packet == TaskResult::default() {
                            self_clone
                                .measurement_finish_to_server(Finished {
                                    m_id,
                                    worker_id: worker_id.into(),
                                })
                                .await
                                .unwrap();

                            break;
                        }

                        self_clone
                            .send_result_to_server(packet)
                            .await
                            .expect("Unable to send task result to orchestrator");
                    }
                    rx.close();
                });
            })
            .expect("Unable to start forwarder thread");
    }
}