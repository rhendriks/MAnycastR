use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::{Finished, Instruction, Origin, TaskResult};
use crate::net::packet::is_in_prefix;
use crate::worker::config::{set_unicast_origins, Worker};
use crate::worker::inbound::{inbound, InboundConfig};
use crate::worker::outbound::{outbound, OutboundConfig};
use crate::worker::SocketChannel;
use crate::{ALL_ID, A_ID, CHAOS_ID, ICMP_ID, TCP_ID};
use log::{info, warn};
use pnet::datalink;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

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
    pub(crate) fn init(
        &mut self,
        start_instruction: Instruction,
        worker_id: u16,
        abort_s: Option<Arc<AtomicBool>>,
    ) {
        let start_measurement =
            if let InstructionType::Start(start) = start_instruction.instruction_type.unwrap() {
                start
            } else {
                panic!("Received non-start packet for init")
            };
        let m_id = start_measurement.m_id;
        let rx_origins: Vec<Origin> = start_measurement.rx_origins;
        let is_probing = !start_measurement.tx_origins.is_empty();
        let qname = start_measurement.record;
        let info_url = start_measurement.url;
        let probing_rate = start_measurement.rate;
        let is_latency = start_measurement.is_latency;
        let is_traceroute = start_measurement.is_traceroute;
        let tx_origins: Vec<Origin> = start_measurement.tx_origins;
        let is_ipv6 = start_measurement.is_ipv6;
        let is_record = start_measurement.is_record;
        // Channel for forwarding tasks to outbound
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(1000);
        self.outbound_tx = Some(outbound_tx);

        // Channel for sending from inbound to the orchestrator forwarder thread
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Get the network interface to use
        let interfaces = datalink::interfaces();

        // Replace unspecified unicast addresses in rx_origins, tx_origins with local addresses
        let rx_origins = set_unicast_origins(rx_origins, is_ipv6);
        let tx_origins = set_unicast_origins(tx_origins, is_ipv6);

        // Look for the interface that uses the listening IP address
        let addr = rx_origins[0].src.unwrap().to_string();
        let interface = if self.interface.is_some() {
            let iface_name = self.interface.as_ref().unwrap();
            let interface = interfaces
                .iter()
                .find(|iface| &iface.name == iface_name)
                .unwrap_or_else(|| panic!("Failed to find forced interface: {}", iface_name));
            info!(
                "[Worker] Using forced interface: {}, for address {addr}",
                interface.name
            );
            interface
        } else if let Some(interface) = interfaces
            .iter()
            .find(|iface| iface.ips.iter().any(|ip| is_in_prefix(&addr, ip)))
        {
            info!(
                "[Worker] Found interface: {}, for address {addr}",
                interface.name
            );
            interface
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

        // Start listening thread
        let config = InboundConfig {
            m_id,
            worker_id,
            m_type: start_measurement.m_type as u8,
            origin_map: rx_origins.clone(),
            abort_s: self.abort_s.clone(),
            is_traceroute,
            is_ipv6,
            is_record,
        };

        inbound(config, tx, socket_rx);

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

            let config = OutboundConfig {
                worker_id,
                tx_origins,
                abort_s: abort_s.unwrap(),
                is_latency,
                m_id,
                m_type: start_measurement.m_type as u8,
                qname,
                info_url,
                if_name: interface.name.clone(),
                probing_rate,
                origin_map: Some(rx_origins),
                is_ipv6,
            };

            // Start sending thread
            outbound(config, outbound_rx, socket_tx);
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
