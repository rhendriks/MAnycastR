use clap::ArgMatches;
use gethostname::gethostname;
use local_ip_address::{local_ip, local_ipv6};
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::Request;

use pnet::datalink::{self, Channel as SocketChannel};

use custom_module::manycastr::{
    controller_client::ControllerClient, task::Data, Address, End, Finished, Origin, Task,
    TaskResult,
};

use crate::net::packet::is_in_prefix;
use crate::worker::inbound::{inbound, InboundConfig};
use crate::worker::outbound::{outbound, OutboundConfig};
use crate::{custom_module, ALL_ID, A_ID, CHAOS_ID, ICMP_ID, TCP_ID};

mod inbound;
mod outbound;

/// The worker that is run at the anycast sites and performs measurements as instructed by the orchestrator.
///
/// The worker is responsible for establishing a connection with the orchestrator, receiving tasks, and performing measurements.
///
/// # Fields
///
/// * 'grpc_client' - the worker gRPC connection with the orchestrator
/// * 'hostname' - the hostname of the worker
/// * 'is_active' - boolean value that is set to true when the worker is currently doing a measurement
/// * 'current_m_id' - contains the ID of the current measurement
/// * 'outbound_tx' - contains the sender of a channel to the outbound prober that tasks are send to
/// * 'inbound_f' - an atomic boolean that is used to signal the inbound thread to stop listening for packets
#[derive(Clone)]
pub struct Worker {
    grpc_client: ControllerClient<Channel>,
    hostname: String,
    is_active: Arc<Mutex<bool>>,
    current_m_id: Arc<Mutex<u32>>,
    outbound_tx: Option<tokio::sync::mpsc::Sender<Data>>,
    abort_s: Arc<AtomicBool>,
}

impl Worker {
    /// Create a worker instance, which includes establishing a connection with the orchestrator.
    ///
    /// Extracts the parameters of the command-line arguments.
    ///
    /// # Arguments
    ///
    /// * 'args' - contains the parsed command-line arguments
    pub async fn new(args: &ArgMatches) -> Result<Worker, Box<dyn Error>> {
        // Get hostname from command line arguments or use the system hostname
        let hostname = args
            .get_one::<String>("hostname")
            .map(|h| h.parse::<String>().expect("Unable to parse hostname"))
            .unwrap_or_else(|| gethostname().into_string().expect("Unable to get hostname"));

        let orc_addr = args.get_one::<String>("orchestrator").unwrap();
        let fqdn = args.get_one::<String>("tls");
        let client = Worker::connect(orc_addr.parse().unwrap(), fqdn)
            .await
            .expect("Unable to connect to orchestrator");

        // Initialize a worker instance
        let mut worker = Worker {
            grpc_client: client,
            hostname,
            is_active: Arc::new(Mutex::new(false)),
            current_m_id: Arc::new(Mutex::new(0)),
            outbound_tx: None,
            abort_s: Arc::new(AtomicBool::new(false)),
        };

        worker.connect_to_server().await?;

        Ok(worker)
    }

    /// Connect to the orchestrator.
    ///
    /// # Arguments
    ///
    /// * 'address' - the address of the orchestrator in string format, containing both the IPv4 address and port number
    ///
    /// * 'fqdn' - an optional string that contains the FQDN of the orchestrator certificate (if TLS is enabled)
    ///
    /// # Example
    ///
    /// ```
    /// let client = connect("127.0.0.0:50001", true);
    /// ```
    async fn connect(
        address: String,
        fqdn: Option<&String>,
    ) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        let channel = if let Some(fqdn) = fqdn {
            // Secure connection
            let addr = format!("https://{address}");

            // Load the CA certificate used to authenticate the orchestrator
            let pem = std::fs::read_to_string("tls/orchestrator.crt")
                .expect("Unable to read CA certificate at ./tls/orchestrator.crt");
            let ca = Certificate::from_pem(pem);
            // Create a TLS configuration
            let tls = ClientTlsConfig::new().ca_certificate(ca).domain_name(fqdn);

            let builder = Channel::from_shared(addr.to_owned()).expect("Unable to set address"); // Use the address provided
            builder
                .keep_alive_timeout(Duration::from_secs(30))
                .http2_keep_alive_interval(Duration::from_secs(15))
                .tcp_keepalive(Some(Duration::from_secs(60)))
                .tls_config(tls)
                .expect("Unable to set TLS configuration")
                .connect()
                .await
                .expect("Unable to connect to orchestrator")
        } else {
            // Unsecure connection
            let addr = format!("http://{address}");

            Channel::from_shared(addr.to_owned())
                .expect("Unable to set address")
                .keep_alive_timeout(Duration::from_secs(30))
                .http2_keep_alive_interval(Duration::from_secs(15))
                .tcp_keepalive(Some(Duration::from_secs(60)))
                .connect()
                .await
                .expect("Unable to connect to orchestrator")
        };
        // Create worker with secret token that is used to authenticate worker commands.
        let client = ControllerClient::new(channel);

        Ok(client)
    }

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
    /// * 'abort_s' - an optional Arc<AtomicBool> that is used to signal the outbound thread to stop sending probes
    fn init(&mut self, task: Task, worker_id: u16, abort_s: Option<Arc<AtomicBool>>) {
        let start_measurement = if let Data::Start(start) = task.data.unwrap() {
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

            println!("[Worker] Using local unicast IP address: {unicast_ip}");
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
            println!(
                "[Worker] Found interface: {}, for address {}",
                interface.name, addr
            );
            interface.clone() // Return the found interface
        } else {
            // Use the default interface (first non-loopback interface)
            let interface = interfaces
                .into_iter()
                .find(|iface| !iface.is_loopback())
                .expect("Failed to find default interface");
            println!(
                "[Worker] No interface found for address: {}, using default interface {}",
                addr, interface.name
            );
            interface
        };

        // Create a socket to send out probes and receive replies with
        // TODO can use config to increase buffer sizes
        let (socket_tx, socket_rx) = match datalink::channel(&interface, Default::default()) {
            Ok(SocketChannel::Ethernet(socket_tx, socket_rx)) => (socket_tx, socket_rx),
            Ok(_) => panic!("Unsupported channel type"),
            Err(e) => panic!("Failed to create datalink channel: {e}"),
        };

        // Start listening thread (except if it is a unicast measurement and we are not probing)
        if !is_unicast || is_probing {
            let config = InboundConfig {
                m_id,
                worker_id,
                is_ipv6,
                m_type: start_measurement.m_type as u8,
                origin_map: rx_origins,
                abort_s: self.abort_s.clone(),
            };

            inbound(config, tx, socket_rx);
        }

        if is_probing {
            match start_measurement.m_type as u8 {
                ICMP_ID => {
                    // Print all probe origin addresses
                    for origin in tx_origins.iter() {
                        println!(
                            "[Worker] Sending on address: {} using ICMP identifier {}",
                            origin.src.unwrap(),
                            origin.dport
                        );
                    }
                }
                A_ID | TCP_ID | CHAOS_ID | ALL_ID => {
                    // Print all probe origin addresses
                    for origin in tx_origins.iter() {
                        println!(
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
                is_ipv6,
                is_symmetric: is_latency || is_unicast,
                m_id,
                m_type: start_measurement.m_type as u8,
                qname,
                info_url,
                if_name: interface.name,
                probing_rate,
            };

            // Start sending thread
            outbound(config, outbound_rx.unwrap(), socket_tx);
        } else {
            println!("[Worker] Not sending probes");
        }

        let mut self_clone = self.clone();
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

    /// Establish a formal connection with the orchestrator.
    ///
    /// Obtains a unique worker ID from the orchestrator, establishes a stream for receiving tasks, and handles tasks as they come in.
    async fn connect_to_server(&mut self) -> Result<(), Box<dyn Error>> {
        println!("[Worker] Connecting to orchestrator");
        let mut abort_s: Option<Arc<AtomicBool>> = None;

        // Get the local unicast addresses
        let unicast_v6 = local_ipv6().ok().map(Address::from);
        let unicast_v4 = local_ip().ok().map(Address::from);

        let worker = custom_module::manycastr::Worker {
            hostname: self.hostname.clone(),
            worker_id: 0, // This will be set after the connection
            status: "".to_string(),
            unicast_v6,
            unicast_v4,
        };

        // Connect to the orchestrator
        let response = self
            .grpc_client
            .worker_connect(Request::new(worker))
            .await
            .expect("Unable to connect to orchestrator");

        let mut stream = response.into_inner();
        // Read the assigned unique worker ID
        let id_message = stream
            .message()
            .await
            .expect("Unable to await stream")
            .expect("Unable to receive worker ID");
        let worker_id = id_message.worker_id.expect("No initial worker ID set") as u16;
        println!(
            "[Worker] Successfully connected with the orchestrator with worker_id: {worker_id}"
        );

        // Await tasks
        while let Some(task) = stream.message().await.expect("Unable to receive task") {
            println!("[] Received task: {:?}", task);
            // If we already have an active measurement
            if *self.is_active.lock().unwrap() {
                // If the CLI disconnected we will receive this message
                match task.data {
                    None => {
                        println!("[Worker] Received empty task, skipping");
                        continue;
                    }
                    Some(Data::Start(_)) => {
                        println!("[Worker] Received new measurement during an active measurement, skipping");
                        continue;
                    }
                    Some(Data::End(data)) => {
                        // Received finish signal
                        if data.code == 0 {
                            println!(
                                "[Worker] Received measurement finished signal from orchestrator"
                            );
                            // Close inbound threads
                            self.abort_s.store(true, Ordering::SeqCst);
                            // Close outbound threads gracefully
                            if let Some(tx) = self.outbound_tx.take() {
                                tx.send(Data::End(End { code: 0 })).await.expect(
                                    "Unable to send measurement_finished to outbound thread",
                                );
                            }
                        } else if data.code == 1 {
                            println!("[Worker] CLI disconnected, aborting measurement");

                            // Close the inbound threads
                            self.abort_s.store(true, Ordering::SeqCst);
                            // finish will be None if this worker is not probing
                            if let Some(abort_s) = &abort_s {
                                // Close outbound threads
                                abort_s.store(true, Ordering::SeqCst);
                            }
                        } else {
                            println!("[Worker] Received invalid code from orchestrator");
                            continue;
                        }
                    }
                    Some(task) => {
                        // outbound_tx will be None if this worker is not probing
                        if let Some(outbound_tx) = &self.outbound_tx {
                            // Send the task to the prober
                            outbound_tx
                                .send(task)
                                .await
                                .expect("Unable to send task to outbound thread");
                        }
                    }
                };

                // If we don't have an active measurement
            } else {
                let (is_unicast, is_probing, m_id) =
                    match task.clone().data.expect("None start measurement task") {
                        Data::Start(start) => {
                            (start.is_unicast, !start.tx_origins.is_empty(), start.m_id)
                        }
                        _ => {
                            // First task is not a start measurement task
                            continue;
                        }
                    };

                // If we are not probing for a unicast measurement, we do nothing
                if is_unicast && !is_probing {
                    println!("[Worker] Not probing for unicast measurement, skipping");
                    continue;
                }

                println!("[Worker] Starting new measurement");

                *self.is_active.lock().unwrap() = true;
                *self.current_m_id.lock().unwrap() = m_id;
                self.abort_s.store(false, Ordering::SeqCst);

                if is_probing {
                    // This worker is probing
                    // Initialize signal finish atomic boolean
                    abort_s = Some(Arc::new(AtomicBool::new(false)));

                    self.init(task, worker_id, abort_s.clone());
                } else {
                    // This worker is not probing
                    abort_s = None;
                    self.outbound_tx = None;
                    self.init(task, worker_id, None);
                }
            }
        }
        println!("[Worker] Stopped awaiting tasks");

        Ok(())
    }

    /// Send a TaskResult to the orchestrator
    async fn send_result_to_server(
        &mut self,
        task_result: TaskResult,
    ) -> Result<(), Box<dyn Error>> {
        self.grpc_client
            .send_result(Request::new(task_result))
            .await?;

        Ok(())
    }

    /// Let the orchestrator know the current measurement is finished.
    ///
    /// When a measurement is finished the orchestrator knows not to expect any more results from this worker.
    ///
    /// # Arguments
    ///
    /// * 'finished' - the 'Finished' message to send to the orchestrator
    async fn measurement_finish_to_server(
        &mut self,
        finished: Finished,
    ) -> Result<(), Box<dyn Error>> {
        println!(
            "[Worker] Letting the orchestrator know that this worker finished the measurement"
        );
        *self.is_active.lock().unwrap() = false;
        self.grpc_client
            .measurement_finished(Request::new(finished))
            .await?;

        Ok(())
    }
}
