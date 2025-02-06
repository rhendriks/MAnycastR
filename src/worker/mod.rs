use std::error::Error;
use std::sync::{Arc, Mutex};
use std::thread;

use clap::ArgMatches;
use futures::sync::oneshot;
use gethostname::gethostname;
use local_ip_address::{local_ip, local_ipv6};
use tonic::Request;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

use custom_module::IP;
use custom_module::verfploeter::{
    Address, ClientId, controller_client::ControllerClient, End, Finished, Metadata, Origin, Task, task::Data, TaskResult,
};

use crate::worker::inbound::listen;
use crate::worker::outbound::outbound;
use crate::custom_module;

mod inbound;
mod outbound;

/// The worker that is run at the anycast sites and performs measurements as instructed by the orchestrator.
///
/// The worker is responsible for establishing a connection with the orchestrator, receiving tasks, and performing measurements.
///
/// # Fields
///
/// * 'grpc_client' - the worker connection with the orchestrator
/// * 'metadata' - used to store this worker's hostname and unique worker ID
/// * 'active' - boolean value that is set to true when the worker is currently doing a measurement
/// * 'current_measurement' - contains the ID of the current measurement
/// * 'outbound_tx' - contains the sender of a channel to the outbound prober that tasks are send to
/// * 'inbound_tx_f' - contains the sender of a channel to the inbound listener that is used to signal the end of a measurement
/// * 'interface' - interface name to connect to (connect to default if None)
#[derive(Clone)]
pub struct Worker {
    grpc_client: ControllerClient<Channel>,
    metadata: Metadata,
    active: Arc<Mutex<bool>>,
    current_measurement: Arc<Mutex<u32>>,
    outbound_tx: Option<tokio::sync::mpsc::Sender<Data>>,
    inbound_tx_f: Option<Vec<tokio::sync::mpsc::Sender<()>>>,
    interface: Option<String>,
}

impl Worker {
    /// Create a worker instance, which includes establishing a connection with the orchestrator.
    ///
    /// Extracts the parameters of the command-line arguments.
    ///
    /// # Arguments
    ///
    /// * 'args' - contains the parsed command-line arguments
    pub async fn new(
        args: &ArgMatches<'_>
    ) -> Result<Worker, Box<dyn Error>> {
        // Get values from args
        let hostname = if args.is_present("hostname") {
            args.value_of("hostname").unwrap().parse().unwrap()
        } else {
            gethostname().into_string().expect("Unable to get hostname")
        }.to_string();

        let interface = args.value_of("interface").map(|s| s.to_string());
        let server_addr = args.value_of("orchestrator").unwrap();
        // This worker's metadata (shared with the Server)
        let metadata = Metadata {
            hostname: hostname.parse().unwrap(),
        };
        // let is_tls = args.is_present("tls");
        let fqdn = args.value_of("tls");
        let client = Worker::connect(server_addr.parse().unwrap(), fqdn).await?;

        // Initialize a worker instance
        let mut client_class = Worker {
            grpc_client: client,
            metadata,
            active: Arc::new(Mutex::new(false)),
            current_measurement: Arc::new(Mutex::new(0)),
            outbound_tx: None,
            inbound_tx_f: None,
            interface,
        };

        client_class.connect_to_server().await?;

        Ok(client_class)
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
    /// let grpc_client = connect("127.0.0.0:50001", true);
    /// ```
    async fn connect(
        address: String,
        fqdn: Option<&str>,
    ) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        let channel = if fqdn.is_some() {
            // Secure connection
            let addr = format!("https://{}", address);

            // Load the CA certificate used to authenticate the orchestrator
            let pem = std::fs::read_to_string("tls/orchestrator.crt").expect("Unable to read CA certificate at ./tls/orchestrator.crt");
            let ca = Certificate::from_pem(pem);

            let tls = ClientTlsConfig::new()
                .ca_certificate(ca)
                .domain_name(fqdn.unwrap());

            let builder = Channel::from_shared(addr.to_owned())?; // Use the address provided
            builder
                .tls_config(tls).expect("Unable to set TLS configuration")
                .connect().await.expect("Unable to connect to orchestrator")
        } else {
            // Unsecure connection
            let addr = format!("http://{}", address);

            Channel::from_shared(addr.to_owned()).expect("Unable to set address")
                .connect().await.expect("Unable to connect to orchestrator")
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
    /// * 'client_id' - the unique ID of this worker
    ///
    /// * 'outbound_f' - a channel used to send the finish signal to the outbound prober
    fn init(
        &mut self,
        task: Task,
        client_id: u8,
        outbound_f: Option<oneshot::Receiver<()>>,
    ) {
        let start_measurement = if let Data::Start(start) = task.data.unwrap() { start } else { panic!("Received non-start packet for init") };
        let measurement_id = start_measurement.measurement_id;
        let is_ipv6 = start_measurement.ipv6;
        let mut rx_origins: Vec<Origin> = start_measurement.rx_origins;
        let is_traceroute = start_measurement.traceroute;
        let is_gcd = start_measurement.unicast;
        let is_probing = start_measurement.active;
        let dns_record = start_measurement.record;
        let info_url = start_measurement.url;

        // Channel for forwarding tasks to outbound
        let outbound_rx = if is_probing {
            let (tx, rx) = tokio::sync::mpsc::channel(1000);
            self.outbound_tx = Some(tx);
            Some(rx)
        } else {
            None
        };

        let tx_origins: Vec<Origin> = if is_gcd {  // Use the local unicast address and CLI defined ports
            let sport = start_measurement.tx_origins[0].sport;
            let dport = start_measurement.tx_origins[0].dport;

            let unicast_ip = if is_ipv6 {
                IP::from(local_ipv6().expect("Unable to get local unicast IPv6 address").to_string())
            } else {
                IP::from(local_ip().expect("Unable to get local unicast IPv4 address").to_string())
            };

            let unicast_origin = Origin {
                src: Some(Address::from(unicast_ip.clone())), // Unicast IP
                sport: sport.into(), // CLI defined source port
                dport: dport.into(), // CLI defined destination port
            };

            // We only listen to our own unicast address (each worker has its own unicast address)
            rx_origins = vec![unicast_origin.clone()];


            println!("[Client] Using local unicast IP address: {:?}", unicast_ip);
            // Use the local unicast address
            vec![unicast_origin]
        } else {
            // Use the sender origins set by the orchestrator
            start_measurement.tx_origins
        };

        // Channel for sending from inbound to the orchestrator forwarder thread
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Channel for signalling when inbound is finished
        let (inbound_tx_f, inbound_rx_f): (tokio::sync::mpsc::Sender<()>, tokio::sync::mpsc::Receiver<()>) = tokio::sync::mpsc::channel(1000);
        self.inbound_tx_f = Some(vec![inbound_tx_f]);

        // Berkeley Packet Filter (BPF) string
        let mut bpf_filter = if is_ipv6 {
            "ip6 and".to_string()
        } else {
            "ip and".to_string()
        };

        // Add filter for each address/port combination based on the measurement type
        let filter_parts: Vec<String> = match start_measurement.measurement_type {
            1 => { // ICMP has no port numbers
                if is_ipv6 {
                    rx_origins.iter()
                        .map(|origin| format!(" (icmp6 and dst host {})", IP::from(origin.clone().src.unwrap()).to_string()))
                        .collect()
                } else {
                    rx_origins.iter()
                        .map(|origin| format!(" (icmp and dst host {})", IP::from(origin.clone().src.unwrap()).to_string()))
                        .collect()
                }
            }
            2 | 4 => { // DNS A record, DNS CHAOS TXT
                if is_ipv6 {
                    rx_origins.iter()
                        .map(|origin| format!(" (ip6[6] == 17 and dst host {} and src port 53 and dst port {}) or (icmp6 and dst host {})", IP::from(origin.clone().src.unwrap()).to_string(), origin.sport, IP::from(origin.clone().src.unwrap()).to_string()))
                        .collect()
                } else {
                    rx_origins.iter()
                        .map(|origin| format!(" (udp and dst host {} and src port 53 and dst port {}) or (icmp and dst host {})", IP::from(origin.clone().src.unwrap()).to_string(), origin.sport, IP::from(origin.clone().src.unwrap()).to_string()))
                        .collect()
                }
            }
            3 => { // TCP
                let mut tcp_filters: Vec<String> = if is_ipv6 {
                    rx_origins.iter()
                        .map(|origin| format!(" (ip6[6] == 6 and dst host {} and dst port {} and src port {})", IP::from(origin.clone().src.unwrap()).to_string(), origin.sport, origin.dport))
                        .collect()
                } else {
                    rx_origins.iter()
                        .map(|origin| format!(" (tcp and dst host {} and dst port {} and src port {})", IP::from(origin.clone().src.unwrap()).to_string(), origin.sport, origin.dport))
                        .collect()
                };

                // When tracerouting we need to listen to ICMP for TTL expired messages
                if is_traceroute {
                    let icmp_ttl_expired_filter: Vec<String> = rx_origins.iter()
                        .map(|origin| format!(" (icmp and dst host {})", IP::from(origin.clone().src.unwrap()).to_string()))
                        .collect();
                    tcp_filters.extend(icmp_ttl_expired_filter);
                }
                tcp_filters
            }
            _ => panic!("Invalid measurement type"),
        };

        bpf_filter.push_str(&*filter_parts.join(" or"));

        // Start listening thread
        listen(tx.clone(), inbound_rx_f, measurement_id, client_id, is_ipv6, bpf_filter, is_traceroute, start_measurement.measurement_type, self.interface.clone());

        if is_probing {
            match start_measurement.measurement_type {
                1 => {
                    // Print all probe origin addresses
                    for origin in tx_origins.iter() {
                        println!("[Client] Sending on address: {} using identifier {}", IP::from(origin.clone().src.unwrap()).to_string(), origin.dport);
                    }
                }
                2 | 3 | 4 => {
                    // Print all probe origin addresses
                    for origin in tx_origins.iter() {
                        println!("[Client] Sending on address: {}, from src port {}, to dst port {}", IP::from(origin.clone().src.unwrap()).to_string(), origin.sport, origin.dport);
                    }
                }
                _ => { () }
            }
            // Start sending thread
            outbound(client_id, tx_origins, outbound_rx.unwrap(), outbound_f.unwrap(), is_ipv6, is_gcd, measurement_id, start_measurement.measurement_type as u8, dns_record, info_url, self.interface.clone());
        } else {
            println!("[Client] Not sending probes");
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
                            self_clone.measurement_finished_to_server(Finished {
                                measurement_id,
                                client_id: client_id.into(),
                            }).await.unwrap();

                            break;
                        }

                        self_clone.send_result_to_server(packet).await.expect("Unable to send task result to orchestrator");
                    };
                    rx.close();
                });
            }).expect("Unable to start forwarder thread");
    }

    /// Establish a formal connection with the orchestrator.
    ///
    /// Obtains a unique worker ID from the orchestrator, establishes a stream for receiving tasks, and handles tasks as they come in.
    async fn connect_to_server(&mut self) -> Result<(), Box<dyn Error>> {
        println!("Connecting to orchestrator");
        // Get the client_id from the orchestrator
        let client_id: u8 = self.get_client_id_to_server().await.expect("Unable to get a worker ID from the orchestrator").client_id as u8;
        let mut f_tx: Option<oneshot::Sender<()>> = None;

        // Connect to the orchestrator
        let response = self.grpc_client.client_connect(Request::new(self.metadata.clone())).await?;
        println!("[Client] Successfully connected with the orchestrator with client_id: {}", client_id);
        let mut stream = response.into_inner();

        // Await tasks
        while let Some(task) = stream.message().await? {
            if *self.active.lock().unwrap() { // If we already have an active measurement
                // If the CLI disconnected we will receive this message
                match task.clone().data {
                    None => {
                        println!("[Client] Received empty task, skipping");
                        continue;
                    }
                    Some(Data::Start(_)) => {
                        println!("[Client] Received new measurement during an active measurement, skipping");
                        continue;
                    }
                    Some(Data::End(data)) => {
                        // Received finish signal
                        if data.code == 0 {
                            println!("[Client] Received measurement finished signal from Server");
                            // Close inbound threads
                            for inbound_tx_f in self.inbound_tx_f.as_mut().unwrap() {
                                inbound_tx_f.send(()).await.expect("Unable to send finish signal to inbound thread");
                            }
                            // Close outbound threads
                            if self.outbound_tx.is_some() {
                                self.outbound_tx.clone().unwrap().send(Data::End(End {
                                    code: 0,
                                })).await.expect("Unable to send measurement_finished to outbound thread");
                            }
                        } else if data.code == 1 {
                            println!("[Client] CLI disconnected, aborting measurement");

                            // Close the inbound threads
                            for inbound_tx_f in self.inbound_tx_f.as_mut().unwrap() {
                                inbound_tx_f.send(()).await.expect("Unable to send finish signal to inbound thread");
                            }
                            // f_tx will be None if this worker is not probing
                            if f_tx.is_some() {
                                // Close outbound threads
                                f_tx.take().unwrap().send(()).expect("Unable to send finish signal to outbound thread");
                            }
                        } else {
                            println!("[Client] Received invalid code from Server");
                            continue;
                        }
                    }
                    Some(task) => {
                        // outbound_tx will be None if this worker is not probing
                        if let Some(outbound_tx) = &self.outbound_tx {
                            // Send the task to the prober
                            outbound_tx.send(task).await.expect("Unable to send task to outbound thread");
                        }
                    }
                };

                // If we don't have an active measurement
            } else {
                println!("[Client] Starting new measurement");

                let (is_probing, measurement_id) = match task.clone().data.expect("None start measurement task") {
                    Data::Start(start) => (start.active, start.measurement_id),
                    _ => { // First task is not a start measurement task
                        println!("[Client] Received non-start packet for init");
                        continue;
                    }
                };

                *self.active.lock().unwrap() = true;
                *self.current_measurement.lock().unwrap() = measurement_id;

                if is_probing { // This worker is probing
                    // Initialize signal finish channel
                    let (outbound_tx_f, outbound_rx_f) = oneshot::channel();
                    f_tx = Some(outbound_tx_f);

                    self.init(task, client_id, Some(outbound_rx_f));
                } else { // This worker is not probing
                    f_tx = None;
                    self.outbound_tx = None;
                    self.init(task, client_id, None);
                }
            }
        }
        println!("[Client] Stopped awaiting tasks");

        Ok(())
    }

    /// Send the get_client_id command to the orchestrator to obtain a unique worker ID
    async fn get_client_id_to_server(&mut self) -> Result<ClientId, Box<dyn Error>> {
        let client_id = self.grpc_client.get_client_id(Request::new(self.metadata.clone())).await?.into_inner();

        Ok(client_id)
    }

    /// Send a TaskResult to the orchestrator
    async fn send_result_to_server(&mut self, task_result: TaskResult) -> Result<(), Box<dyn Error>> {
        self.grpc_client.send_result(Request::new(task_result)).await?;

        Ok(())
    }

    /// Let the orchestrator know the current measurement is finished.
    ///
    /// When a measurement is finished the orchestrator knows not to expect any more results from this worker.
    ///
    /// # Arguments
    ///
    /// * 'finished' - the 'Finished' message to send to the orchestrator
    async fn measurement_finished_to_server(&mut self, finished: Finished) -> Result<(), Box<dyn Error>> {
        println!("[Client] Letting the orchestrator know that this worker finished the measurement");
        *self.active.lock().unwrap() = false;
        self.grpc_client.measurement_finished(Request::new(finished)).await?;

        Ok(())
    }
}
