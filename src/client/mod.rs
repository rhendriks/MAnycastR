use crate::custom_module;
use custom_module::IP;
use custom_module::verfploeter::{
    Finished, Task, Metadata, TaskResult, task::Data, ClientId, controller_client::ControllerClient, Address, Origin, End
};
use tonic::{Request};
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::thread;
use clap::ArgMatches;
use futures::sync::oneshot;
use crate::client::inbound::listen;
use gethostname::gethostname;
use crate::client::outbound::outbound;
use local_ip_address::{local_ip, local_ipv6};

mod inbound;
mod outbound;

/// The client that is ran at the anycast sites and performs tasks as instructed by the server to which it is connected to
///
/// # Fields
///
/// * 'grpc_client' - the client connection with the server
/// * 'metadata' - used to store this client's hostname and unique client ID
/// * 'source_address' - contains the source address this client will use for outgoing probes (optional value that can be defined when creating this client)
/// * 'source_port' - contains the source port this client will use for outgoing probes (optional value that can be defined when creating this client)
/// * 'dest_port' - contains the destination port (OR ICMP identifier value) this client will use for outgoing probes (optional value that can be defined when creating this client)
/// * 'active' - boolean value that is set to true when the client is currently doing a measurement
/// * 'current_task' - contains the task ID of the current measurement
/// * 'outbound_tx' - contains the sender of a channel to the outbound prober that tasks are send to
/// * 'inbound_tx_f' - contains the sender of a channel to the inbound listener that is used to signal the end of a measurement
/// * 'multi_probing' - boolean value that is set to true when the client is configured to send probes from all configured origins (i.e., address/port combinations)
#[derive(Clone)]
pub struct Client {
    grpc_client: ControllerClient<Channel>,
    metadata: Metadata,
    // source_address: IP,
    // source_port: u16,
    // dest_port: u16,
    active: Arc<Mutex<bool>>,
    current_task: Arc<Mutex<u32>>,
    outbound_tx: Option<tokio::sync::mpsc::Sender<Data>>,
    inbound_tx_f: Option<Vec<tokio::sync::mpsc::Sender<()>>>,
}

impl Client {
    /// Create a client instance, which includes establishing a connection with the server.
    ///
    /// Extracts the parameters of the command-line arguments.
    ///
    /// # Arguments
    ///
    /// * 'args' - contains the parsed command-line arguments
    pub async fn new(args: &ArgMatches<'_>) -> Result<Client, Box<dyn Error>> {
        // Get values from args
        let hostname = if args.is_present("hostname") {
            args.value_of("hostname").unwrap().parse().unwrap()
        } else {
            gethostname().into_string().unwrap()
        }.to_string();

        let server_addr = args.value_of("server").unwrap();

        // // Get the custom source address for this client (optional)
        // let source_address = if args.is_present("source") {
        //     let source = args.value_of("source").unwrap();
        //     println!("[Client] Using custom source address: {}", source);
        //
        //     if source.contains(':') {
        //         IP::V6(Ipv6Addr::from_str(source).expect("Invalid IPv6 address"))
        //     } else {
        //         IP::V4(Ipv4Addr::from_str(source).expect("Invalid IPv4 address"))
        //     }
        // } else {
        //     println!("[Client] Using source address from task");
        //     IP::None
        // };

        // // Get the custom source port for this client (optional)
        // let s_port = if args.is_present("source_port") {
        //     let s_port = args.value_of("source_port").unwrap()
        //         .parse::<u16>().expect("Invalid source port value");
        //     println!("[Client] Using custom source port: {}", s_port);
        //
        //     s_port
        // } else {
        //     println!("[Client] Using source port from task");
        //     0
        // };
        //
        //
        // // Get the optional destination port for this client (optional)
        // let d_port = if args.is_present("dest_port") {
        //     let d_port = args.value_of("dest_port").unwrap()
        //         .parse::<u16>().expect("Invalid destination port");
        //     println!("[Client] Using custom destination port: {}", d_port);
        //
        //     d_port
        // } else {
        //     println!("[Client] Using destination port from task");
        //     0
        // };

        // Get the optional multi-probing flag -> if set, this client will send probes from all configured 'Origins'
        // let multi_probing = args.is_present("multi-probing");
        // if multi_probing {
        //     println!("[Client] Using multi-probing (this client will send probes using all configured Origins)");
        // }

        // This client's metadata (shared with the Server)
        let metadata = Metadata {
            hostname: hostname.parse().unwrap(),
            // origin: Some(Origin {  // TODO remove this, the CLI must define origins used
            //     source_address: Some(Address::from(source_address.clone())),
            //     source_port: s_port.into(),
            //     destination_port: d_port.into(),
            //     })
        };

        let is_tls = args.is_present("tls");
        let client = Client::connect(server_addr.parse().unwrap(), is_tls).await?;

        // Initialize a client instance
        let mut client_class = Client {
            grpc_client: client,
            metadata,
            // source_address,
            // source_port: s_port,
            // dest_port: d_port,
            active: Arc::new(Mutex::new(false)),
            current_task: Arc::new(Mutex::new(0)),
            outbound_tx: None,
            inbound_tx_f: None,
        };

        client_class.connect_to_server().await?;

        Ok(client_class)
    }

    /// Connect to the server.
    ///
    /// # Arguments
    ///
    /// * 'address' - the address of the server in string format, containing both the IPv4 address and port number
    ///
    /// * 'tls' - a boolean that indicates whether the connection should be secured with TLS
    ///
    /// # Example
    ///
    /// ```
    /// let grpc_client = connect("127.0.0.0:50001", true);
    /// ```
    async fn connect(address: String, tls: bool) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        let channel = if tls {
            // Secure connection
            let addr = format!("https://{}", address);

            // Load the CA certificate used to authenticate the server
            let pem = std::fs::read_to_string("tls/server.crt").expect("Unable to read CA certificate at ./tls/server.crt");
            let ca = Certificate::from_pem(pem);

            let tls = ClientTlsConfig::new()
                .ca_certificate(ca)
                .domain_name("localhost");

            let builder = Channel::from_shared(addr.to_owned())?; // Use the address provided
            builder
                .tls_config(tls).expect("Unable to set TLS configuration")
                .connect().await.expect("Unable to connect to server")
        } else {
            // Unsecure connection
            let addr = format!("http://{}", address);

            Channel::from_shared(addr.to_owned()).expect("Unable to set address")
                .connect().await.expect("Unable to connect to server")
        };
        // Create client with secret token that is used to authenticate client commands.
        let client = ControllerClient::new(channel);

        Ok(client)
    }


    /// Initialize a new measurement by creating outbound and inbound threads, and ensures tasks are sent back to the server.
    ///
    /// Extracts the protocol type from the task, and determines which source address to use.
    /// Creates a socket to send out probes and receive replies with, calls the appropriate inbound & outbound functions.
    /// Creates an additional thread that forwards task results to the server.
    ///
    /// # Arguments
    ///
    /// * 'task' - the first 'Task' message sent by the server for the new measurement
    ///
    /// * 'client_id' - the unique ID of this client
    ///
    /// * 'outbound_f' - a channel used to send the finish signal to the outbound prober
    ///
    /// * 'probing' - a boolean that indicates whether this client has to send out probes
    ///
    /// * 'igreedy' - a boolean that indicates whether this client has to use the local unicast address to perform latency measurements
    fn init(
        &mut self,
        task: Task,
        client_id: u8,
        outbound_f: Option<oneshot::Receiver<()>>,
        probing: bool,
        igreedy: bool,
    ) {
        // If the task is empty, we don't do a measurement
        if let Data::Empty(_) = task.data.clone().unwrap() {
            println!("[Client] Received an empty task, skipping measurement");
            return
        }

        // Channel for forwarding tasks to outbound
        let outbound_rx = if probing {
            let (tx, rx) = tokio::sync::mpsc::channel(1000);
            self.outbound_tx = Some(tx);
            Some(rx)
        } else {
            None
        };

        let start = if let Data::Start(start) = task.data.unwrap() { start } else { panic!("Received non-start packet for init") };
        // TODO start contains the rate, but the rate is enforced by the Server and the Client does not need to know about it
        let task_id = start.task_id;
        let is_ipv6 = start.ipv6;
        let mut rx_origins: Vec<Origin> = start.rx_origins;
        let traceroute = start.traceroute;

        // If this client has a specified source address use it, otherwise use the one from the task
        let tx_origins: Vec<Origin> = if igreedy {  // Use the local unicast address and CLI defined ports
            let sport = start.tx_origins[0].sport;
            let dport = start.tx_origins[0].dport;

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

            // We only listen to our own unicast address (each client has its own unicast address)
            rx_origins = vec![unicast_origin.clone()];

            println!("[Client] Using local unicast IP address: {:?}", unicast_ip);
            // Use the local unicast address
            vec![unicast_origin]
        } else {
            // Use the sender origins set by the server
            start.tx_origins
        };

        // Channel for sending from inbound to the server forwarder thread
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Channel for signalling when inbound is finished
        let (inbound_tx_f, inbound_rx_f): (tokio::sync::mpsc::Sender<()>, tokio::sync::mpsc::Receiver<()>) = tokio::sync::mpsc::channel(1000);
        self.inbound_tx_f = Some(vec![inbound_tx_f]);

        let mut filter = String::new();

        if is_ipv6 {
            println!("[Client] Using IPv6");
            filter.push_str("ip6");
        } else {
            println!("[Client] Using IPv4");
            filter.push_str("ip");
        };

        // With these traceroute probes we need to encode the TTL used in the probe in the payload
        // TODO this listener needs to capture ICMP TTL expired for all protocols
        match start.task_type {
            1 => {
                if is_ipv6 {
                    filter.push_str(" and icmp6");
                } else {
                    filter.push_str(" and icmp");
                }
            },
            2 | 4 =>  { // DNS A record, DNS CHAOS TXT
                // if ipv6 {
                //     filter.push_str(" and (icmp6 or ip6[6] == 17)");
                // } else {
                //     filter.push_str(" and (udp or icmp)");
                // }
            },
            3 => {
                if is_ipv6 {
                    filter.push_str(" and ip6[6] == 6");
                } else {
                    filter.push_str(" and tcp");
                }
            },
            _ => panic!("Invalid task type"),
        };

        if probing {
            match start.task_type {
                1 => {
                    // Print all probe origin addresses
                    for origin in tx_origins.iter() {
                        println!("[Client] Sending on address: {}", IP::from(origin.clone().src.unwrap()).to_string());
                        // TODO print ICMP identifier (destination port)
                    }
                },
                2 | 3 | 4 => {
                    // Print all probe origin addresses
                    for origin in tx_origins.iter() {
                        println!("[Client] Sending on address: {}, from src port {}, to dst port {}", IP::from(origin.clone().src.unwrap()).to_string(), origin.sport, origin.dport);
                    }
                },
                _ => { () }
            }
        } else {
            println!("[Client] Not sending probes");
        }

        // Add filter for each address/port combination
        filter.push_str(" and");
        let filter_parts: Vec<String> = match start.task_type {
            1 => { // ICMP has no port numbers
                rx_origins.iter()
                    .map(|origin| format!(" dst host {}", IP::from(origin.clone().src.unwrap()).to_string()))
                    .collect()
            },
            2 | 4 => { // DNS A record, DNS CHAOS TXT
                if is_ipv6 {
                    rx_origins.iter()
                        .map(|origin| format!(" (ip6[6] == 17 and dst host {} and src port 53) or (icmp6 and dst host {})", IP::from(origin.clone().src.unwrap()).to_string(), IP::from(origin.clone().src.unwrap()).to_string()))
                        .collect()
                } else {
                    rx_origins.iter()
                        .map(|origin| format!(" (udp and dst host {} and src port 53) or (icmp and dst host {})", IP::from(origin.clone().src.unwrap()).to_string(), IP::from(origin.clone().src.unwrap()).to_string()))
                        .collect()
                }
            },
            _ => { // TCP
                rx_origins.iter()
                    .map(|origin| format!(" (dst host {} and dst port {} and src port {})", IP::from(origin.clone().src.unwrap()).to_string(), origin.sport, origin.dport))
                    .collect()
            }
        };

        filter.push_str(&*filter_parts.join(" or"));

        // Start listening thread
        // TODO listening threads are not needed for non-probing clients when using the local unicast address
        match start.task_type {
            1 => { // ICMP
                listen(tx.clone(), inbound_rx_f, task_id, client_id, is_ipv6, filter, traceroute, start.task_type);
            }
            2 | 4 => { // DNS A record, DNS CHAOS TXT
                listen(tx.clone(), inbound_rx_f, task_id, client_id, is_ipv6, filter, traceroute, start.task_type);
            }
            3 => { // TCP
                // When tracerouting we need to listen to ICMP for TTL expired messages
                if traceroute {
                    if is_ipv6 {
                        filter.push_str(" or icmp6");
                    } else {
                        filter.push_str(" or icmp");
                    }
                }
                listen(tx.clone(), inbound_rx_f, task_id, client_id, is_ipv6, filter, traceroute, start.task_type);
            }
            _ => { () }
        };

        // Start sending thread, if this client is probing
        if probing {
            outbound(client_id, tx_origins, outbound_rx.unwrap(), outbound_f.unwrap(), is_ipv6, igreedy, task_id, start.task_type as u8)
        }

        let mut self_clone = self.clone();  // TODO remove clone
        // Thread that listens for task results from inbound and forwards them to the server
        thread::Builder::new()
            .name("forwarder_thread".to_string())
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let _enter = rt.enter();

                rt.block_on(async {
                    // Obtain TaskResults from the unbounded channel and send them to the server
                    while let Some(packet) = rx.recv().await {
                        // A default TaskResult notifies this sender that there will be no more results
                        if packet == TaskResult::default() {
                            self_clone.task_finished_to_server(Finished {
                                task_id,
                                client_id: client_id.into(),
                            }).await.unwrap();

                            break;
                        }

                        self_clone.send_result_to_server(packet).await.expect("Unable to send task result to server");
                    };
                    rx.close();
                });
            }).expect("Unable to start forwarder thread");
    }

    /// Establish a formal connection with the server.
    ///
    /// Obtains a unique client ID from the server, establishes a stream for receiving tasks, and handles tasks as they come in.
    async fn connect_to_server(&mut self) -> Result<(), Box<dyn Error>> {
        // Get the client_id from the server
        let client_id: u8 = self.get_client_id_to_server().await.expect("Unable to get a client ID from the server").client_id as u8;
        let mut f_tx: Option<oneshot::Sender<()>> = None;

        // Connect to the server
        println!("[Client] Sending client connect");
        let response = self.grpc_client.client_connect(Request::new(self.metadata.clone())).await?;
        println!("[Client] Registered at the server");
        let mut stream = response.into_inner();

        // Await tasks
        while let Some(task) = stream.message().await? {
            // If we already have an active task
            if *self.active.lock().unwrap() == true {
                // If the CLI disconnected we will receive this message
                match task.clone().data {
                    None => {
                        // A task with data None identifies the end of a measurement
                        if task.data == None { // TODO use the end message with an abort/finished flag
                            println!("[Client] Received measurement finished from Server");
                            // Close the inbound threads
                            for inbound_tx_f in self.inbound_tx_f.as_mut().unwrap() {
                                inbound_tx_f.send(()).await.expect("Unable to send finish signal to inbound thread");
                            }
                            // Outbound threads gets exited by sending this None task to outbound
                            // outbound_tx will be None if this client is not probing
                            if self.outbound_tx.is_some() {
                                // Send the task to the prober
                                self.outbound_tx.clone().unwrap().send(Data::End(End {
                                })).await.expect("Unable to send task_finished to outbound thread");
                            }
                        }
                    }
                    Some(Data::Start(_)) => {
                        println!("[Client] Received new measurement during an active measurement, skipping");
                        continue
                    },
                    Some(Data::End(_)) => {
                        // Send finish signal
                        println!("[Client] CLI disconnected, aborting measurement");
                        // Close the inbound threads
                        for inbound_tx_f in self.inbound_tx_f.as_mut().unwrap() {
                            inbound_tx_f.send(()).await.expect("Unable to send finish signal to inbound thread");
                        }
                        // f_tx will be None if this client is not probing
                        if f_tx.is_some() {
                            // Close outbound threads
                            f_tx.take().unwrap().send(()).expect("Unable to send finish signal to outbound thread");
                        }
                    }
                    Some(task) => {
                        // outbound_tx will be None if this client is not probing
                        if self.outbound_tx.is_some() {
                            // Send the task to the prober
                            self.outbound_tx.clone().unwrap().send(task).await.expect("Unable to send task to outbound thread");
                        }
                    },
                };

            // If we don't have an active measurement
            } else {
                println!("[Client] Starting new measurement");

                let (is_probing, task_id, unicast) = match task.clone().data.expect("None start task") {
                    Data::Start(start) => (start.active, start.task_id, start.unicast),
                    _ => { // First task is not a start task
                        println!("[Client] Received non-start packet for init");
                        continue
                    },
                };

                *self.active.lock().unwrap() = true;
                *self.current_task.lock().unwrap() = task_id;

                if is_probing { // This client is probing
                    // Initialize signal finish channel
                    let (outbound_tx_f, outbound_rx_f) = oneshot::channel();
                    f_tx = Some(outbound_tx_f);

                    self.init(task, client_id, Some(outbound_rx_f), true, unicast);
                } else { // This client is not probing
                    f_tx = None;
                    self.outbound_tx = None;
                    self.init(task, client_id, None, false, unicast);
                }
            }
        }
        println!("[Client] Stopped awaiting tasks");

        Ok(())
    }

    /// Send the get_client_id command to the server to obtain a unique client ID
    async fn get_client_id_to_server(&mut self) -> Result<ClientId, Box<dyn Error>> {
        println!("[Client] Requesting client_id");
        let client_id = self.grpc_client.get_client_id(Request::new(self.metadata.clone())).await?.into_inner();

        Ok(client_id)
    }

    /// Send a TaskResult to the server
    async fn send_result_to_server(&mut self, task_result: TaskResult) -> Result<(), Box<dyn Error>> {
        let request = Request::new(task_result);
        self.grpc_client.send_result(request).await?;

        Ok(())
    }

    /// Let the server know the current measurement is finished.
    ///
    /// When a measurement is finished the server knows not to expect any more results from this client.
    ///
    /// # Arguments
    ///
    /// * 'finished' - the 'Finished' message to send to the server
    async fn task_finished_to_server(&mut self, finished: Finished) -> Result<(), Box<dyn Error>> {
        println!("[Client] Sending task finished to server");
        *self.active.lock().unwrap() = false;
        let request = Request::new(finished);
        self.grpc_client.task_finished(request).await?;

        Ok(())
    }
}
