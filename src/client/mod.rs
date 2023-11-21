use crate::custom_module;
use custom_module::IP;
use custom_module::verfploeter::{
    TaskId, Task, Metadata, TaskResult, task::Data, ClientId, controller_client::ControllerClient, Address
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use socket2::{Domain, Protocol, Socket, Type};
use tonic::Request;
use tonic::transport::Channel;
use std::error::Error;
use std::ops::Add;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use clap::ArgMatches;
use futures::sync::oneshot;
use crate::client::inbound::{listen_ping, listen_tcp, listen_udp};
use crate::client::outbound::{perform_ping, perform_tcp, perform_udp};

mod inbound;
mod outbound;

/// The client that is ran at the anycast sites and performs tasks as instructed by the server to which it is connected to
///
/// # Fields
///
/// * 'grpc_client' - the client connection with the server
/// * 'metadata' - used to store this client's hostname and unique client ID
/// * 'source_address' - contains the source address this client will use for outgoing probes (optional value that can be defined when creating this client)
/// * 'active' - boolean value that is set to true when the client is currently doing a measurement
/// * 'current_task' - contains the task ID of the current measurement
/// * 'outbound_tx' - contains the sender of a channel to the outbound prober that tasks are send to
/// * 'inbound_tx_f' - contains the sender of a channel to the inbound listener that is used to signal the end of a measurement
#[derive(Clone)]
pub struct Client {
    grpc_client: ControllerClient<Channel>,
    metadata: Metadata,
    source_address: IP,
    source_port: u16,
    active: Arc<Mutex<bool>>,
    current_task: Arc<Mutex<u32>>,
    outbound_tx: Option<tokio::sync::mpsc::Sender<Task>>,
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
        let hostname = args.value_of("hostname").unwrap();
        let server_addr = args.value_of("server").unwrap();

        // Get the custom source address for this client (optional)
        let source_address = if args.is_present("source") {
            let source = args.value_of("source").unwrap();
            println!("[Client] Using custom source address: {}", source);

            if source.contains(':') {
                IP::V6(Ipv6Addr::from_str(source).expect("Invalid IPv6 address"))
            } else {
                IP::V4(Ipv4Addr::from_str(source).expect("Invalid IPv4 address"))
            }
        } else {
            println!("[Client] Using source address from task");
            IP::None
        };

        // Get the custom source port for this client (optional)
        let source_port = if args.is_present("source_port") {
            let source_port = args.value_of("source_port").unwrap();
            let source_port = source_port.parse::<u16>().expect("Invalid source port");
            if source_port < 61440 { // Minimum value for source port is 61440
                panic!("Source port must be greater than 61440")
            }
            println!("[Client] Using custom source port: {}", source_port);

            source_port
        } else {
            println!("[Client] Using default source port 62321");
            62321
        };

        let metadata = Metadata {
            hostname: hostname.parse().unwrap(),
            source_address: Some(Address::from(source_address.clone())),
            source_port: source_port.into(),
        };

        // Initialize a client instance
        let mut client_class = Client {
            grpc_client: Self::connect(server_addr).await?,
            metadata,
            source_address,
            source_port,
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
    /// # Example
    ///
    /// ```
    /// let grpc_client = connect("127.0.0.0:50001");
    /// ```
    async fn connect(address: &str) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        let addr = "https://".to_string().add(address);
        println!("[Client] Connecting to Controller Server at address: {} ...", addr);
        let client = ControllerClient::connect(addr).await?;
        println!("[Client] Connected to the Controller Server");

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
    /// * 'outbound_rx' - the channel that's passed on to outbound for sending all future tasks of this measurement
    ///
    /// * 'outbound_f' - a channel used to send the finish signal to the outbound prober
    ///
    /// * 'probing' - a boolean that indicates whether this client has to send out probes
    fn init(&mut self, task: Task, client_id: u8, outbound_f: Option<oneshot::Receiver<()>>, probing: bool) {
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
        let rate: u32 = start.rate;
        let task_id = task.task_id;
        let mut client_sources: Vec<Address> =  start.client_sources;

        // If this client has a specified source address use it, otherwise use the one from the task
        let source_addr: IP = if self.source_address == IP::None {
            IP::from(start.source_address.unwrap())
        } else {
            client_sources.append(&mut vec![start.source_address.unwrap()]); // Add default address to client_sources such that this client will listen on the default address as well
            self.source_address.clone()
        };

        // Channel for sending from inbound to the server forwarder thread
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Channel for signalling when inbound is finished
        let (inbound_tx_f, inbound_rx_f): (tokio::sync::mpsc::Sender<()>, tokio::sync::mpsc::Receiver<()>) = tokio::sync::mpsc::channel(1000);
        self.inbound_tx_f = Some(vec![inbound_tx_f]);

        let ipv6;
        let mut bind_address;

        let domain = if source_addr.to_string().contains(':') {
            println!("[Client] Using IPv6");
            ipv6 = true;
            bind_address = format!("[{}]", source_addr.to_string());
            Domain::ipv6()
        } else {
            println!("[Client] Using IPv4");
            bind_address = format!("{}", source_addr.to_string());
            ipv6 = false;
            Domain::ipv4()
        };

        let protocol = match start.task_type {
            1 => {
                bind_address = format!("{}:{}", bind_address, "0");
                if ipv6 {
                    Protocol::icmpv6()
                } else {
                    Protocol::icmpv4()
                }
            },
            2 | 4 =>  { // DNS A record, DNS CHAOS TXT
                bind_address = format!("{}:{}", bind_address, self.source_port);
                Protocol::udp()
            },
            3 => {
                bind_address = format!("{}:{}", bind_address, self.source_port);
                Protocol::tcp()
            },
            _ => panic!("Invalid task type"),
        };

        // TODO current socket does not forward ipv6 header (future: implement pcap for rust sockets https://lib.rs/crates/pcap)
        // Create the socket to send and receive to/from
        let socket = Arc::new(Socket::new(domain, Type::raw(), Some(protocol)).unwrap()); // TODO try Domain::unix()
        socket.bind(&bind_address.parse::<SocketAddr>().unwrap().into()).unwrap();

        println!("[Client] Sending and listening on address: {}", bind_address);

        // Create a socket for each client_address // TODO do we need a socket for each client_address, source_port combination?
        let mut sockets = Vec::new();
        for client_address in client_sources {
            let address = IP::from(client_address).to_string();
            if source_addr.to_string() == address { // Skip our own address (we already have a socket for it)
                continue
            }

            println!("[Client] Listening on custom address: {}", address);
            sockets.append(&mut vec![create_socket(address, ipv6, protocol, self.source_port)]);
        }

        // Start listening thread and sending thread
        match start.task_type {
            1 => {
                listen_ping(self.metadata.clone(), socket.clone(), tx.clone(), inbound_rx_f, task_id, client_id, ipv6);

                // Start listening thread for other source addresses used during this measurement
                for socket in sockets {
                    let (inbound_tx_f, inbound_rx_f): (tokio::sync::mpsc::Sender<()>, tokio::sync::mpsc::Receiver<()>) = tokio::sync::mpsc::channel(1000);
                    self.inbound_tx_f.as_mut().unwrap().push(inbound_tx_f);
                    listen_ping(self.metadata.clone(), socket.clone(), tx.clone(), inbound_rx_f, task_id, client_id, ipv6);
                }

                if probing {
                    perform_ping(socket, client_id, source_addr, outbound_rx.unwrap(), outbound_f.unwrap(), rate, ipv6);
                }
            }
            2 | 4 => {
                // Create ICMP socket
                let socket_icmp = if ipv6 {
                    Arc::new(Socket::new(domain, Type::raw(), Some(Protocol::icmpv6())).unwrap())
                } else {
                    Arc::new(Socket::new(domain, Type::raw(), Some(Protocol::icmpv4())).unwrap())
                };
                socket_icmp.bind(&bind_address.parse::<SocketAddr>().unwrap().into()).unwrap();

                let task_type: u32 = start.task_type;

                // Start listening thread
                listen_udp(self.metadata.clone(), socket.clone(), tx.clone(), inbound_rx_f, task_id, client_id, socket_icmp, ipv6, task_type);

                // // Start listening thread for other source addresses used during this measurement
                for socket in sockets {
                    let (inbound_tx_f, inbound_rx_f): (tokio::sync::mpsc::Sender<()>, tokio::sync::mpsc::Receiver<()>) = tokio::sync::mpsc::channel(1000);
                    self.inbound_tx_f.as_mut().unwrap().push(inbound_tx_f);

                    let socket_icmp = if ipv6 {
                        create_socket(socket.local_addr().expect("Unable get socket address").as_inet6().expect("Unexpected IP type").ip().to_string(), ipv6, Protocol::icmpv6(), 0)
                    } else {
                        create_socket(socket.local_addr().expect("Unable get socket address").as_inet().expect("Unexpected IP type").ip().to_string(), ipv6, Protocol::icmpv4(), 0)
                    };

                    listen_udp(self.metadata.clone(), socket.clone(), tx.clone(), inbound_rx_f, task_id, client_id, socket_icmp, ipv6, task_type);
                }

                // Start sending thread
                if probing {
                    perform_udp(socket, client_id, source_addr, self.source_port, outbound_rx.unwrap(), outbound_f.unwrap(), rate, ipv6, task_type);
                }
            }
            3 => {
                // Destination port is a high number to prevent causing open states on the target
                let dest_port = 63853 + client_id as u16;

                // Start listening thread
                listen_tcp(self.metadata.clone(), socket.clone(), tx.clone(), inbound_rx_f, task_id, client_id, ipv6);

                // Start listening thread for other source addresses used during this measurement
                for socket in sockets {
                    let (inbound_tx_f, inbound_rx_f): (tokio::sync::mpsc::Sender<()>, tokio::sync::mpsc::Receiver<()>) = tokio::sync::mpsc::channel(1000);
                    self.inbound_tx_f.as_mut().unwrap().push(inbound_tx_f);
                    listen_tcp(self.metadata.clone(), socket.clone(), tx.clone(), inbound_rx_f, task_id, client_id, ipv6);
                }

                // Start sending thread
                if probing {
                    perform_tcp(socket, source_addr, dest_port, self.source_port, outbound_rx.unwrap(), outbound_f.unwrap(), rate, ipv6);
                }
            }
            _ => { () }
        };

        // Thread that listens for task results from inbound and forwards them to the server
        thread::spawn({
            let mut self_clone = self.clone();
            move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let _enter = rt.enter();

                rt.block_on(async {
                    // Obtain TaskResults from the unbounded channel and send them to the server
                    while let Some(packet) = rx.recv().await {
                        // A default TaskResult notifies this sender that there will be no more results
                        if packet == TaskResult::default() {
                            self_clone.task_finished_to_server(TaskId {
                                task_id
                            }).await.unwrap();

                            break;
                        }

                        self_clone.send_result_to_server(packet).await.unwrap();
                    };
                    rx.close();
                });
            }
        });
    }

    /// Establish a formal connection with the server.
    ///
    /// Obtains a unique client ID from the server, establishes a stream for receiving tasks, and handles tasks as they come in.
    async fn connect_to_server(&mut self) -> Result<(), Box<dyn Error>> {
        // Get the client_id from the server
        let client_id: u8 = self.get_client_id_to_server().await.unwrap().client_id as u8;
        let mut f_tx: Option<oneshot::Sender<()>> = None;

        // Connect to the server
        println!("[Client] Sending client connect");
        let response = self.grpc_client.client_connect(Request::new(self.metadata.clone())).await?;
        println!("[Client] Registered at the server");
        let mut stream = response.into_inner();

        // Await tasks
        while let Some(task) = stream.message().await? {
            let task_id = task.task_id;
            // If we already have an active task
            if *self.active.lock().unwrap() == true {
                // If the CLI disconnected we will receive this message
                if *self.current_task.lock().unwrap() + 1000 == task_id {
                    // Send finish signal
                    println!("[Client] CLI disconnected, aborting measurement");
                    // Close the inbound threads
                    for inbound_tx_f in self.inbound_tx_f.as_mut().unwrap() {
                        inbound_tx_f.send(()).await.unwrap();
                    }
                    // f_tx will be None if this client is not probing
                    if f_tx.is_some() {
                        // Close outbound threads
                        f_tx.take().unwrap().send(()).unwrap();
                    }
                // If the received task is part of the active task
                } else if *self.current_task.lock().unwrap() == task_id {
                    // A task with data None identifies the end of a measurement
                    if task.data == None {
                        println!("[Client] Received measurement finished from Server");
                        // Close the inbound threads
                        for inbound_tx_f in self.inbound_tx_f.as_mut().unwrap() {
                            inbound_tx_f.send(()).await.unwrap();
                        }
                        // Outbound threads gets exited by sending this None task to outbound
                    }

                    // outbound_tx will be None if this client is not probing
                    if self.outbound_tx.is_some() {
                        // Send the task to the prober
                        match self.outbound_tx.clone().unwrap().send(task).await {
                            Ok(_) => (),
                            Err(_) => (),
                        }
                    }
                } else {
                    // If we received a new task during a measurement
                    println!("[Client] Received new measurement during an active measurement, skipping")
                }
            // If we don't have an active measurement
            } else {
                println!("[Client] Starting new measurement");

                let task_active = match task.clone().data.unwrap() { // TODO encountered None value when exiting CLI during a measurement and starting a new one soon after
                    Data::Start(start) => start.active,
                    _ => continue, // First task must be a Start task
                };

                *self.active.lock().unwrap() = true;
                *self.current_task.lock().unwrap() = task_id;

                if task_active { // This client is probing
                    // Initialize signal finish channel
                    let (outbound_tx_f, outbound_rx_f) = oneshot::channel();
                    f_tx = Some(outbound_tx_f);

                    self.init(task, client_id, Some(outbound_rx_f), true);
                } else { // This client is not probing
                    f_tx = None;
                    self.outbound_tx = None;
                    self.init(task, client_id, None, false);
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
    /// * 'task_id' - the task ID of the current measurement
    async fn task_finished_to_server(&mut self, task_id: TaskId) -> Result<(), Box<dyn Error>> {
        println!("[Client] Sending task finished to server");
        *self.active.lock().unwrap() = false;
        let request = Request::new(task_id);
        self.grpc_client.task_finished(request).await?;

        Ok(())
    }
}

/// Create a socket for a certain address, domain, protocol, and port
fn create_socket(address: String, v6: bool, protocol: Protocol, port: u16) -> Arc<Socket> {
    let (bind_address, domain) = if v6 == true {
        (format!("[{}]:{}", address, port), Domain::ipv6())
    } else {
        (format!("{}:{}", address, port), Domain::ipv4())
    };

    // Create the socket to send and receive to/from
    let socket = Arc::new(Socket::new(domain, Type::raw(), Some(protocol)).unwrap());
    socket.bind(&bind_address.parse::<SocketAddr>().unwrap().into()).unwrap();

    return socket
}
