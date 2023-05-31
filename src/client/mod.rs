pub mod verfploeter { tonic::include_proto!("verfploeter"); }
use verfploeter::controller_client::ControllerClient;
use verfploeter::{ TaskId, Task, Metadata, TaskResult, task::Data, ClientId };
use std::net::{Ipv4Addr, SocketAddr};
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
/// * 'outbound_channel_tx' - contains the sender of a channel to the outbound prober that tasks are send to (will be None when there is no active measurement)
#[derive(Clone)]
pub struct Client {
    grpc_client: ControllerClient<Channel>,
    metadata: Metadata,
    source_address: u32,
    active: Arc<Mutex<bool>>,
    current_task: Arc<Mutex<u32>>,
    outbound_channel_tx: Option<tokio::sync::mpsc::Sender<Task>>,
    inbound_f: Option<tokio::sync::mpsc::Sender<()>>,
}

impl Client {
    /// Create a client instance, which includes establishing a connection with the server.
    ///
    /// Extracts the source address from the optional argument.
    ///
    /// # Arguments
    ///
    /// * 'args' - contains the parsed CLI arguments
    pub async fn new(args: &ArgMatches<'_>) -> Result<Client, Box<dyn Error>> {
        // Get values from args
        let hostname = args.value_of("hostname").unwrap();
        let server_addr = args.value_of("server").unwrap();
        // Get the source address if it's present (optional argument)
        let source_address = if args.is_present("source") {
            u32::from(Ipv4Addr::from_str(args.value_of("source").unwrap()).unwrap())
        } else { 0 };

        let metadata = Metadata {
            hostname: hostname.parse().unwrap(),
        };

        // Initialize a client instance
        let mut client_class = Client {
            grpc_client: Self::connect(server_addr.clone()).await?,
            metadata,
            source_address,
            active: Arc::new(Mutex::new(false)),
            current_task: Arc::new(Mutex::new(0)),
            outbound_channel_tx: None,
            inbound_f: None,
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
    /// * 'finish_rx' - a channel used to abort the measurement
    fn init(&mut self, task: Task, client_id: u8, outbound_rx: tokio::sync::mpsc::Receiver<Task>, finish_rx: oneshot::Receiver<()>, probing: bool) {
        // If the task is empty, we don't do a measurement
        if let Data::Empty(_) = task.data.clone().unwrap() {
            println!("[Client] Received an empty task, skipping measurement");
            return
        }

        let start = if let Data::Start(start) = task.data.unwrap() { start } else { todo!() };

        let rate: u32 = start.rate;
        let task_id = task.task_id;
        // If this client has a specified source address use it, otherwise use the one from the task
        let source_addr = if self.source_address == 0 {
            start.source_address
            // match task.data.clone().unwrap() {
            //     Data::Ping(ping) => { ping.source_address }
            //     Data::Udp(udp) => { udp.source_address }
            //     Data::Tcp(tcp) => { tcp.source_address }
            //     Data::Empty(_) => { 0 }
            // }
        } else {
            self.source_address
        };

        // Get protocol type
        // let protocol = match task.data.clone().unwrap() {
        //     Data::Ping(_) => { Protocol::icmpv4() }
        //     Data::Udp(_) => { Protocol::udp() }
        //     Data::Tcp(_) => { Protocol::tcp() }
        //     Data::Empty(_) => { Protocol::icmpv4() }
        // };
        let protocol = match start.task_type {
            1 => { Protocol::icmpv4() }
            2 => { Protocol::udp() }
            3 => { Protocol::tcp() }
            _ => { Protocol::icmpv4() }
        };

        let socket = Arc::new(Socket::new(Domain::ipv4(), Type::raw(), Some(protocol)).unwrap());

        // Channel for sending from inbound to the server forwarder thread (at the end of the function)
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Channel for signalling when outbound is finished
        let (tx_f, rx_f): (tokio::sync::mpsc::Sender<()>, tokio::sync::mpsc::Receiver<()>) = tokio::sync::mpsc::channel(1000);

        self.inbound_f = Some(tx_f);

        // Start listening thread and sending thread
        match start.task_type {
            1 => {
                // Create the socket to send and receive to/from
                let bind_address = format!(
                    "{}:0",
                    Ipv4Addr::from(source_addr).to_string()
                );
                socket.bind(&bind_address.parse::<SocketAddr>().unwrap().into()).unwrap();

                listen_ping(self.metadata.clone(), socket.clone(), tx, rx_f, task_id, client_id);
                if probing {
                    perform_ping(socket, client_id, source_addr, outbound_rx, finish_rx, rate);
                }
            }
            2 => {
                let src_port: u16 = 62321;
                // Create the socket to send and receive to/from
                let bind_address = format!(
                    "{}:0",
                    Ipv4Addr::from(source_addr).to_string()
                );
                socket.bind(&bind_address.parse::<SocketAddr>().unwrap().into()).unwrap();

                // Create ICMP socket
                let socket_icmp = Arc::new(Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4())).unwrap());
                let bind_address_icmp = format!(
                    "{}:0",
                    Ipv4Addr::from(source_addr).to_string()
                );
                socket_icmp.bind(&bind_address_icmp.parse::<SocketAddr>().unwrap().into()).unwrap();

                // Start listening thread
                listen_udp(self.metadata.clone(), socket.clone(), tx, rx_f, task_id, client_id, socket_icmp);

                // Start sending thread
                if probing {
                    perform_udp(socket, client_id, source_addr,src_port, outbound_rx, finish_rx, rate);
                }
            }
            3 => {
                // Destination port is a high number to prevent causing open states on the target
                let dest_port = 63853 + client_id as u16;
                let src_port = 62321;
                // Create the socket to send and receive to/from
                let bind_address = format!(
                    "{}:0",
                    Ipv4Addr::from(source_addr).to_string()
                );
                socket.bind(&bind_address.parse::<SocketAddr>().unwrap().into()).unwrap();

                // Start listening thread
                listen_tcp(self.metadata.clone(), socket.clone(), tx, rx_f, task_id, client_id);

                // Start sending thread
                if probing {
                    perform_tcp(socket, source_addr, dest_port, src_port, outbound_rx, finish_rx, rate);
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

                            // finish_rx.close();

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
                // TODO task finished message by server
                // If the CLI disconnected we will receive this message
                if *self.current_task.lock().unwrap() + 1000 == task_id {
                    // Send finish signal
                    println!("[Client] CLI disconnected, exiting task");
                    f_tx.take().unwrap().send(()).unwrap();
                // If the received task is part of the active task
                } else if *self.current_task.lock().unwrap() == task_id {

                    // A task with data None identifies the end of a measurement
                    if task.data == None {
                        println!("[Client] Received measurement finished from Server");
                        // Close the inbound threads
                        self.inbound_f.clone().unwrap().send(()).await.unwrap();
                        // Outbound threads gets exited by sending this None task to outbound
                    }

                    // Send the task to the prober
                    // TODO this is not neccesary if this client is not sending out tasks
                    match self.outbound_channel_tx.clone().unwrap().send(task).await {
                        Ok(_) => (),
                        Err(_) => (),
                    }
                } else {
                    // If we received a new task during a measurement
                    println!("[Client] Received new measurement during an active measurement, skipping")
                }
            // If we don't have an active task
            } else {
                println!("[Client] Starting new measurement");

                let task_active = match task.clone().data.unwrap() {
                    Data::Start(start) => start.active,
                    _ => todo!(), // TODO must be a start task
                };

                *self.active.lock().unwrap() = true;
                *self.current_task.lock().unwrap() = task_id;

                // Initialize signal finish channel
                let (finish_tx, finish_rx) = oneshot::channel();
                f_tx = Some(finish_tx);

                // if task_active { // TODO certain variables not neccessary when task_active == false
                // Channel for forwarding tasks to outbound
                let (tx, rx) = tokio::sync::mpsc::channel(1000);
                tx.send(task.clone()).await.unwrap();
                self.outbound_channel_tx = Some(tx);
                // }

                // TODO make sure task is a Start task
                self.init(task, client_id, rx, finish_rx, task_active);
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