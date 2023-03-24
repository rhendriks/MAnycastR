// Load in the generated code from verfploeter.proto using tonic
pub mod verfploeter {
    tonic::include_proto!("verfploeter");
}

// Load in the ControllerClient
use verfploeter::controller_client::ControllerClient;
// Load in struct definitions for the message types
use verfploeter::{
    TaskId, Task, Metadata, TaskResult, task::Data, ClientId
};

// Ping dependencies
use std::net::{Ipv4Addr, SocketAddr};
use socket2::{Domain, Protocol, Socket, Type};

use tonic::Request;
use tonic::transport::Channel;
use std::error::Error;
use std::ops::Add;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Receiver;
use std::thread;

use clap::ArgMatches;

use crate::client::inbound::{listen_ping, listen_tcp, listen_udp};
use crate::client::outbound::{perform_ping, perform_tcp, perform_udp};

mod inbound;
mod outbound;

#[derive(Clone)]
pub struct ClientClass {
    grpc_client: ControllerClient<Channel>,
    metadata: Metadata,
    source_address: u32,
    active: Arc<Mutex<bool>>,
    current_task: Arc<Mutex<u32>>,
    outbound_channel_tx: Option<std::sync::mpsc::Sender<Task>>,
}

impl ClientClass {
    // Create a new client object
    pub async fn new(args: &ArgMatches<'_>) -> Result<ClientClass, Box<dyn Error>> {
        println!("[Client] Creating new client");

        let hostname = args.value_of("hostname").unwrap();

        let server_addr = args.value_of("server").unwrap();

        let mut source = 0;
        // Get the source address if it's present
        if args.is_present("source") {
            source = u32::from(Ipv4Addr::from_str(args.value_of("source").unwrap()).unwrap());
        }

        let metadata = Metadata {
            hostname: hostname.parse().unwrap(),
        };

        // Initialize a client class
        let mut client_class = ClientClass {
            grpc_client: Self::connect(server_addr.clone()).await?,
            metadata,
            source_address: source,
            active: Arc::new(Mutex::new(false)),
            current_task: Arc::new(Mutex::new(0)),
            outbound_channel_tx: None,
        };

        client_class.connect_to_server().await?;

        Ok(client_class)
    }

    // Create a connection to the gRPC Controller server
    async fn connect(address: &str) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        // Create client connection with the Controller Server
        let addr = "https://".to_string().add(address);
        println!("[Client] Connecting to Controller Server at address: {}", addr);
        let client = ControllerClient::connect(addr).await?;
        println!("[Client] Connected to the Controller Server");

        Ok(client)
    }

    // Start the appropriate measurement based on the received task
    fn start_measurement(&mut self, task: Task, client_id: u8, rx: Receiver<Task>) {
        // If the task is empty, we don't do a measurement
        if let Data::Empty(_) = task.data.clone().unwrap() {
            println!("[Client] Received an empty task, skipping measurement");
            return
        }

        let task_id = task.task_id;
        // Find what kind of task was sent by the Controller
        self.init(task, task_id, client_id, rx);
    }

    fn init(&mut self, task: Task, task_id: u32, client_id: u8, outbound_rx: Receiver<Task>) {
        // If there's a source address specified use it, otherwise use the one in the task.
        let source_addr;
        if self.source_address == 0 {
            // Use the one specified by the CLI in the task

            source_addr = match task.data.clone().unwrap() {
                Data::Ping(ping) => { ping.source_address }
                Data::Udp(udp) => { udp.source_address }
                Data::Tcp(tcp) => { tcp.source_address }
                Data::Empty(_) => { 0 }
            };
        } else {
            // Use this client's address that was specified in the command-line arguments
            source_addr = self.source_address;
        }

        // Create the socket to send the ping messages from
        let bind_address = format!(
            "{}:0",
            Ipv4Addr::from(source_addr).to_string()
        );

        // Get protocol
        let protocol = match task.data.clone().unwrap() {
            Data::Ping(_) => { Protocol::icmpv4() }
            Data::Udp(_) => { Protocol::udp() }
            Data::Tcp(_) => { Protocol::tcp() }
            Data::Empty(_) => { Protocol::icmpv4() }
        };

        let socket = Arc::new(Socket::new(Domain::ipv4(), Type::raw(), Some(protocol)).unwrap());
        socket.bind(&bind_address.parse::<SocketAddr>().unwrap().into()).unwrap();

        // TODO unbounded_channel can cause the process to run out of memory, if the receiver does not keep up with the sender
        // Channel for receiving and sending to the inbound listening thread
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Channel for signalling when outbound is finished
        let (tx_f, rx_f): (tokio::sync::oneshot::Sender<()>, tokio::sync::oneshot::Receiver<()>) = tokio::sync::oneshot::channel();

        // Start listening thread and sending thread
        match task.data.clone().unwrap() {
            Data::Ping(_) => {
                listen_ping(self.metadata.clone(), socket.clone(), tx, tx_f, task_id, client_id);
                perform_ping(socket, rx_f, client_id, source_addr, outbound_rx);
            }
            Data::Udp(_) => {
                let src_port: u16 = 62321;

                // Start listening thread
                listen_udp(self.metadata.clone(), socket.clone(), tx, tx_f, task_id, client_id, src_port);

                // Start sending thread
                perform_udp(socket, rx_f, client_id, source_addr,src_port, outbound_rx);
            }
            Data::Tcp(_) => {
                // Destination port is a high number to prevent causing open states on the target
                let dest_port= 63853;
                let src_port = 62321 + client_id as u16;

                // Start listening thread
                listen_tcp(self.metadata.clone(), socket.clone(), tx, tx_f, task_id, client_id);

                // Start sending thread
                perform_tcp(socket, rx_f, source_addr, dest_port, src_port, outbound_rx);
            }
            Data::Empty(_) => { () }
        };

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

    // rpc client_connect(Metadata) returns (stream Task) {}
    async fn connect_to_server(&mut self) -> Result<(), Box<dyn Error>> {
        let request = Request::new(self.metadata.clone());

        let client_id: u8 = self.get_client_id_to_server().await.unwrap().client_id as u8;

        println!("[Client] Sending client connect");
        let response = self.grpc_client.client_connect(request).await?;

        let mut stream = response.into_inner();

        while let Some(task) = stream.message().await? {
            println!("[Client] Received task");
            let task_id = task.task_id;
            // If we already have an active task
            if *self.active.lock().unwrap() == true {
                // If the received task is part of the active task
                if *self.current_task.lock().unwrap() == task_id {
                    // Send the task to the prober
                    self.outbound_channel_tx.clone().unwrap().send(task).unwrap();
                } else {
                    println!("[Client] Received new measurement during an active measurement")
                    // If we received a new task during a measurement
                    // TODO
                }

            // If we don't have an active task
            } else {
                *self.active.lock().unwrap() = true;
                *self.current_task.lock().unwrap() = task_id;

                let (tx, rx) = std::sync::mpsc::channel();
                tx.send(task.clone()).unwrap();
                self.outbound_channel_tx = Some(tx);

                self.start_measurement(task, client_id, rx);
            }
        }
        println!("[Client] Stopped awaiting tasks...");

        Ok(())
    }

    // Obtain a unique client_id at the server
    async fn get_client_id_to_server(&mut self) -> Result<ClientId, Box<dyn Error>> {
        println!("[Client] Requesting client_id");
        let client_id = self.grpc_client.get_client_id(Request::new(self.metadata.clone())).await?.into_inner();

        Ok(client_id)
    }

    // rpc send_result(TaskResult) returns (Ack) {}
    async fn send_result_to_server(&mut self, task_result: TaskResult) -> Result<(), Box<dyn Error>> {
        println!("[Client] Sending TaskResult to server");
        let request = Request::new(task_result);
        let _ = self.grpc_client.send_result(request).await?;

        Ok(())
    }

    // rpc task_finished(TaskId) returns (Ack) {}
    async fn task_finished_to_server(&mut self, task_id: TaskId) -> Result<(), Box<dyn Error>> {
        println!("[Client] Sending task finished to server");
        *self.active.lock().unwrap() = false;
        let request = Request::new(task_id);
        let _ = self.grpc_client.task_finished(request).await?;

        Ok(())
    }
}