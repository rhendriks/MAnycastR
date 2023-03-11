// Load in the generated code from verfploeter.proto using tonic
pub mod verfploeter {
    tonic::include_proto!("verfploeter");
}

// Load in the ControllerClient
use verfploeter::controller_client::ControllerClient;
// Load in struct definitions for the message types
use verfploeter::{
    Empty, TaskId, Task, Metadata, Ping, TaskResult, task::Data
};

// Ping dependencies
use std::net::{Ipv4Addr, SocketAddr};
use socket2::{Domain, Protocol, Socket, Type};

use tonic::Request;
use tonic::transport::Channel;
use std::error::Error;
use std::ops::Add;
use std::str::FromStr;
use std::sync::Arc;

use clap::ArgMatches;

use crate::client::inbound::listen_ping;
use crate::client::outbound::perform_ping;
use crate::client::udp_inbound::listen_udp;
use crate::client::udp_outbound::perform_udp;
use crate::client::verfploeter::{ClientId, Udp};


mod udp_inbound;
mod udp_outbound;
mod inbound;
mod outbound;

pub struct ClientClass {
    grpc_client: ControllerClient<Channel>,
    metadata: Metadata,
    source_address: u32,
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
            version: "1".to_string(),
        };

        // Initialize a client class
        let mut client_class = ClientClass {
            grpc_client: Self::connect(server_addr.clone()).await?,
            metadata,
            source_address: source,
        };

        client_class.connect_to_server().await?;

        Ok(client_class)
    }

    // Create a connection to the gRPC Controller server
    async fn connect(address: &str) -> Result<ControllerClient<Channel>, Box<dyn Error>> {
        // Create client connection with the Controller Server
        // let client = ControllerClient::connect("http://[::1]:10001").await?;

        let addr = "https://".to_string().add(address);
        println!("[Client] Connecting to Controller Server at address: {}", addr);
        let client = ControllerClient::connect(addr).await?;
        println!("[Client] Connected to the Controller Server");

        Ok(client)
    }

    // Start the appropriate measurement based on the received task
    async fn start_measurement(&mut self, task: Task, client_id: u32) {
        let task_id = task.task_id;
        // Find what kind of task was sent by the Controller
        match task.data.unwrap() {
            Data::Ping(ping) => { self.init_ping(ping, task_id, client_id).await }
            Data::Udp(udp) => { self.init_udp(udp, task_id, client_id).await }
            Data::Tcp(tcp) => { todo!() } // TODO
            Data::Empty(_) => { println!("[Client] Received an empty task")}
        }
    }

    // Prepare for performing a ping task
    async fn init_ping(&mut self, ping: Ping, task_id: u32, client_id: u32) {
        // Obtain values from the Ping message

        // If there's a source address specified use it, otherwise use the one in the task.
        let source_addr;
        if self.source_address == 0 {
            // Use the one specified by the CLI in the task
            source_addr = ping.source_address;
        } else {
            // Use this client's address that was specified in the command-line arguments
            source_addr = self.source_address;
        }
        let dest_addresses = ping.destination_addresses;

        // Create the socket to send the ping messages from
        let bind_address = format!(
            "{}:0",
            Ipv4Addr::from(source_addr).to_string()
        );
        let socket = Arc::new(Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::icmpv4())).unwrap());
        socket.bind(&bind_address.parse::<SocketAddr>().unwrap().into()).unwrap();

        let socket2 = socket.clone();

        // TODO unbounded_channel can cause the process to run out of memory, if the receiver does not keep up with the sender
        // Channel for receiving and sending to the ping inbound listening thread
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Channel for signalling when the outbound pinger is finished
        let (tx_f, rx_f): (tokio::sync::oneshot::Sender<()>, tokio::sync::oneshot::Receiver<()>) = tokio::sync::oneshot::channel();

        // Start listening thread
        listen_ping(self.metadata.clone(), socket, tx, tx_f, task_id, client_id);

        // Start sending thread
        perform_ping(dest_addresses, socket2, rx_f, task_id, client_id, source_addr);

        // Obtain TaskResults from the unbounded channel and send them to the server
        while let Some(packet) = rx.recv().await {
            // A default TaskResult notifies this sender that there will be no more results
            if packet == TaskResult::default() {
                self.task_finished_to_server(TaskId {
                    task_id
                }).await.unwrap();
                break;
            }
            self.send_result_to_server(packet).await.unwrap();
        }
        rx.close();
    }

    // Prepare for performing a ping task
    async fn init_udp(&mut self, udp: Udp, task_id: u32, client_id: u32) {
        // Obtain values from the Ping message

        // If there's a source address specified use it, otherwise use the one in the task.
        let source_addr;
        if self.source_address == 0 {
            // Use the one specified by the CLI in the task
            source_addr = udp.source_address;
        } else {
            // Use this client's address that was specified in the command-line arguments
            source_addr = self.source_address;
        }
        let dest_addresses = udp.destination_addresses;

        // Create the socket to send the ping messages from
        let bind_address = format!(
            "{}:0",
            Ipv4Addr::from(source_addr).to_string()
        );
        let socket = Arc::new(Socket::new(Domain::ipv4(), Type::raw(), Some(Protocol::udp())).unwrap());
        socket.bind(&bind_address.parse::<SocketAddr>().unwrap().into()).unwrap();

        let socket2 = socket.clone();

        // TODO unbounded_channel can cause the process to run out of memory, if the receiver does not keep up with the sender
        // Channel for receiving and sending to the ping inbound listening thread
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Channel for signalling when the outbound prober is finished
        let (tx_f, rx_f): (tokio::sync::oneshot::Sender<()>, tokio::sync::oneshot::Receiver<()>) = tokio::sync::oneshot::channel();

        // Start listening thread
        listen_udp(self.metadata.clone(), socket, tx, tx_f, task_id, client_id);

        let dest_port= 53; // TODO what port number to use (ports not used by windows/linux/whatever?)
        let src_port = 4000 + client_id; // TODO what port number to use (ports not used by windows/linux/whatever?)

        // Start sending thread
        perform_udp(dest_addresses, socket2, rx_f, task_id, client_id, source_addr, dest_port, src_port);

        // Obtain TaskResults from the unbounded channel and send them to the server
        while let Some(packet) = rx.recv().await {
            // A default TaskResult notifies this sender that there will be no more results
            if packet == TaskResult::default() {
                self.task_finished_to_server(TaskId {
                    task_id
                }).await.unwrap();
                break;
            }
            self.send_result_to_server(packet).await.unwrap();
        }
        rx.close();
    }

    // rpc client_connect(Metadata) returns (stream Task) {}
    async fn connect_to_server(&mut self) -> Result<(), Box<dyn Error>> {
        let request = Request::new(self.metadata.clone());

        let client_id: u32 = self.get_client_id_to_server().await.unwrap().client_id;

        println!("[Client] Sending client connect");
        let response = self.grpc_client.client_connect(request).await?;

        let mut stream = response.into_inner();

        while let Some(task) = stream.message().await? {
            println!("[Client] Received task");
            // Only one measurement at a time, therefore it is pointless to spawn threads here
            self.start_measurement(task, client_id).await;
        }
        println!("[Client] Stopped awaiting tasks...");

        Ok(())
    }

    // Obtain a unique client_id at the server
    async fn get_client_id_to_server(&mut self) -> Result<ClientId, Box<dyn Error>> {
        println!("[Client] Requesting client_id");
        let client_id = self.grpc_client.get_client_id(Request::new(Empty::default())).await?.into_inner();

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
        let request = Request::new(task_id);
        let _ = self.grpc_client.task_finished(request).await?;

        Ok(())
    }
}