// Load in the generated code from verfploeter.proto using tonic
pub mod verfploeter {
    tonic::include_proto!("verfploeter");
}

// Load in the ControllerClient
use verfploeter::controller_client::ControllerClient;
// Load in struct definitions for the message types
use verfploeter::{
    Empty, TaskId, Task, Metadata, TaskResult, task::Data, ClientId
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

use crate::client::inbound::{listen_ping, listen_tcp};
use crate::client::outbound::{perform_ping, perform_tcp};
use crate::client::inbound::listen_udp;
use crate::client::outbound::perform_udp;


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
            // version: "1".to_string(),
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
    async fn start_measurement(&mut self, task: Task, client_id: u8) {

        // TODO make sure only one measurement can be active at a time

        let task_id = task.task_id;
        // Find what kind of task was sent by the Controller
        self.init(task, task_id, client_id).await;
    }

    async fn init(&mut self, task: Task, task_id: u32, client_id: u8) {
        // Obtain values from the Ping message

        // If there's a source address specified use it, otherwise use the one in the task.
        let source_addr;
        if self.source_address == 0 {
            // Use the one specified by the CLI in the task

            source_addr = match task.data.clone().unwrap() {
                Data::Ping(ping) => { ping.source_address }
                Data::Udp(udp) => { udp.source_address }
                Data::Tcp(tcp) => { tcp.source_address }
                Data::Empty(_) => { 0} // TODO handle this
            };
        } else {
            // Use this client's address that was specified in the command-line arguments
            source_addr = self.source_address;
        }

        let dest_addresses = match task.data.clone().unwrap() {
            Data::Ping(ping) => { ping.destination_addresses }
            Data::Udp(udp) => { udp.destination_addresses }
            Data::Tcp(tcp) => { tcp.destination_addresses }
            Data::Empty(_) => { vec![] } // TODO
        };

        // Get port to open socket on TODO it should listen on all ports i.e. 0 since we will be sending from different ports on different clients
        // TODO and we want to receive the responses to those clients as well
        // let port = match task.data.clone().unwrap() {
        //     Data::Ping(ping) => { 0 }
        //     Data::Udp(udp) => { udp.destination_addresses }
        //     Data::Tcp(tcp) => { tcp.destination_addresses }
        //     Data::Empty(_) => { 0 }
        // };

        // Create the socket to send the ping messages from
        let bind_address = format!(
            "{}:0", // TODO port of bind address
            Ipv4Addr::from(source_addr).to_string()
        );

        // Get protocol
        let protocol = match task.data.clone().unwrap() {
            Data::Ping(_) => { Protocol::icmpv4() }
            Data::Udp(_) => { Protocol::udp() }
            Data::Tcp(_) => { Protocol::tcp() }
            Data::Empty(_) => { Protocol::icmpv4() } // TODO handle this
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
                perform_ping(dest_addresses, socket, rx_f, task_id, client_id, source_addr);
            }
            Data::Udp(_) => {
                // TODO do ports need to be randomized to prevent firewall issues?
                let src_port: u16 = 62321;

                // Start listening thread
                listen_udp(self.metadata.clone(), socket.clone(), tx, tx_f, task_id, client_id, src_port);

                // Start sending thread
                perform_udp(dest_addresses, socket, rx_f, task_id, client_id, source_addr,src_port);
            }
            Data::Tcp(_) => {
                // Destination port is a high number to prevent causing open states on the target
                // TODO do ports need to be randomized to prevent firewall issues?
                let dest_port= 63853;
                let src_port = 62321 + client_id as u16;

                // Start listening thread
                listen_tcp(self.metadata.clone(), socket.clone(), tx, tx_f, task_id, client_id);

                // Start sending thread
                perform_tcp(dest_addresses, socket, rx_f, task_id, client_id, source_addr, dest_port, src_port);
            }
            Data::Empty(_) => { println!("[Client] Received an empty task")} // TODO handle this
        };

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

        let client_id: u8 = self.get_client_id_to_server().await.unwrap().client_id as u8;

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