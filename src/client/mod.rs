// Load in the generated code from verfploeter.proto using tonic
pub mod verfploeter {
    tonic::include_proto!("verfploeter"); // Based on the 'verfploeter' package name
}

// Load in the ControllerClient
use verfploeter::controller_client::ControllerClient;
// Load in struct definitions for the message types
use verfploeter::{
    Empty, Ack, TaskId, ScheduleTask, ClientList, Client, Task, Metadata, Ping, TaskResult,
    VerfploeterResult, PingResult, PingPayload
};
use crate::client::verfploeter::task::Data;


// Ping dependencies
use std::net::{Ipv4Addr, SocketAddr};
use socket2::{Domain, Protocol, Socket, Type};

use tonic::Request;
use tonic::transport::Channel;
use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;

use clap::ArgMatches;

use crate::client::inbound::listen_ping;
use crate::client::outbound::perform_ping;
use crate::client::verfploeter::ClientId;


mod inbound;
mod outbound;

pub struct ClientClass {
    grpc_client: ControllerClient<Channel>,
    metadata: verfploeter::Metadata,
    source_address: u32,
}

impl ClientClass {
    // Create a new client object
    pub async fn new(args: &ArgMatches<'_>) -> Result<ClientClass, Box<dyn std::error::Error>> {
        println!("[Client] Creating new client");

        let hostname = args.value_of("hostname").unwrap();

        let mut source = 0;
        // Get the source address if it's present
        if args.is_present("source") {
            source = u32::from(Ipv4Addr::from_str(args.value_of("source").unwrap()).unwrap());
        }

        let metadata = verfploeter::Metadata {
            hostname: hostname.parse().unwrap(),
            version: "1".to_string(),
        };

        // Initialize a client class
        let mut client_class = ClientClass {
            grpc_client: Self::connect().await.unwrap(),
            metadata,
            source_address: source,
        };

        // TODO has to be called here otherwise the message does not reach the server
        // TODO when I need the client connection further it is best to pass it on as argument
        client_class.connect_to_server().await?;

        Ok(client_class)
    }

    // pub fn start(&mut self) { // TODO never used
    //     let metadata = verfploeter::Metadata {
    //         hostname: "temporary".to_string(),
    //         version: "1.01".to_string(),
    //     };
    //
    //     let rt = tokio::runtime::Builder::new_current_thread()
    //         .enable_all()
    //         .build()
    //         .unwrap();
    //
    //     // Connect to the server
    //     rt.block_on(async { self.connect_to_server(metadata).await.unwrap() });
    // }

    // Create a connection to the gRPC Controller server
    async fn connect() -> Result<ControllerClient<Channel>, Box<dyn std::error::Error>> {
        // Create client connection with the Controller Server
        let client = ControllerClient::connect("http://[::1]:10001").await?;

        Ok(client)
    }



    // Start the appropriate measurement based on the received task
    async fn start_measurement(&mut self, task: verfploeter::Task, client_id: u32) {
        let task_id = task.task_id;
        // Find what kind of task was sent by the Controller
        match task.data.unwrap() {
            Data::Ping(ping) => { self.init_ping(ping, task_id, client_id).await }
            Data::Empty(_) => { println!("EMPTY TASK")} //TODO error handling
        }
    }

    // Prepare for performing a ping task
    async fn init_ping(&mut self, ping: verfploeter::Ping, task_id: u32, client_id: u32) {
        // Obtain values from the Ping message

        // If there's a source address specified use it, otherwise use the one in the task.
        let mut source_addr;
        if self.source_address == 0 {
            source_addr = ping.source_address;
        } else {
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
        listen_ping(self.metadata.clone(), socket, tx, tx_f, task_id);

        // Start sending thread
        perform_ping(dest_addresses, socket2, rx_f, client_id);

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

        println!("[Client] sending client connect");
        let response = self.grpc_client.client_connect(request).await?;

        let mut stream = response.into_inner();

        while let Some(task) = stream.message().await? {
            println!("[Client] Received task! {:?}", task);
            // Only one measurement at a time, therefore it is pointless to spawn threads here
            self.start_measurement(task, client_id).await;
        }
        println!("[Client] Stopped awaiting tasks...");

        Ok(())
    }

    async fn get_client_id_to_server(&mut self) -> Result<(ClientId), Box<dyn Error>> {
        let client_id = self.grpc_client.get_client_id(Request::new(verfploeter::Empty::default())).await?.into_inner();

        Ok(client_id)
    }

    // rpc send_result(TaskResult) returns (Ack) {}
    async fn send_result_to_server(&mut self, taskresult: verfploeter::TaskResult) -> Result<(), Box<dyn Error>> {
        println!("[Client] Sending TaskResult to server");
        let request = Request::new(taskresult);
        let _ = self.grpc_client.send_result(request).await?; // TODO check ack

        Ok(())
    }

    // rpc task_finished(TaskId) returns (Ack) {}
    async fn task_finished_to_server(&mut self, task_id: verfploeter::TaskId) -> Result<(), Box<dyn Error>> {
        println!("[Client] Sending task finished to server");
        let request = Request::new(task_id);
        let _ = self.grpc_client.task_finished(request).await?; // TODO check acknowledgement

        Ok(())
    }
}