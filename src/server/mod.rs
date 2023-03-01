// gRPC/tonic dependencies
use futures_core::Stream;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;

use tonic::transport::Channel;
use std::error::Error;

// use crate::server::verfploeter::task::Data as TaskData;
//
// use crate::server::verfploeter::schedule_task::Data as ScheduleData;



// Used for sending messages to the clients
use crate::server::mpsc::Sender;

// Load in the generated code from verfploeter.proto using tonic
pub mod verfploeter {
    tonic::include_proto!("verfploeter"); // Based on the 'verfploeter' package name
}

// Load in the Controller service and Controller Server generated code
use verfploeter::controller_server::{Controller, ControllerServer};
// Load in struct definitions for the message types
use verfploeter::{
    Empty, Ack, TaskId, ScheduleTask, ClientList, Client, Task, Metadata, Ping, TaskResult,
    VerfploeterResult, PingResult, PingPayload,
};

// Load in CliClient
use verfploeter::cli_client::CliClient;
use crate::server::verfploeter::schedule_task::Data;
use crate::server;

// Struct for the Server service
#[derive(Debug)]
pub struct ControllerService {
    // clients: Arc<Vec<Client>>, // Keep a list of clients //TODO make mutable
    clients: ClientList,
    senders: Arc<Mutex<Vec<Sender<Result<verfploeter::Task, Status>>>>>,
}

// Realized largely with this tutorial https://github.com/hyperium/tonic/blob/master/examples/routeguide-tutorial.md
// The Controller service implementation
#[tonic::async_trait]
impl Controller for ControllerService {

    async fn task_finished(
        &self,
        request: Request<TaskId>,
    ) -> Result<Response<Ack>, Status> {
        println!("Received task finished");

        unimplemented!()
    }

    // Both streams are Server-sided
    type client_connectStream = ReceiverStream<Result<Task, Status>>;
    async fn client_connect(
        &self,
        request: Request<verfploeter::Metadata>,
    ) -> Result<Response<Self::client_connectStream>, Status> {
        println!("Received client_connect");

        let (mut tx, rx) = tokio::sync::mpsc::channel::<Result<verfploeter::Task, Status>>(4);
        // TODO can be replaced with a tokio::sync::broadcast::channel possible, which is single-writer, multiple reader
        // TODO this can then be a single channel that is re-used between clients

        // Store the stream sender to send tasks through later
        let mut senders = self.senders.lock().unwrap();
        senders.push(tx);

        // tokio::spawn(async move {
        //     // tx.send(Ok(Task.default())).await.unwrap(); // TODO
        // });

        // Send the stream receiver to the client
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    // If the Server were to receive a stream use this:
    // type somethingStream = Pin<Box<dyn Stream<Item = Result<MESSAGE_TYPE, Status>> + Send  + 'static>>;

    async fn do_task( // TODO
        &self,
        request: Request<ScheduleTask>,
    ) -> Result<Response<Ack>, Status> {
        println!("Received do task");

        // Get the list of Senders
        let senders_list_clone = {
            let senders_list = self.senders.lock().unwrap();
            println!("{:?}", senders_list);
            senders_list.clone()
        };

        // Create a Task from the ScheduleTask
        // Get the data from the ScheduleTask
        let task_data = match request.into_inner().data.unwrap() {
            Data::Ping(ping) => { ping }
        };
        // Create a Task with this data
        let task = verfploeter::Task {
            data: Some(server::verfploeter::task::Data::Ping(task_data)),
            task_id: 1, //TODO task_id
        };

        // Send the task to every client
        for sender in senders_list_clone.iter() {
            println!("sending task to client");
            sender.send(Ok(task.clone())).await.unwrap(); // TODO if a client crashes it will still try to send to the client here, which will crash the program
        }

        Ok(Response::new(Ack::default()))
    }

    async fn list_clients( // TODO
        &self,
        _request: Request<verfploeter::Empty>,
    ) -> Result<Response<ClientList>, Status> {
        println!("Received list clients");

        // for client in &self.clients[..] {
        //
        // }
        Ok(Response::new(ClientList::default()))
    }

    async fn send_result( // TODO
        &self,
        request: Request<TaskResult>,
    ) -> Result<Response<Ack>, Status> {
        println!("Received task result {:?}", request);

        Ok(Response::new(Ack::default()))
    }

    type subscribe_resultStream = ReceiverStream<Result<TaskResult, Status>>;

    // The server sends a Stream
    async fn subscribe_result( // TODO
        &self,
        request: Request<TaskId>,
    ) -> Result<tonic::Response<Self::subscribe_resultStream>, Status> {
        println!("Received subscribe result");

        let (mut tx, rx) = tokio::sync::mpsc::channel(4);

        tokio::spawn(async move {
            // for client in &self.clients[..] {
            //     tx.send(Ok(client.clone())).await.unwrap(); //TODO
            // }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start the Controller server
    let addr = "[::1]:10001".parse().unwrap();

    println!("Controller server listening on: {}", addr);

    let controller = ControllerService {
        clients: ClientList::default(),
        senders: Arc::new(Mutex::new(Vec::new())),
    };

    let svc = ControllerServer::new(controller);

    // Main function keeps looping here
    Server::builder().add_service(svc).serve(addr).await?;

    // Start the Cli client
    // println!("awaiting connections");
    // let mut client = CliClient::connect("http://[::1]:10001").await?;
    // println!("received connection!");

    Ok(())
}

// rpc task_finished(TaskId) returns (Ack) {}
async fn task_finished_to_cli(task_id: verfploeter::TaskId, client: &mut CliClient<Channel>) -> Result<(), Box<dyn Error>> {
    println!("Sending task finished");
    let request = Request::new(task_id);
    let response = client.task_finished(request).await?;

    println!("RESPONSE = {:?}", response);

    Ok(())
}
