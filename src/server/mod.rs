use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;

use std::ops::AddAssign;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;
use futures_core::Stream;
use tokio::sync::mpsc::error::TryRecvError;

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
    VerfploeterResult, PingResult, PingPayload, ClientId
};

// Load in CliClient
// use verfploeter::cli_client::CliClient;
use crate::server::verfploeter::schedule_task::Data;
use crate::server;

// Struct for the Server service
#[derive(Debug)]
pub struct ControllerService {
    clients: Arc<Mutex<ClientList>>,
    senders: Arc<Mutex<Vec<Sender<Result<verfploeter::Task, Status>>>>>,
    cli_sender: Arc<Mutex<Option<Sender<Result<verfploeter::TaskResult, Status>>>>>,
    open_tasks: Arc<Mutex<HashMap<u32, u32>>>,
    current_task_id: Arc<Mutex<u32>>,
    current_client_id: Arc<Mutex<u32>>,
}

pub struct MyStream(tokio::sync::mpsc::Receiver<Result<Task, Status>>);

// In here you just need to forward the `poll_accept` call
// to the inner `Reciever`.

//https://github.com/hyperium/tonic/issues/196#issuecomment-567137432

//https://github.com/hyperium/tonic/issues/377

// Special Receiver struct that notices when the receiver drops
// This allows us to detect when a client has disconnected and handle it
pub struct DropReceiver<T> {
    inner: mpsc::Receiver<T>,
    open_tasks: Arc<Mutex<HashMap<u32, u32>>>,
    cli_sender: Arc<Mutex<Option<Sender<Result<verfploeter::TaskResult, Status>>>>>,
}

impl<T> Stream for DropReceiver<T> {
    type Item = T;

    fn poll_next(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.inner.poll_recv(cx)
    }
}

impl<T> Drop for DropReceiver<T> {
    fn drop(&mut self) {
        println!("[Server] Receiver has been dropped");


        let mut open_tasks = self.open_tasks.lock().unwrap();

        if open_tasks.len() > 0 {
            for (task_id, remaining) in open_tasks.clone().iter( ){
                // If this task is already finished
                if remaining == &0 {
                    continue
                }
                // If this is the last client for this open task
                if remaining == &1 {
                    println!("[Server] Sending task finished to CLI !!");
                    self.cli_sender.lock().unwrap().clone().unwrap().try_send(Ok(TaskResult::default())).unwrap();
                    // TODO doesn't get sent to CLI
                // If there are more clients still performing this task
                } else {
                    // The server no longer has to wait for this client
                    *open_tasks.get_mut(&task_id).unwrap() -= 1;
                }
            }
        }
    }
}

// gRPC tutorial https://github.com/hyperium/tonic/blob/master/examples/routeguide-tutorial.md
// The Controller service implementation
#[tonic::async_trait]
impl Controller for ControllerService {

    async fn get_client_id(
        &self,
        request: Request<verfploeter::Empty>
    ) -> Result<Response<ClientId>, Status> {

        // Obtain client id
        let client_id: u32;
        {
            let mut current_client_id = self.current_client_id.lock().unwrap();
            client_id = *current_client_id;
            current_client_id.add_assign(1);
        }

        Ok(Response::new(ClientId{
            client_id,
        }))
    }

    async fn task_finished(
        &self,
        request: Request<TaskId>,
    ) -> Result<Response<Ack>, Status> {
        println!("[Server] Received task finished");

        let task_id: u32 = request.into_inner().task_id;

        let tx = {
            let sender = self.cli_sender.lock().unwrap();
            sender.clone().unwrap()
        };

        // Wait till we have received 'task_finished' from all clients that executed this task
        let finished: bool;
        {
            let mut open_tasks = self.open_tasks.lock().unwrap();

            let remaining: &u32 = open_tasks.get(&task_id).unwrap();
            // If this is the last client we are finished
            if remaining == &(1 as u32) {
                open_tasks.remove(&task_id);
                finished = true;
            // If this is not the last client, decrement the amount of remaining clients
            } else {
                *open_tasks.get_mut(&task_id).unwrap() -= 1;
                finished = false;
                // open_tasks.insert(task_id, remaining.add_subtract(1));
            }
        }
        if finished {
            println!("[Server] Sending default value to CLI, notifying the task is finished");
            tx.send(Ok(TaskResult::default())).await.unwrap();
        }

        Ok(Response::new(Ack::default()))
    }

    // Both streams are Server-sided
    type client_connectStream = DropReceiver<Result<Task, Status>>;
    async fn client_connect(
        &self,
        request: Request<verfploeter::Metadata>,
    ) -> Result<Response<Self::client_connectStream>, Status> {
        println!("[Server] Received client_connect");

        // Add the client to the client list
        {
            let mut clients_list = self.clients.lock().unwrap();

            let new_client = verfploeter::Client { // TODO remove this client when he disconnects/loses connection/crashes
                // index: 0,
                metadata: Some(request.into_inner()),
            };

            clients_list.clients.push(new_client);
        };

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<verfploeter::Task, Status>>(1000);

        // Store the stream sender to send tasks through later
        {
            let mut senders = self.senders.lock().unwrap();
            senders.push(tx);
        }

        let rx = DropReceiver {
            inner: rx,
            open_tasks: self.open_tasks.clone(),
            cli_sender: self.cli_sender.clone(),
        };
        // Send the stream receiver to the client
        Ok(Response::new(rx))
    }

    type do_taskStream = ReceiverStream<Result<TaskResult, Status>>;
    async fn do_task(
        &self,
        request: Request<ScheduleTask>,
    ) -> Result<Response<Self::do_taskStream>, Status> {
        println!("[Server] Received do_task");

        // Get the list of Senders (that connect to the clients)
        let senders_list_clone = {
            // Make sure all clients still have an open connection
            let mut i = 0;
            let mut senders = self.senders.lock().unwrap();
            // Temporary clone to loop over (as we will be changing the senders during this loop)
            let senders_temp = senders.clone();

            for sender in senders_temp {
                // If the sender is closed
                if sender.is_closed() {
                    println!("[Server] Client unavailable, connection closed. Client removed.");
                    // Remove this sender
                    senders.remove(i);
                    println!("removed");
                } else {
                    i += 1
                }
            }
            senders
        };

        // If there are connected clients that will perform this task
        if senders_list_clone.len() > 0 {
            // obtain task id
            let task_id: u32;
            {
                let mut current_task_id = self.current_task_id.lock().unwrap();
                task_id = *current_task_id;
                current_task_id.add_assign(1);
            }

            // Store the number of clients that will perform this task
            {
                let mut open_tasks = self.open_tasks.lock().unwrap();
                println!("LEN {:?}", senders_list_clone);
                open_tasks.insert(task_id, senders_list_clone.len() as u32);
            }

            // Create a Task from the ScheduleTask
            // Get the data from the ScheduleTask
            let task_data = match request.into_inner().data.unwrap() {
                Data::Ping(ping) => { ping }
            };
            // Create a Task with this data
            let task = verfploeter::Task {
                data: Some(server::verfploeter::task::Data::Ping(task_data)),
                task_id,
            };

            // Send the task to every client
            for sender in senders_list_clone.iter() {
                // Send packet to client
                if let Ok(_) = sender.try_send(Ok(task.clone())) {
                    println!("[Server] Sent task to client");
                } else {
                    println!("[Server] ERROR - Failed to send task to client"); // TODO error handling
                }
            }

            // Establish a stream with the CLI to return the TaskResults through
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<verfploeter::TaskResult, Status>>(1000);
            {
                let mut sender = self.cli_sender.lock().unwrap();
                let _ = sender.insert(tx);
            }

            // TODO spawn thread that periodically checks if all clients are connected and will handle it when they are not


            Ok(Response::new(ReceiverStream::new(rx)))
        // If there are no connected clients
        } else {
            Err(Status::new(tonic::Code::Cancelled, "No connected clients"))
        }
    }

    async fn list_clients(
        &self,
        _request: Request<verfploeter::Empty>,
    ) -> Result<Response<ClientList>, Status> {
        println!("[Server] Received list_clients");
        Ok(Response::new(self.clients.lock().unwrap().clone()))
    }

    // Receive a TaskResult from the client and put it in the stream towards the CLI
    async fn send_result(
        &self,
        request: Request<TaskResult>,
    ) -> Result<Response<Ack>, Status> {
        println!("[Server] Received send_result");

        // Send the result to the CLI through the established stream
        let tx = {
            let sender = self.cli_sender.lock().unwrap();
            sender.clone().unwrap()
        };

        println!("[Server] Forwarding result to CLI");
        tx.send(Ok(request.into_inner())).await.unwrap();

        Ok(Response::new(Ack::default()))
    }
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start the Controller server
    let addr = "[::1]:10001".parse().unwrap();

    println!("[Server] Controller server listening on: {}", addr);

    let controller = ControllerService {
        clients: Arc::new(Mutex::new(ClientList::default())),
        senders: Arc::new(Mutex::new(Vec::new())),
        cli_sender: Arc::new(Mutex::new(None)),
        open_tasks: Arc::new(Mutex::new(HashMap::new())),

        current_task_id: Arc::new(Mutex::new(156434)), // TODO create random value as initial task id?
        current_client_id: Arc::new(Mutex::new(0)),
    };

    let svc = ControllerServer::new(controller);

    Server::builder().add_service(svc).serve(addr).await?;

    Ok(())
}