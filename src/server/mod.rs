use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};
use tonic::transport::Server;

use std::ops::{Add, AddAssign};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;
use clap::ArgMatches;
use futures_core::Stream;

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
    Ack, TaskId, ScheduleTask, ClientList, Task, TaskResult, ClientId, schedule_task::Data
};

// Struct for the Server service
#[derive(Debug, Clone)]
pub struct ControllerService {
    clients: Arc<Mutex<ClientList>>,
    senders: Arc<Mutex<Vec<Sender<Result<verfploeter::Task, Status>>>>>,
    cli_sender: Arc<Mutex<Option<Sender<Result<verfploeter::TaskResult, Status>>>>>,
    open_tasks: Arc<Mutex<HashMap<u32, u32>>>,
    current_task_id: Arc<Mutex<u32>>,
    current_client_id: Arc<Mutex<u32>>,
    active: Arc<Mutex<bool>>,
}

//https://github.com/hyperium/tonic/issues/196#issuecomment-567137432

// Special Receiver struct that notices when the receiver drops
// This allows us to detect when a client has disconnected and handle it
pub struct ClientReceiver<T> {
    inner: mpsc::Receiver<T>,
    open_tasks: Arc<Mutex<HashMap<u32, u32>>>,
    cli_sender: Arc<Mutex<Option<Sender<Result<verfploeter::TaskResult, Status>>>>>,
    hostname: String,
    clients: Arc<Mutex<ClientList>>,
}

impl<T> Stream for ClientReceiver<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.inner.poll_recv(cx)
    }
}

impl<T> Drop for ClientReceiver<T> {
    fn drop(&mut self) {
        println!("[Server] Client receiver has been dropped");

        // Remove this client from the clients list
        let mut clientslist = self.clients.lock().unwrap();
        let mut i = 0;
        for client in clientslist.clients.clone() {
            if client.metadata.unwrap().hostname == self.hostname {
                clientslist.clients.remove(i);
                break;
            }
            i += 1;
        }

        // Handle the open tasks that involve this client
        let mut open_tasks = self.open_tasks.lock().unwrap();
        if open_tasks.len() > 0 {
            for (task_id, remaining) in open_tasks.clone().iter( ){
                // If this task is already finished
                if remaining == &0 {
                    continue
                }
                // If this is the last client for this open task
                if remaining == &1 {
                    println!("[Server] The last client for a task dropped, sending task finished to CLI");
                    self.cli_sender.lock().unwrap().clone().unwrap().try_send(Ok(TaskResult::default())).unwrap();
                // If there are more clients still performing this task
                } else {
                    // The server no longer has to wait for this client
                    *open_tasks.get_mut(&task_id).unwrap() -= 1;
                }
            }
        }
    }
}

// Special Receiver struct that notices when the receiver drops
// This allows us to detect when a CLI has disconnected and handle it
pub struct CLIReceiver<T> {
    inner: mpsc::Receiver<T>,
    open_tasks: Arc<Mutex<HashMap<u32, u32>>>,
    task_id: u32,
    active: Arc<Mutex<bool>>,
    senders: Arc<Mutex<Vec<Sender<Result<verfploeter::Task, Status>>>>>,
    // Client senders
}

impl<T> Stream for CLIReceiver<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.inner.poll_recv(cx)
    }
}

impl<T> Drop for CLIReceiver<T> {
    fn drop(&mut self) {
        println!("[Server] CLI receiver has been dropped");

        let mut active = self.active.lock().unwrap();

        // If there is an active task we need to cancel it and notify the clients
        if *active == true {

            // Create termination 'task'
            let task = verfploeter::Task {
                data: None,
                task_id: self.task_id,
            };

            // Tell each client to terminate the task
            for client in self.senders.lock().unwrap().iter() {
                if let Ok(_) = client.try_send(Ok(task.clone())) {
                    println!("[Server] Terminated task at client");
                } else {
                    println!("[Server] ERROR - Failed to terminate task");
                }
            }

            // Handle the open task that this CLI created
            let mut open_tasks = self.open_tasks.lock().unwrap();
            open_tasks.remove(&self.task_id);

            // Set task_active to false
            *active = false;
        }
    }
}

// gRPC tutorial https://github.com/hyperium/tonic/blob/master/examples/routeguide-tutorial.md
// The Controller service implementation
#[tonic::async_trait]
impl Controller for ControllerService {

    async fn get_client_id(
        &self,
        request: Request<verfploeter::Metadata>
    ) -> Result<Response<ClientId>, Status> {
        println!("[Server] Received get_client_id");

        let metadata = request.into_inner();
        let hostname = metadata.hostname;

        let mut clients_list = self.clients.lock().unwrap();

        for client in clients_list.clone().clients.into_iter() {
            if hostname == client.metadata.unwrap().hostname {
                println!("[Server] Refusing client as the hostname already exists: {}", hostname);
                return Err(Status::new(tonic::Code::AlreadyExists, "This hostname already exists"));
            }
        }

        // Obtain client id
        let client_id: u32;
        {
            let mut current_client_id = self.current_client_id.lock().unwrap();
            client_id = *current_client_id;
            current_client_id.add_assign(1);
        }

        // Add the client to the client list
        let new_client = verfploeter::Client {
            client_id,
            metadata: Some(verfploeter::Metadata {
                hostname: hostname.clone(),
            }),
        };

        clients_list.clients.push(new_client);

        Ok(Response::new(ClientId{
            client_id,
        }))
    }

    async fn task_finished(
        &self,
        request: Request<TaskId>,
    ) -> Result<Response<Ack>, Status> {
        println!("[Server] Received task_finished");

        let task_id: u32 = request.into_inner().clone().task_id;

        let tx = {
            let sender = self.cli_sender.lock().unwrap();
            sender.clone().unwrap()
        };

        // Wait till we have received 'task_finished' from all clients that executed this task
        let finished: bool;
        {
            let mut open_tasks = self.open_tasks.lock().unwrap();

            let remaining: &u32;
            if let Some(value) = open_tasks.get(&task_id) {
                remaining = value;
            } else {
                println!("[Server] Received task_finished for non-existent task {}", &task_id);
                return Ok(Response::new(Ack {
                    success: false,
                    error_message: "Task unknown".to_string(),
                }))
            }
            // If this is the last client we are finished
            if remaining == &(1 as u32) {
                open_tasks.remove(&task_id);
                finished = true;
            // If this is not the last client, decrement the amount of remaining clients
            } else {
                *open_tasks.get_mut(&task_id).unwrap() -= 1;
                finished = false;
            }
        }
        if finished {
            println!("[Server] Sending default value to CLI, notifying the task is finished");
            // There is no longer an active measurement
            *self.active.lock().unwrap() = false;

            return match tx.send(Ok(TaskResult::default())).await {
                Ok(_) => Ok(Response::new(Ack {
                    success: true,
                    error_message: "".to_string(),
                })),
                Err(_) => Ok(Response::new(Ack {
                    success: false,
                    error_message: "CLI disconnected".to_string(),
                })),
            }
        }
        Ok(Response::new(Ack {
            success: true,
            error_message: "".to_string(),
        }))
    }

    // Both streams are Server-sided
    type ClientConnectStream = ClientReceiver<Result<Task, Status>>;
    async fn client_connect(
        &self,
        request: Request<verfploeter::Metadata>,
    ) -> Result<Response<Self::ClientConnectStream>, Status> {
        println!("[Server] Received client_connect");

        let hostname = request.into_inner().hostname;

        let (tx, rx) = mpsc::channel::<Result<verfploeter::Task, Status>>(1000);

        // Store the stream sender to send tasks through later
        {
            let mut senders = self.senders.lock().unwrap();
            senders.push(tx);
        }

        let rx = ClientReceiver {
            inner: rx,
            open_tasks: self.open_tasks.clone(),
            cli_sender: self.cli_sender.clone(),
            hostname: hostname.clone(),
            clients: self.clients.clone(),
        };
        // Send the stream receiver to the client
        Ok(Response::new(rx))
    }

    type DoTaskStream = CLIReceiver<Result<TaskResult, Status>>;
    async fn do_task(
        &self,
        request: Request<ScheduleTask>,
    ) -> Result<Response<Self::DoTaskStream>, Status> {
        println!("[Server] Received do_task");
        
        // If there already is an active measurement, we skip
        {
            let mut active = self.active.lock().unwrap();
            if *active == true {
                println!("[Server] There is already an active task, returning");
                return Err(Status::new(tonic::Code::Cancelled, "There is already an active measurement"))
            } else {
                *active = true;
            }
        }

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
                } else {
                    i += 1
                }
            }
            senders
        };

        // If there are no connected clients that can perform this task
        if senders_list_clone.len() == 0 {
            println!("[Server] No connected clients, termination task.");
            *self.active.lock().unwrap() = false;
            return Err(Status::new(tonic::Code::Cancelled, "No connected clients"));
        }

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
            open_tasks.insert(task_id, senders_list_clone.len() as u32);
        }

        // Create a Task from the ScheduleTask
        // Get the destination addresses, the source address and the task type from the CLI task
        let dest_addresses;
        let src_addr;
        let task_type = match request.into_inner().data.unwrap() {
            Data::Ping(ping) => {
                dest_addresses = ping.destination_addresses;
                src_addr = ping.source_address;
                1
            }
            Data::Udp(udp) => {
                dest_addresses = udp.destination_addresses;
                src_addr = udp.source_address;
                2
            }
            Data::Tcp(tcp) => {
                dest_addresses = tcp.destination_addresses;
                src_addr = tcp.source_address;
                3
            }
        };

        // Establish a stream with the CLI to return the TaskResults through
        let (tx, rx) = mpsc::channel::<Result<verfploeter::TaskResult, Status>>(1000); // TODO
        {
            let mut sender = self.cli_sender.lock().unwrap();
            let _ = sender.insert(tx);
        }

        let self_clone = self.clone();
        let task_distribution = move || {
            let senders_list_clone = self_clone.senders.lock().unwrap().clone();

            // Split the destination addresses into chunks and create a task for each chunk
            for chunk in dest_addresses.chunks(100) {
                // Create a Task with this data
                let task = match task_type {
                    1 => verfploeter::Task {
                        data: Some(verfploeter::task::Data::Ping(verfploeter::Ping {
                            source_address: src_addr,
                            destination_addresses: chunk.to_vec(),
                        })),
                        task_id,
                    },
                    2 => verfploeter::Task {
                        data: Some(verfploeter::task::Data::Udp(verfploeter::Udp {
                            source_address: src_addr,
                            destination_addresses: chunk.to_vec(),
                        })),
                        task_id,
                    },
                    3 => verfploeter::Task {
                        data: Some(verfploeter::task::Data::Tcp(verfploeter::Tcp {
                            source_address: src_addr,
                            destination_addresses: chunk.to_vec(),
                        })),
                        task_id,
                    },
                    _ => verfploeter::Task::default(),
                };

                // Send task to each client, and wait 1 second in between
                for sender in senders_list_clone.iter() {

                    // If the CLI disconnects during task distribution, abort
                    if *self_clone.active.lock().unwrap() == false {
                        println!("[Server] CLI disconnected during task distribution");
                        break
                    }
                    // Sleep one second such that time between probes is ~1 second
                    thread::sleep(Duration::from_secs(1));
                    // TODO if the time to send the task to client is significant, the time between probes will not be ~1 second
                    // Send packet to client
                    if let Ok(_) = sender.try_send(Ok(task.clone())) {
                        println!("[Server] Sent task to client");
                    } else {
                        println!("[Server] ERROR - Failed to send task to client");
                    }
                }
            }
            // Send a message to each client to let it know it has received everything for the current task
            for sender in senders_list_clone.clone().into_iter() {
                sender.try_send(Ok(verfploeter::Task {
                    data: None,
                    task_id,
                })).unwrap();
            }
        };

        // Spawn a new thread to execute the task distribution closure
        let task_thread = thread::spawn(task_distribution);
        // TODO splitting the addresses in small chunks of 100, and waiting 1 second between sending it to each client
        // TODO will drastically increase the probing time

        let rx = CLIReceiver {
            inner: rx,
            open_tasks: self.open_tasks.clone(),
            task_id,
            active: self.active.clone(),
            senders: self.senders.clone(),
        };

        println!("[Server] Sending task stream receiver to CLI");
        Ok(Response::new(rx))
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
        match tx.send(Ok(request.into_inner())).await {
            Ok(_) => Ok(Response::new(Ack {
                success: true,
                error_message: "".to_string(),
            })),
            Err(_) => Ok(Response::new(Ack {
                success: false,
                error_message: "CLI disconnected".to_string(),
            })),
        }
    }
}

// Start the server
pub async fn start(args: &ArgMatches<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let port = args.value_of("port").unwrap();
    let addr: SocketAddr = "0.0.0.0:".to_string().add(port).parse().unwrap();

    println!("[Server] Controller server listening on: {}", addr);

    let controller = ControllerService {
        clients: Arc::new(Mutex::new(ClientList::default())),
        senders: Arc::new(Mutex::new(Vec::new())),
        cli_sender: Arc::new(Mutex::new(None)),
        open_tasks: Arc::new(Mutex::new(HashMap::new())),

        current_task_id: Arc::new(Mutex::new(156434)),
        current_client_id: Arc::new(Mutex::new(0)),
        active: Arc::new(Mutex::new(false)),
    };

    let svc = ControllerServer::new(controller);

    Server::builder().add_service(svc).serve(addr).await?;

    Ok(())
}