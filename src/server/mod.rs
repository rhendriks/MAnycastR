use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status, transport::Server};
use std::ops::{Add, AddAssign};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use clap::ArgMatches;
use futures_core::Stream;
use tokio::spawn;
use crate::server::mpsc::Sender;
pub mod verfploeter { tonic::include_proto!("verfploeter"); }
use verfploeter::controller_server::{Controller, ControllerServer};
use verfploeter::{
    Ack, TaskId, ScheduleTask, ClientList, Task, TaskResult, ClientId, schedule_task::Data, Origin
};

/// Struct for the Server service
///
/// # Fields
///
/// * 'clients' - a ClientList that contains all connected clients (hostname and client ID)
/// * 'senders' - a list of senders that connect to the clients, these senders are used to stream Tasks
/// * 'cli_sender' - the sender that connects to the CLI, to stream TaskResults
/// * 'open_tasks' - a list of the current open tasks, and the number of clients that are currently working on it
/// * 'current_task_id' - keeps track of the last used task ID and is used to assign a unique task ID to a new measurement
/// * 'current-client_id' - keeps track of the last used client ID and is used to assign a unique client ID to a new connecting client
/// * 'active' - a boolean value that is set to true when there is an active measurement
#[derive(Debug, Clone)]
pub struct ControllerService {
    clients: Arc<Mutex<ClientList>>,
    senders: Arc<Mutex<Vec<Sender<Result<Task, Status>>>>>,
    cli_sender: Arc<Mutex<Option<Sender<Result<TaskResult, Status>>>>>,
    open_tasks: Arc<Mutex<HashMap<u32, u32>>>,
    current_task_id: Arc<Mutex<u32>>,
    current_client_id: Arc<Mutex<u32>>,
    active: Arc<Mutex<bool>>,
}

//https://github.com/hyperium/tonic/issues/196#issuecomment-567137432

/// Special Receiver struct that notices when the client disconnects.
///
/// When a client drops we update the open_tasks such that the server knows this client is not participating in any measurements.
/// Furthermore, we send a message to the CLI if it is currently performing a measurement, to let it know this client is finished.
///
/// Finally, remove this client from the client list.
pub struct ClientReceiver<T> {
    inner: mpsc::Receiver<T>,
    open_tasks: Arc<Mutex<HashMap<u32, u32>>>,
    cli_sender: Arc<Mutex<Option<Sender<Result<TaskResult, Status>>>>>,
    hostname: String,
    clients: Arc<Mutex<ClientList>>,
    active: Arc<Mutex<bool>>,
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
                    // The server no longer has to wait for this client
                    *open_tasks.get_mut(&task_id).unwrap() -= 1;

                    println!("[Server] The last client for a task dropped, sending task_finished to CLI");
                    *self.active.lock().unwrap() = false;
                    match self.cli_sender.lock().unwrap().clone().unwrap().try_send(Ok(TaskResult::default())) {
                        Ok(_) => (),
                        Err(_) => println!("[Server] Failed to send task_finished to CLI")
                    }
                // If there are more clients still performing this task
                } else {
                    // The server no longer has to wait for this client
                    *open_tasks.get_mut(&task_id).unwrap() -= 1;
                }
            }
        }
    }
}

/// Special Receiver struct that notices when the CLI disconnects.
///
/// When a CLI disconnects we cancel all open measurements. We set this server as available for receiving a new measurement.
///
/// Furthermore, if a measurement is active, we send a termination message to all clients to quit the current measurement.
pub struct CLIReceiver<T> {
    inner: mpsc::Receiver<T>,
    task_id: u32,
    active: Arc<Mutex<bool>>,
    senders: Arc<Mutex<Vec<Sender<Result<Task, Status>>>>>,
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
            let task = Task {
                task_id: self.task_id + 1000,
                // rate: 0,
                data: None,
            };

            let senders = self.senders.clone();
            let task = task.clone();

            // Tell each client to terminate the task
            for client in senders.lock().unwrap().iter() {
                let client = client.clone();
                let task = task.clone();

                spawn(async move {
                    if let Err(e) = client.send(Ok(task)).await {
                        println!("[Server] ERROR - Failed to terminate task {}", e);
                    } else {
                        println!("[Server] Terminated task at client");
                    }
                });
            }

            // Set task_active to false
            *active = false;
        }
    }
}

// The Controller service implementation
#[tonic::async_trait]
impl Controller for ControllerService {

    /// Handles a client requesting a client ID.
    ///
    /// Returns a unique client ID.
    ///
    /// # Arguments
    ///
    /// * 'request' - Metadata message that contains the client's hostname
    ///
    /// # Errors
    ///
    /// Returns an error if the hostname already exists
    async fn get_client_id(
        &self,
        request: Request<verfploeter::Metadata>
    ) -> Result<Response<ClientId>, Status> {
        println!("[Server] Received get_client_id");

        let metadata = request.into_inner();
        let hostname = metadata.hostname;
        let source_address = metadata.origin.clone().unwrap().source_address.unwrap();
        let source_port = metadata.origin.unwrap().source_port;

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
                // source_address,
                // source_port,
                origin: Some(Origin {
                    source_address: Some(source_address),
                    source_port,
                })
            }),
        };

        clients_list.clients.push(new_client);

        Ok(Response::new(ClientId{
            client_id,
        }))
    }

    /// Called by the client when it has finished its current task.
    ///
    /// When all connected clients have finished this task, it will notify the CLI that the task is finished.
    ///
    /// # Arguments
    ///
    /// * 'request' - A TaskId message
    ///
    /// # Errors
    ///
    /// Returns an error if the task ID of task finished does not match an active task, or if the CLI has disconnected.
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

    type ClientConnectStream = ClientReceiver<Result<Task, Status>>;

    /// Handles a client connecting to this server formally.
    ///
    /// Returns the receiver side of a stream to which the server will send Tasks
    ///
    /// # Arguments
    ///
    /// * 'request' - a Metadata message containing the hostname and client ID of the client
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
            active: self.active.clone(),
        };

        // Send the stream receiver to the client
        Ok(Response::new(rx))
    }

    type DoTaskStream = CLIReceiver<Result<TaskResult, Status>>;
    /// Handles the do_task command from the CLI.
    ///
    /// Instructs all clients to perform the task and returns the receiver side of a stream in which TaskResults will be streamed.
    ///
    /// Will lock active to true, such that no other measurement can start.
    ///
    /// Makes sure all clients are still connected, removes their senders if not.
    ///
    /// Assigns a unique task ID to the measurement.
    ///
    /// Streams the task to the clients, in a round-robin fashion, with 1 second delays between clients.
    ///
    /// Furthermore, lets the clients know of the desired probing rate (defined by the CLI).
    ///
    /// # Arguments
    ///
    /// * 'request' - a ScheduleTask message containing information about the task
    ///
    /// # Errors
    ///
    /// Returns an error if there is already an active measurement, or if there are no connected clients to perform the task.
    async fn do_task(
        &self,
        request: Request<ScheduleTask>,
    ) -> Result<Response<Self::DoTaskStream>, Status> {
        println!("[Server] Received do_task");
        
        // If there already is an active measurement, we skip
        {
            // If the server is already working on another measurement
            let mut active = self.active.lock().unwrap();
            if *active == true {
                println!("[Server] There is already an active task, returning");
                return Err(Status::new(tonic::Code::Cancelled, "There is already an active measurement"))
            }

            // If a client is still working on an another measurement
            let open_tasks = self.open_tasks.lock().unwrap();

            // For every open task
            for (_, open) in open_tasks.iter() {
                // If there are still clients who are working on a different measurement
                if open > &0 {
                    println!("[Server] There is already an active task, returning");
                    return Err(Status::new(tonic::Code::Cancelled, "There are still clients working on an active measurement"))
                }
            }

            *active = true;
        }

        // Get the list of Senders (that connect to the clients)
        let senders = {
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
        if senders.len() == 0 {
            println!("[Server] No connected clients, terminating task.");
            *self.active.lock().unwrap() = false;
            return Err(Status::new(tonic::Code::Cancelled, "No connected clients"));
        }

        // Obtain task id
        let task_id: u32;
        {
            let mut current_task_id = self.current_task_id.lock().unwrap();
            task_id = *current_task_id;
            current_task_id.add_assign(1);
        }

        let task = request.into_inner();
        // Create a list of the connected clients' IDs
        let mut client_list_u32: Vec<u32> = vec![];
        for client in &self.clients.lock().unwrap().clients {
            client_list_u32.push(client.client_id);
        }

        // Check if there is a list of clients specified
        let clients: Vec<u32> = task.clients;
        if clients.len() != 0 {
            // Make sure all client IDs are valid
            for client in clients.clone() {
                if !client_list_u32.contains(&client) {
                    println!("[Server] Client ID requested that is not connected, terminating task.");
                    *self.active.lock().unwrap() = false;
                    return Err(Status::new(tonic::Code::Cancelled, format!("There is no client with ID {}", client)))
                }
            }
        }
        // Store the number of clients that will perform this task
        {
            let mut open_tasks = self.open_tasks.lock().unwrap();
            open_tasks.insert(task_id, senders.len() as u32);
        }

        // Create a Task from the ScheduleTask
        // Get the destination addresses, the source address, the rate, and the task type from the CLI task
        let dest_addresses;
        let default_src_addr = task.source_address;
        let rate = task.rate;
        let task_type = task.task_type;
        match task.data.unwrap() {
            Data::Ping(ping) => {
                dest_addresses = ping.destination_addresses;
            }
            Data::Udp(udp) => {
                dest_addresses = udp.destination_addresses;
            }
            Data::Tcp(tcp) => {
                dest_addresses = tcp.destination_addresses;
            }
        };

        // Establish a stream with the CLI to return the TaskResults through
        let (tx, rx) = mpsc::channel::<Result<TaskResult, Status>>(1000);
        {
            let mut sender = self.cli_sender.lock().unwrap();
            let _ = sender.insert(tx);
        }

        // Create a list of origins used by clients
        let mut client_sources: Vec<Origin> = vec![];
        for client in &self.clients.lock().unwrap().clients {
            let mut origin = client.metadata.clone().unwrap().origin.unwrap();
            if origin.source_address.is_none() { // If this client has no source address specified, give it the CLI default one
                origin = Origin {
                    source_address: default_src_addr.clone(),
                    source_port: origin.source_port,
                }
            }
            // Avoid duplicate origins
            if !client_sources.contains(&origin) { // TODO will this work?
                client_sources.push(origin);
            }
            // client_sources.push(client.metadata.clone().unwrap().source_address.unwrap());
        }

        println!("[Server] Letting {} clients know a measurement is starting", senders.len());
        // Notify all senders that a new measurement is starting
        let mut i = 0;
        for sender in senders.iter() {
            let active = if clients.is_empty() {
                // If no client list was specified, all clients will perform the task
                true
            } else {
                // Make sure the current client is selected to perform the task
                clients.contains(client_list_u32.get(i).expect(&*format!("Client with ID {} not found", i))) // TODO client ids are not in order
            };
            i = i + 1;

            let start_task = Task {
                task_id,
                data: Some(verfploeter::task::Data::Start(verfploeter::Start {
                    rate,
                    active,
                    task_type,
                    source_address: default_src_addr.clone(),
                    origins: client_sources.clone(),
                }))
            };

            match sender.try_send(Ok(start_task.clone())) {
                Ok(_) => (),
                Err(e) => println!("[Server] Failed to send 'start measurement' {:?}", e),
            }
        }

        println!("[Server] Distributing tasks");
        let mut t: u64 = 0;
        // Create a thread that streams tasks for each client
        for sender in senders.iter() {
            t += 1;
            let sender = sender.clone();
            let dest_addresses = dest_addresses.clone();
            let active = self.active.clone();
            // This client's unique ID
            let client_id = *client_list_u32.get(t as usize - 1).unwrap();
            let clients = clients.clone();

            spawn(async move {
                let mut abort = false;
                let chunk_size: usize = 10; // TODO try increasing chunk size to reduce overhead

                // Sleep the desired time
                tokio::time::sleep(Duration::from_secs(t)).await;

                // If this client is actively probing stream tasks, else just sleep the measurement time then send the end measurement packet
                let probing = if clients.clone().len() == 0 {
                    true // All clients are probing
                } else if clients.contains(&client_id) {
                    true // This client was selected to probe
                } else {
                    false // This client was not selected to probe
                };

                // Send out packets at the required interval
                let mut interval = tokio::time::interval(Duration::from_nanos(((1.0 / rate as f64) * chunk_size as f64 * 1_000_000_000.0) as u64));

                if probing {
                    println!("[Server] streaming tasks to client with ID {}", client_id);
                } else {
                    println!("[Server] not streaming tasks to client with ID {}", client_id);
                }

                for chunk in dest_addresses.chunks(chunk_size) {
                    // If the CLI disconnects during task distribution, abort
                    if *active.lock().unwrap() == false {
                        println!("[Server] CLI disconnected during task distribution");
                        abort = true;
                        break
                    }

                    if probing {
                        let task = match task_type {
                            1 => Task {
                                task_id,
                                data: Some(verfploeter::task::Data::Ping(verfploeter::Ping {
                                    destination_addresses: chunk.to_vec(),
                                })),
                            },
                            2 | 4 => Task {
                                task_id,
                                data: Some(verfploeter::task::Data::Udp(verfploeter::Udp {
                                    destination_addresses: chunk.to_vec(),
                                })),
                            },
                            3 => Task {
                                task_id,
                                data: Some(verfploeter::task::Data::Tcp(verfploeter::Tcp {
                                    destination_addresses: chunk.to_vec(),
                                })),
                            },
                            _ => Task::default(),
                        };

                        // Send packet to client
                        match sender.send(Ok(task.clone())).await {
                            Ok(_) => (),
                            Err(e) => println!("[Server] Failed to send task to client {:?}", e),
                        }
                    }

                    interval.tick().await;
                }

                if !abort {
                    // Sleep 10 seconds to give the client time to finish the task and receive the last responses
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    println!("[Server] Sending 'task finished' to client");
                    // Send a message to the client to let it know it has received everything for the current task
                    match sender.send(Ok(Task {
                        task_id,
                        data: None,
                    })).await {
                        Ok(_) => (),
                        Err(e) => println!("[Server] Failed to send 'termination message' {:?}", e),
                    }
                }
            });
        }

        let rx = CLIReceiver {
            inner: rx,
            task_id,
            active: self.active.clone(),
            senders: self.senders.clone(),
        };

        println!("[Server] Sending task stream receiver to CLI");
        Ok(Response::new(rx))
    }

    /// Handle the list_clients command from the CLI.
    ///
    /// Returns the connected clients.
    async fn list_clients(
        &self,
        _request: Request<verfploeter::Empty>,
    ) -> Result<Response<ClientList>, Status> {
        println!("[Server] Received list_clients");
        Ok(Response::new(self.clients.lock().unwrap().clone()))
    }

    /// Receive a TaskResult from the client and put it in the stream towards the CLI
    ///
    /// # Errors
    ///
    /// Returns an error if the CLI has disconnected.
    async fn send_result(
        &self,
        request: Request<TaskResult>,
    ) -> Result<Response<Ack>, Status> {
        // Send the result to the CLI through the established stream
        let tx = {
            let sender = self.cli_sender.lock().unwrap();
            sender.clone().unwrap()
        };

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

/// Start the server.
///
/// Starts the server on the specified port.
///
/// # Arguments
///
/// * 'args' - the parsed command-line arguments
pub async fn start(args: &ArgMatches<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let port = args.value_of("port").expect("No port specified");
    let addr: SocketAddr = "0.0.0.0:".to_string().add(port).parse().unwrap();

    println!("[Server] Controller server listening on: {}", addr);

    let controller = ControllerService {
        clients: Arc::new(Mutex::new(ClientList::default())),
        senders: Arc::new(Mutex::new(Vec::new())),
        cli_sender: Arc::new(Mutex::new(None)),
        open_tasks: Arc::new(Mutex::new(HashMap::new())),
        current_task_id: Arc::new(Mutex::new(156434)),
        current_client_id: Arc::new(Mutex::new(1)),
        active: Arc::new(Mutex::new(false)),
    };

    let svc = ControllerServer::new(controller);

    Server::builder().add_service(svc).serve(addr).await?;

    Ok(())
}
