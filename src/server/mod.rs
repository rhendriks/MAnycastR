use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status, transport::Server};
use std::ops::{Add, AddAssign};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use clap::ArgMatches;
use futures_core::Stream;
use rand::Rng;
use tokio::spawn;
use tonic::transport::{Identity, ServerTlsConfig};
use crate::server::mpsc::Sender;
use crate::custom_module;
use custom_module::IP;
use custom_module::verfploeter::{
    Ack, Finished, ScheduleTask, ClientList, Task, TaskResult, ClientId, schedule_task::Data, Origin,
    verfploeter_result::Value::Ping as PingResult, verfploeter_result::Value::Udp as UdpResult, verfploeter_result::Value::Tcp as TcpResult,
    controller_server::Controller, controller_server::ControllerServer, Address, task::Data::End as TaskEnd, End,
    task::Data::Trace as TaskTrace, Trace, task::Data::Start as TaskStart, Start, task::Data::Ping as TaskPing, Ping,
    task::Data::Udp as TaskUdp, Udp, task::Data::Tcp as TaskTcp, Tcp,
    Metadata, Client, Empty, ip_result::Value::Ipv6, ip_result::Value::Ipv4
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
/// * 'current_client_id' - keeps track of the last used client ID and is used to assign a unique client ID to a new connecting client
/// * 'active' - a boolean value that is set to true when there is an active measurement
/// * 'traceroute_targets' - a map that keeps track of the clients that have received probe replies for a specific target, and the 'flows' that reach each client
/// * 'traceroute' - a boolean value that is set to true when traceroute is enabled
/// * 'interval' - the interval between clients sending out probes to the same target
#[derive(Debug, Clone)]
pub struct ControllerService {
    clients: Arc<Mutex<ClientList>>, // TODO combine clients and senders into one struct
    senders: Arc<Mutex<Vec<Sender<Result<Task, Status>>>>>,
    cli_sender: Arc<Mutex<Option<Sender<Result<TaskResult, Status>>>>>,
    open_tasks: Arc<Mutex<HashMap<u32, u32>>>,
    current_task_id: Arc<Mutex<u32>>,
    current_client_id: Arc<Mutex<u32>>,
    active: Arc<Mutex<bool>>,
    traceroute_targets: Arc<tokio::sync::Mutex<HashMap<IP, (Vec<u8>, Instant, u8, Vec<Origin>)>>>, // IP -> (clients, timestamp, ttl, flows)
    traceroute: Arc<Mutex<bool>>,
}

/// Special Receiver struct that notices when the client disconnects.
///
/// When a client drops we update the open_tasks such that the server knows this client is not participating in any measurements.
/// Furthermore, we send a message to the CLI if it is currently performing a measurement, to let it know this client is finished.
///
/// Finally, remove this client from the client list.
///
/// # Fields
///
/// * 'inner' - the receiver that connects to the client
///
/// * 'open_tasks' - a list of the current open tasks, and the number of clients that are currently working on it
///
/// * 'cli_sender' - the sender that connects to the CLI
///
/// * 'hostname' - the hostname of the client
///
/// * 'clients' - a ClientList that contains all connected clients (hostname and client ID)
///
/// * 'active' - a boolean value that is set to true when there is an active measurement
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
                    open_tasks.remove(&task_id);

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
///
/// # Fields
///
/// * 'inner' - the receiver that connects to the CLI
///
/// * 'active' - a boolean value that is set to true when there is an active measurement
///
/// * 'senders' - a list of senders that connect to the clients
pub struct CLIReceiver<T> {
    inner: mpsc::Receiver<T>,
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
        let mut active = self.active.lock().unwrap();

        // If there is an active task we need to cancel it and notify the clients
        if *active == true {
            println!("[Server] CLI dropped during an active measurement, terminating task");

            // Create termination 'task'
            let task = Task {
                data: Some(TaskEnd(End {
                })),
            };

            // Tell each client to terminate the task
            for client in self.senders.lock().unwrap().iter() {
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
        request: Request<Finished>,
    ) -> Result<Response<Ack>, Status> {
        let request = request.into_inner();
        let task_id: u32 = request.task_id;
        let tx = self.cli_sender.lock().unwrap().clone().unwrap();

        // Wait till we have received 'task_finished' from all clients that executed this task
        let finished: bool;
        { // TODO if a client disconnects during a measurement, this will hang
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
            if remaining == &(1u32) {
                println!("{}", request.client_id);
                println!("[Server] All clients finished");

                open_tasks.remove(&task_id);
                finished = true;
                // If this is not the last client, decrement the amount of remaining clients
            } else {
                // Print the client ID that finished the task
                print!("{},", request.client_id);
                *open_tasks.get_mut(&task_id).unwrap() -= 1;
                finished = false;
            }
        }
        if finished {
            println!("[Server] Notifying CLI that task {} is finished", task_id);
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
    /// * 'request' - a Metadata message containing the hostname of the client
    async fn client_connect(
        &self,
        request: Request<Metadata>,
    ) -> Result<Response<Self::ClientConnectStream>, Status> {
        let hostname = request.into_inner().hostname;
        println!("[Server] New client connected: {}", hostname);
        let (tx, rx) = mpsc::channel::<Result<Task, Status>>(1000);

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
    /// Streams the task to the clients, in a round-robin fashion, with 1-second delays between clients.
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
        println!("[Server] Received CLI measurement request");

        // If there already is an active measurement, we skip
        {
            // If the server is already working on another measurement
            let mut active = self.active.lock().unwrap();
            if *active == true {
                println!("[Server] There is already an active task, returning");
                return Err(Status::new(tonic::Code::Cancelled, "There is already an active measurement"))
            }

            // If a client is still working on another measurement
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
            *current_task_id = current_task_id.wrapping_add(1);
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
        let dest_addresses;
        let unicast = task.unicast;

        // Get the probe origins
        let probe_origins: Vec<Origin> = if unicast {
            vec![task.origin.clone().unwrap()] // Contains port values
        } else if task.configurations.len() > 0 {
            vec![]
        }
        else {
            vec![task.origin.clone().unwrap()]
        };

        let rate = task.rate;
        let task_type = task.task_type;
        let ipv6 = task.ipv6;
        let traceroute = task.traceroute;
        let divide = task.divide;
        let clients_interval = task.interval;
        *self.traceroute.lock().unwrap() = traceroute;
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
        // let mut listen_origins: Vec<Origin> = vec![];
        let mut listen_origins = probe_origins.clone(); // TODO support multiple listen origins

        // Add all configuration origins to the listen origins
        for configuration in task.configurations.clone() {
            let origin = configuration.origin.unwrap();
            // Avoid duplicate origins
            if !listen_origins.contains(&origin) {
                listen_origins.push(origin);
            }
        }

        // If traceroute is enabled, start a thread that handles when and how the clients should perform traceroute
        if traceroute {
            let targets = self.traceroute_targets.clone();
            let senders = self.senders.clone();
            // Thread that cleans up the targets map and instruct traceroute
            spawn(async move {
                loop {
                    let cleanup_interval = Duration::from_secs(40);
                    // Sleep for the cleanup interval
                    tokio::time::sleep(cleanup_interval).await;
                    // Perform the cleanup
                    let mut map = targets.lock().await;
                    let mut traceroute_targets = HashMap::new();

                    for (target, (clients, timestamp, _, _)) in map.clone().iter() {
                        if Instant::now().duration_since(*timestamp) > cleanup_interval {
                            let value = map.remove(target).expect("Failed to remove target from map");
                            if clients.len() > 1 {
                                println!("Tracerouting to {} from clients {:?}", target, clients);
                                traceroute_targets.insert(target.clone(), value);
                            }
                        }
                    }

                    for (target, (clients, _, ttl, origins)) in traceroute_targets {
                        // Get the upper bound TTL we should perform traceroute with
                        let max_ttl = if ttl >= 128 {
                            255 - ttl
                        } else if ttl >= 64 {
                            128 - ttl
                        } else {
                            64 - ttl
                        } as u32;

                        let traceroute_task = Task {
                            data: Some(TaskTrace(Trace {
                                max_ttl,
                                destination_address: Some(Address::from(target.clone())),
                                origins,
                            }))
                        };

                        // TODO make sure client_id is mapped to the right sender
                        // TODO when client IDs don't start at 1, this will fail
                        for client_id in clients { // Instruct all clients (that received probe replies) to perform traceroute
                            // Sleep 1 second between each client to avoid rate limiting
                            // tokio::time::sleep(Duration::from_secs(1)).await;
                            // TODO will fail when clients have been instructed to end
                            senders.lock().unwrap().get(client_id as usize - 1).unwrap().try_send(Ok(traceroute_task.clone())).expect("Failed to send traceroute task");
                        }
                    }


                }
            });
        }

        println!("[Server] Letting {} clients know a measurement is starting", senders.len());
        // Notify all senders that a new measurement is starting
        let mut i = 0;
        let mut active_clients = 0;
        for sender in senders.iter() {
            let mut client_probe_origins = probe_origins.clone();

            // TODO add configuration origins assigned to this client to probe_origins
            for configuration in task.configurations.clone() {
                if (configuration.client_id == *client_list_u32.get(i).unwrap()) | (configuration.client_id == u32::MAX) {
                    let origin = configuration.origin.unwrap();
                    // Avoid duplicate origins
                    if !client_probe_origins.contains(&origin) {
                        client_probe_origins.push(origin);
                    }
                }
            }

            let active = if clients.is_empty() {
                // No client-selective probing
                if client_probe_origins.len() == 0 {
                    false // No probe origins -> not probing
                } else {
                    true
                }
            } else {
                // Make sure the current client is selected to perform the task
                clients.contains(client_list_u32.get(i).expect(&*format!("Client with ID {} not found", i)))
            };
            if active { active_clients += 1; }
            i = i + 1;

            let start_task = Task {
                data: Some(TaskStart(Start {
                    rate,
                    task_id,
                    active,
                    task_type,
                    unicast,
                    ipv6,
                    traceroute,
                    probe_origins: client_probe_origins.clone(),
                    listen_origins: listen_origins.clone(),
                }))
            };

            match sender.try_send(Ok(start_task.clone())) {
                Ok(_) => (),
                Err(e) => println!("[Server] Failed to send 'start measurement' {:?}", e),
            }
        }

        let number_of_clients = senders.len() as u64;

        if !divide {
            println!("[Server] {} clients will listen for probe replies, {} clients will send out probes to the same target {} seconds after each other", number_of_clients, active_clients, clients_interval);
        } else {
            println!("[Server] {} clients will listen for probe replies, {} client will send out probes to a different chunk of the destination addresses", number_of_clients, active_clients);
        }

        // Shared variable to keep track of the number of clients that have finished
        let clients_finished = Arc::new(Mutex::new(0));
        // Shared channel that clients will wait for till the last client has finished
        let (tx_f, _) = tokio::sync::broadcast::channel::<()>(1);
        let mut t: u64 = 0; // Index for active clients
        let mut i = 0; // Index for the client list

        // Create a thread that streams tasks for each client
        for sender in senders.iter() {
            let sender = sender.clone();
            // This client's unique ID
            let client_id = *client_list_u32.get(i as usize).unwrap();
            i += 1;
            let clients = clients.clone();
            // If clients is empty, all clients are probing, otherwise only the clients in the list are probing
            let probing = clients.len() == 0 || clients.contains(&client_id);

            let dest_addresses = if !probing {
                vec![]
            } else if divide {
                // Each client gets its own chunk of the destination addresses
                let chunk_size = dest_addresses.len() / active_clients as usize;

                // Get start and end index of targets to probe for this client
                let start_index = t as usize * chunk_size;
                let end_index = if t == active_clients - 1 {
                    dest_addresses.len() // End of the list
                } else {
                    start_index + chunk_size
                };

                dest_addresses[start_index..end_index].to_vec()
            } else {
                // All clients get the same destination addresses
                dest_addresses.clone()
            };

            // increment if this client is sending probes
            if probing { t += 1; }

            let tx_f = tx_f.clone();
            let mut rx_f = tx_f.subscribe();
            let clients_finished = clients_finished.clone();

            let active = self.active.clone();
            spawn(async move {
                let chunk_size: usize = 10; // TODO try increasing chunk size to reduce overhead

                // Synchronize clients probing by sleeping for a certain amount of time (ensures clients send out probes to the same target 1 second after each other)
                if probing && !divide {
                    tokio::time::sleep(Duration::from_secs((t - 1) * clients_interval as u64)).await;
                }

                // Send out packets at the required interval
                let mut interval = tokio::time::interval(Duration::from_nanos(((1.0 / rate as f64) * chunk_size as f64 * 1_000_000_000.0) as u64));

                for chunk in dest_addresses.chunks(chunk_size) {
                    // If the CLI disconnects during task distribution, abort
                    if *active.lock().unwrap() == false {
                        clients_finished.lock().unwrap().add_assign(1); // This client is 'finished'
                        if clients_finished.lock().unwrap().clone() == number_of_clients {
                            println!("[Server] CLI disconnected during task distribution");
                            tx_f.send(()).expect("Failed to send finished signal");
                        }
                        return // abort
                    }

                    if probing {
                        let task = match task_type {
                            1 => Task {
                                data: Some(TaskPing(Ping {
                                    destination_addresses: chunk.to_vec(),
                                })),
                            },
                            2 | 4 => Task {
                                data: Some(TaskUdp(Udp {
                                    destination_addresses: chunk.to_vec(),
                                })),
                            },
                            3 => Task {
                                data: Some(TaskTcp(Tcp {
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

                clients_finished.lock().unwrap().add_assign(1); // This client is 'finished'
                if clients_finished.lock().unwrap().clone() == number_of_clients {
                    print!("[Server] Measurement finished, awaiting clients... ");
                    // Send a message to the other sending threads to let them know the measurement is finished
                    tx_f.send(()).expect("Failed to send finished signal");
                } else {
                    // Wait for the last client to finish
                    rx_f.recv().await.expect("Failed to receive finished signal");

                    // If the CLI disconnects whilst waiting for the finished signal, abort
                    if *active.lock().unwrap() == false {
                        return // abort
                    }
                }

                // Sleep 10 seconds to give the client time to finish the task and receive the last responses (traceroute takes longer)
                if traceroute {
                    tokio::time::sleep(Duration::from_secs(120)).await;
                } else {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }

                // Send a message to the client to let it know it has received everything for the current task
                match sender.send(Ok(Task {
                    data: None,
                })).await {
                    Ok(_) => (),
                    Err(e) => println!("[Server] Failed to send 'termination message' {:?}", e),
                }
            });
        }

        let rx = CLIReceiver {
            inner: rx,
            active: self.active.clone(),
            senders: self.senders.clone(),
        };

        Ok(Response::new(rx))
    }
    /// Handle the list_clients command from the CLI.
    ///
    /// Returns the connected clients.
    async fn list_clients(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ClientList>, Status> {
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
        let task_result = request.into_inner();

        if *self.traceroute.lock().unwrap() {
            // Loop over the results and keep track of the clients that have received probe responses
            let client_id = task_result.client_id as u8;
            let mut map = self.traceroute_targets.lock().await;
            for result in task_result.clone().result_list {

                let value = result.value.unwrap();
                let (probed_address, anycast_address) = match value.clone() {
                    PingResult(value) => {
                        match value.ip_result.unwrap().value.unwrap() {
                            Ipv4(v4) => (IP::V4(Ipv4Addr::from(v4.source_address)), IP::V4(Ipv4Addr::from(v4.destination_address))),
                            Ipv6(v6) => (IP::V6(Ipv6Addr::from(((v6.source_address.clone().unwrap().p1 as u128) << 64) | v6.source_address.unwrap().p2 as u128)),
                                         IP::V6(Ipv6Addr::from(((v6.destination_address.clone().unwrap().p1 as u128) << 64) | v6.destination_address.unwrap().p2 as u128))),
                        }
                    },
                    UdpResult(value) => {
                        match value.ip_result.unwrap().value.unwrap() {
                            Ipv4(v4) => (IP::V4(Ipv4Addr::from(v4.source_address)), IP::V4(Ipv4Addr::from(v4.destination_address))),
                            Ipv6(v6) => (IP::V6(Ipv6Addr::from(((v6.source_address.clone().unwrap().p1 as u128) << 64) | v6.source_address.unwrap().p2 as u128)),
                                         IP::V6(Ipv6Addr::from(((v6.destination_address.clone().unwrap().p1 as u128) << 64) | v6.destination_address.unwrap().p2 as u128))),
                        }
                    },
                    TcpResult(value) => {
                        match value.ip_result.unwrap().value.unwrap() {
                            Ipv4(v4) => (IP::V4(Ipv4Addr::from(v4.source_address)), IP::V4(Ipv4Addr::from(v4.destination_address))),
                            Ipv6(v6) => (IP::V6(Ipv6Addr::from(((v6.source_address.clone().unwrap().p1 as u128) << 64) | v6.source_address.unwrap().p2 as u128)),
                                         IP::V6(Ipv6Addr::from(((v6.destination_address.clone().unwrap().p1 as u128) << 64) | v6.destination_address.unwrap().p2 as u128))),
                        }
                    },
                    _ => (IP::None, IP::None),
                };

                // Get port combination that the client received
                let (source_port, destination_port) = match value.clone() {
                    PingResult(_) => {
                        (0, 0)
                    },
                    UdpResult(value) => {
                        (value.source_port, value.destination_port)
                    },
                    TcpResult(value) => {
                        (value.source_port, value.destination_port)
                    },
                    _ => (0, 0)
                };

                // Create origin flows (i.e., a single flow for each client that has received probe replies)
                let origin_flow = Origin {
                    source_address: Some(Address::from(anycast_address)),
                    source_port,
                    destination_port,
                };
                // TODO we need to keep track of the flow per /24 (or /48 for ipv6)

                let ttl = match value {
                    PingResult(value) => {
                        value.ip_result.unwrap().ttl
                    },
                    UdpResult(value) => {
                        value.ip_result.unwrap().ttl
                    },
                    TcpResult(value) => {
                        value.ip_result.unwrap().ttl
                    },
                    _ => 0,
                } as u8;

                if probed_address == IP::None {
                    continue
                }
                if map.contains_key(&probed_address) {
                    let (clients, _, ttl_old, origins) = map.get_mut(&probed_address).unwrap();
                    // We want to keep track of the lowest TTL recorded
                    if ttl < ttl_old.clone() {
                        *ttl_old = ttl;
                    }
                    // Keep track of all clients that have received probe replies for this target
                    if !clients.contains(&client_id) {
                        clients.push(client_id);
                        origins.push(origin_flow); // First time we see this client receive a probe reply -> we add this origin flow for this client
                    }
                } else {
                    map.insert(probed_address, (vec![client_id], Instant::now(), ttl, vec![origin_flow]));
                }
            }
        }

        let tx = {
            let sender = self.cli_sender.lock().unwrap();
            sender.clone().unwrap()
        };

        match tx.send(Ok(task_result)).await {
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
        request: Request<Metadata>
    ) -> Result<Response<ClientId>, Status> {
        let metadata = request.into_inner();
        let hostname = metadata.hostname;
        let mut clients_list = self.clients.lock().unwrap();

        // Check if the hostname already exists
        for client in clients_list.clone().clients.into_iter() {
            if hostname == client.metadata.unwrap().hostname {
                println!("[Server] Refusing client as the hostname already exists: {}", hostname);
                return Err(Status::new(tonic::Code::AlreadyExists, "This hostname already exists"));
            }
        }

        // Obtain unique client id
        let client_id: u32;
        {
            let mut current_client_id = self.current_client_id.lock().unwrap();
            client_id = *current_client_id;
            current_client_id.add_assign(1);
        }

        // Add the client to the client list
        let new_client = Client {
            client_id,
            metadata: Some(Metadata {
                hostname: hostname.clone(),
                // origin: Some(Origin {
                //     source_address: Some(source_address),
                //     source_port,
                //     destination_port,
                // })
            }),
        };
        clients_list.clients.push(new_client);

        // Accept the client and give it a unique client ID
        Ok(Response::new(ClientId{
            client_id,
        }))
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

    // Get a random task ID
    let random_task_id = rand::thread_rng().gen_range(0..u32::MAX);

    let controller = ControllerService {
        clients: Arc::new(Mutex::new(ClientList::default())),
        senders: Arc::new(Mutex::new(Vec::new())),
        cli_sender: Arc::new(Mutex::new(None)),
        open_tasks: Arc::new(Mutex::new(HashMap::new())),
        current_task_id: Arc::new(Mutex::new(random_task_id)),
        current_client_id: Arc::new(Mutex::new(1)),
        active: Arc::new(Mutex::new(false)),
        traceroute_targets: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        traceroute: Arc::new(Mutex::new(false)),
    };

    let svc = ControllerServer::new(controller);

    // if TLS is enabled create the server using a TLS configuration
    if args.is_present("tls") {
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(load_tls())).expect("Failed to load TLS certificate")
            .add_service(svc)
            .serve(addr)
            .await?;
    } else {
        Server::builder()
            .add_service(svc)
            .serve(addr)
            .await?;
    }

    Ok(())
}

// 1. Generate private key:
// openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048
// 2. Generate certificate signing request:
// openssl req -new -key server.key -out server.csr
// 3. Generate self-signed certificate:
// openssl x509 -req -in server.csr -signkey server.key -out server.crt -days 3650
// 4. Distribute server.crt to clients
fn load_tls() -> Identity {
    // Load TLS certificate
    let cert = fs::read("tls/server.crt").expect("Unable to read certificate file at ./tls/server.crt");
    // Load TLS private key
    let key = fs::read("tls/server.key").expect("Unable to read key file at ./tls/server.key");

    // Create TLS configuration
    let identity = Identity::from_pem(cert, key);

    identity
}

