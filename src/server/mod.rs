use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::{Add, AddAssign};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use clap::ArgMatches;
use futures_core::Stream;
use local_ip_address::local_ip;
use pcap::{Capture, Device};
use rand::Rng;
use tokio::spawn;
use tokio::sync::broadcast::Receiver;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status, transport::Server};
use tonic::transport::{Identity, ServerTlsConfig};

use custom_module::IP;
use custom_module::verfploeter::{
    Ack, Address, Client, ClientId, ClientList, controller_server::Controller, controller_server::ControllerServer, Empty,
    End, Finished, ip_result::Value::Ipv4,
    ip_result::Value::Ipv6, Metadata, Origin, ScheduleMeasurement, Start,
    Targets, Task, task::Data::End as TaskEnd, task::Data::Start as TaskStart, task::Data::Trace as TaskTrace,
    TaskResult, Trace, verfploeter_result::Value::Ping as PingResult, verfploeter_result::Value::Tcp as TcpResult, verfploeter_result::Value::Udp as UdpResult,
};

use crate::custom_module;
use crate::net::packet::{create_ping, create_tcp, create_udp, get_ethernet_header};
use crate::server::mpsc::Sender;

/// Struct for the Server service
///
/// # Fields
///
/// * 'clients' - a ClientList that contains all connected clients (hostname and client ID)
/// * 'senders' - a list of senders that connect to the clients, these senders are used to stream Tasks
/// * 'cli_sender' - the sender that connects to the CLI, to stream TaskResults
/// * 'open_measurements' - a list of the current open measurements, and the number of clients that are currently working on it
/// * 'current_measurement_id' - keeps track of the last used measurement ID
/// * 'current_client_id' - keeps track of the last used client ID and is used to assign a unique client ID to a new connecting client
/// * 'active' - a boolean value that is set to true when there is an active measurement
/// * 'traceroute_targets' - a map that keeps track of the clients that have received probe replies for a specific target, and the 'flows' that reach each client
/// * 'traceroute' - a boolean value that is set to true when traceroute measurements are being performed
/// * 'responsive' - a boolean value that is set to true when responsive targets are being measured
/// * 'responsive_targets' - a list of the responsive targets that need to be measured
#[derive(Debug, Clone)]
pub struct ControllerService {
    clients: Arc<Mutex<ClientList>>,
    senders: Arc<Mutex<Vec<Sender<Result<Task, Status>>>>>,
    cli_sender: Arc<Mutex<Option<Sender<Result<TaskResult, Status>>>>>,
    open_measurements: Arc<Mutex<HashMap<u32, u32>>>,
    current_measurement_id: Arc<Mutex<u32>>,
    current_client_id: Arc<Mutex<u32>>,
    active: Arc<Mutex<bool>>,
    traceroute_targets: Arc<tokio::sync::Mutex<HashMap<IP, (Vec<u8>, Instant, u8, Vec<Origin>)>>>, // IP -> (clients, timestamp, ttl, flows)
    traceroute: Arc<Mutex<bool>>,
    responsive_targets: Arc<Mutex<Vec<Address>>>,
}

/// Special Receiver struct that notices when the client disconnects.
///
/// When a client drops we update the open_measurements such that the server knows this client is not participating in any measurements.
/// Furthermore, we send a message to the CLI if it is currently performing a measurement, to let it know this client is finished.
///
/// Finally, remove this client from the client list.
///
/// # Fields
///
/// * 'inner' - the receiver that connects to the client
/// * 'open_measurements' - a list of the current open measurements, and the number of clients that are currently working on it
/// * 'cli_sender' - the sender that connects to the CLI
/// * 'hostname' - the hostname of the client
/// * 'clients' - a ClientList that contains all connected clients (hostname and client ID)
/// * 'active' - a boolean value that is set to true when there is an active measurement
pub struct ClientReceiver<T> {
    inner: mpsc::Receiver<T>,
    open_measurements: Arc<Mutex<HashMap<u32, u32>>>,
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
        self.clients.lock().unwrap().clients.retain(|client| {
            let Some(metadata) = &client.metadata else { panic!("Client without metadata") };
            metadata.hostname != self.hostname
        });

        // // Handle the open measurements that involve this client
        let mut open_measurements = self.open_measurements.lock().unwrap();
        if open_measurements.len() > 0 {
            for (measurement_id, remaining) in open_measurements.clone().iter() {
                // If this measurement is already finished
                if remaining == &0 {
                    continue;
                }
                // If this is the last client for this open measurement
                if remaining == &1 {
                    // The server no longer has to wait for this client
                    open_measurements.remove(&measurement_id);

                    println!("[Server] The last client for a measurement dropped, sending measurement finished signal to CLI");
                    *self.active.lock().unwrap() = false;
                    match self.cli_sender.lock().unwrap().clone().unwrap().try_send(Ok(TaskResult::default())) {
                        Ok(_) => (),
                        Err(_) => println!("[Server] Failed to send measurement finished signal to CLI")
                    }
                } else { // If there are more clients still performing this measurement
                    // The server no longer has to wait for this client
                    *open_measurements.get_mut(&measurement_id).unwrap() -= 1;
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
/// * 'active' - a boolean value that is set to true when there is an active measurement
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

        // If there is an active measurement we need to cancel it and notify the clients
        if *active {
            println!("[Server] CLI dropped during an active measurement, terminating measurement");

            // Create termination 'task'
            let end_task = Task {
                data: Some(TaskEnd(End {
                    code: 0,
                })),
            };

            // Tell each client to terminate the measurement
            for client in self.senders.lock().unwrap().iter().cloned() {
                let end_task = end_task.clone();

                spawn(async move {
                    if let Err(e) = client.send(Ok(end_task)).await {
                        println!("[Server] ERROR - Failed to terminate measurement {}", e);
                    }
                });
            }
            println!("[Server] Terminated the current measurement at all clients");

            *active = false; // No longer an active measurement
        }
    }
}


/// Implementation of the Controller trait for the ControllerService
/// Handles communication with the clients and the CLI
#[tonic::async_trait]
impl Controller for ControllerService {
    /// Called by the client when it has finished its current measurement.
    ///
    /// When all connected clients have finished this measurement, it will notify the CLI that the measurement is finished.
    ///
    /// # Arguments
    ///
    /// * 'request' - a Finished message containing the measurement ID of the measurement that has finished
    ///
    /// # Errors
    ///
    /// Returns an error if the measurement ID is unknown.
    async fn measurement_finished(
        &self,
        request: Request<Finished>,
    ) -> Result<Response<Ack>, Status> {
        let finished_measurement = request.into_inner();
        let measurement_id: u32 = finished_measurement.measurement_id;
        let tx = self.cli_sender.lock().unwrap().clone().unwrap();

        // Wait till we have received 'measurement_finished' from all clients that executed this measurement
        let is_finished = {
            let mut open_measurements = self.open_measurements.lock().unwrap();

            // Number of clients that still have to finish this measurement
            let remaining = if let Some(remaining) = open_measurements.get(&measurement_id) {
                remaining
            } else {
                println!("[Server] Received measurement finished signal for non-existent measurement {}", &measurement_id);
                return Ok(Response::new(Ack {
                    success: false,
                    error_message: "Measurement unknown".to_string(),
                }));
            };
            if remaining == &(1u32) { // If this is the last client we are finished
                println!("{}", finished_measurement.client_id);
                println!("[Server] All clients finished");

                open_measurements.remove(&measurement_id);
                true // Finished
            } else { // If this is not the last client, decrement the amount of remaining clients
                print!("{},", finished_measurement.client_id);
                *open_measurements.get_mut(&measurement_id).unwrap() -= 1;
                false // Not finished yet
            }
        };
        if is_finished {
            println!("[Server] Notifying CLI that the measurement is finished");
            // There is no longer an active measurement
            *self.active.lock().unwrap() = false;

            // Send an ack to the client that it has finished
            return match tx.send(Ok(TaskResult::default())).await {
                Ok(_) => Ok(Response::new(Ack {
                    success: true,
                    error_message: "".to_string(),
                })),
                Err(_) => Ok(Response::new(Ack {
                    success: false,
                    error_message: "CLI disconnected".to_string(),
                })),
            };
        } else {
            // Send an ack to the client that it has finished
            Ok(Response::new(Ack {
                success: true,
                error_message: "".to_string(),
            }))
        }
    }

    type ClientConnectStream = ClientReceiver<Result<Task, Status>>;

    /// Handles a client connecting to this server formally.
    ///
    /// Returns the receiver side of a stream to which the server will send tasks
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
        self.senders.lock().unwrap().push(tx);

        // Create stream receiver for the client
        let client_rx = ClientReceiver {
            inner: rx,
            open_measurements: self.open_measurements.clone(),
            cli_sender: self.cli_sender.clone(),
            hostname: hostname.clone(),
            clients: self.clients.clone(),
            active: self.active.clone(),
        };

        // Send the stream receiver to the client
        Ok(Response::new(client_rx))
    }
    type DoMeasurementStream = CLIReceiver<Result<TaskResult, Status>>;

    /// Handles the do_measurement command from the CLI.
    ///
    /// Instructs all clients to perform the measurement and returns the receiver side of a stream in which TaskResults will be streamed.
    ///
    /// Will lock active to true, such that no other measurement can start.
    ///
    /// Makes sure all clients are still connected, removes their senders if not.
    ///
    /// Assigns a unique ID to the measurement.
    ///
    /// Streams tasks to the clients, in a round-robin fashion, with 1-second delays between clients.
    ///
    /// Furthermore, lets the clients know of the desired probing rate (defined by the CLI).
    ///
    /// # Arguments
    ///
    /// * 'request' - a ScheduleMeasurement message containing information about the measurement that the CLI wants to perform
    ///
    /// # Errors
    ///
    /// Returns an error if there is already an active measurement, or if there are no connected clients to perform the measurement.
    async fn do_measurement(
        &self,
        request: Request<ScheduleMeasurement>,
    ) -> Result<Response<Self::DoMeasurementStream>, Status> {
        println!("[Server] Received CLI measurement request for measurement");

        // If there already is an active measurement, we skip
        {
            // If the server is already working on another measurement
            let mut active = self.active.lock().unwrap();
            if *active {
                println!("[Server] There is already an active measurement, returning");
                return Err(Status::new(tonic::Code::Cancelled, "There is already an active measurement"));
            }

            // For every open measurement
            for (_, open) in self.open_measurements.lock().expect("No open measurements map").iter() {
                // If there are still clients who are working on a different measurement
                if open > &0 {
                    println!("[Server] There is already an active measurement, returning");
                    return Err(Status::new(tonic::Code::Cancelled, "There are still clients working on an active measurement"));
                }
            }

            *active = true;
        }

        // Get the list of Senders (that connect to the clients)
        let senders = {
            // Lock the senders mutex and remove closed senders
            self.senders.lock().unwrap().retain(|sender| {
                if sender.is_closed() {
                    println!("[Server] Client unavailable, connection closed. Client removed.");
                    false
                } else {
                    true
                }
            });
            self.senders.lock().unwrap().clone()
        };

        // If there are no connected clients that can perform this measurement
        if senders.len() == 0 {
            println!("[Server] No connected clients, terminating measurement.");
            *self.active.lock().unwrap() = false;
            return Err(Status::new(tonic::Code::Cancelled, "No connected clients"));
        }

        // Assign a unique ID the measurement and increment the measurement ID counter
        let measurement_id = {
            let mut current_measurement_id = self.current_measurement_id.lock().unwrap();
            let id = *current_measurement_id;
            *current_measurement_id = current_measurement_id.wrapping_add(1);
            id
        };

        // The measurement that the CLI wants to perform
        let scheduled_measurement = request.into_inner();
        // Create a list of the connected clients' IDs
        let client_list_u32: Vec<u32> = self.clients.lock().unwrap().clients
            .iter()
            .map(|client| client.client_id)
            .collect();

        // Check if the CLI requested a client-selective probing measurement
        let mut selected_clients: Vec<u32> = scheduled_measurement.clients;

        // Make sure all client IDs are valid
        if selected_clients.iter().any(|client| !client_list_u32.contains(client)) {
            println!("[Server] Client ID requested that is not connected, terminating measurement.");
            *self.active.lock().unwrap() = false;
            return Err(Status::new(tonic::Code::Cancelled, "One or more client IDs are not connected."));
        }

        // Create a measurement from the ScheduleMeasurement
        let is_unicast = scheduled_measurement.unicast;
        // Get the probe origins
        let tx_origins: Vec<Origin> = if is_unicast {
            vec![scheduled_measurement.origin.clone().unwrap()] // Contains port values
        } else if scheduled_measurement.configurations.len() > 0 {
            // Make sure no unknown clients are in the list
            if scheduled_measurement.configurations.iter().any(|conf| !client_list_u32.contains(&conf.client_id) && conf.client_id != u32::MAX) {
                println!("[Server] Unknown client in configuration list, terminating measurement.");
                *self.active.lock().unwrap() = false;
                return Err(Status::new(tonic::Code::Cancelled, "Unknown client in configuration list"));
            }
            // Update selected_clients to contain all clients that are in the configuration list
            for configuration in &scheduled_measurement.configurations {
                if !selected_clients.contains(&configuration.client_id) {
                    selected_clients.push(configuration.client_id);
                }
                // All clients are selected
                if configuration.client_id == u32::MAX {
                    selected_clients = vec![];
                    break;
                }
            }

            vec![]  // Return an empty list, as we will add the origins per client
        } else {
            vec![scheduled_measurement.origin.clone().unwrap()]
        };

        // Store the number of clients that will perform this measurement
        self.open_measurements.lock().unwrap().insert(measurement_id, senders.len() as u32);

        let rate = scheduled_measurement.rate;
        let measurement_type = scheduled_measurement.measurement_type;
        let is_ipv6 = scheduled_measurement.ipv6;
        let is_traceroute = scheduled_measurement.traceroute;
        let is_divide = scheduled_measurement.divide;
        let inter_client_interval = scheduled_measurement.interval as u64;
        *self.traceroute.lock().unwrap() = is_traceroute;
        let dst_addresses = scheduled_measurement.targets.expect("Received measurement with no targets").dst_addresses;
        let responsive = scheduled_measurement.responsive;

        // Establish a stream with the CLI to return the TaskResults through
        let (tx, rx) = mpsc::channel::<Result<TaskResult, Status>>(1000);
        // Store the CLI sender
        let _ = self.cli_sender.lock().unwrap().insert(tx);

        // Create a list of origins used by clients
        let mut rx_origins = tx_origins.clone();
        // Add all configuration origins to the listen origins
        for configuration in &scheduled_measurement.configurations {
            if let Some(origin) = &configuration.origin {
                // Avoid duplicate origins
                if !rx_origins.contains(origin) {
                    rx_origins.push(origin.clone());
                }
            }
        }

        // If traceroute is enabled, start a thread that handles when and how the clients should perform traceroute
        if is_traceroute {
            traceroute_orchestrator(self.traceroute_targets.clone(), self.senders.clone()).await;
        }

        // Notify all senders that a new measurement is starting
        let mut current_client = 0;
        let mut current_active_client = 0;
        let chaos = scheduled_measurement.chaos.clone();
        for sender in senders.iter() {
            let mut client_tx_origins = tx_origins.clone();
            // Add all configuration probing origins assigned to this client
            for configuration in &scheduled_measurement.configurations {
                // If the client is selected to perform the measurement (or all clients are selected (u32::MAX))
                if (configuration.client_id == *client_list_u32.get(current_client).unwrap()) | (configuration.client_id == u32::MAX) {
                    if let Some(origin) = &configuration.origin {
                        // Avoid duplicate origins
                        if !client_tx_origins.contains(origin) {
                            client_tx_origins.push(origin.clone());
                        }
                    }
                }
            }

            // Check if the current client is selected to send probes
            let is_probing = if selected_clients.is_empty() {
                // No client-selective probing
                if client_tx_origins.len() == 0 {
                    false // No probe origins -> not probing
                } else {
                    true
                }
            } else {
                // Make sure the current client is selected to perform the measurement
                selected_clients.contains(client_list_u32.get(current_client).expect(&*format!("Client with ID {} not found", current_client)))
            };
            if is_probing { current_active_client += 1; }
            current_client = current_client + 1;

            let start_task = Task {
                data: Some(TaskStart(Start {
                    rate,
                    measurement_id,
                    active: is_probing,
                    measurement_type,
                    unicast: is_unicast,
                    ipv6: is_ipv6,
                    traceroute: is_traceroute,
                    tx_origins: client_tx_origins.clone(),
                    rx_origins: rx_origins.clone(),
                    chaos: chaos.to_string(),
                }))
            };

            match sender.try_send(Ok(start_task.clone())) {
                Ok(_) => (),
                Err(e) => println!("[Server] Failed to send 'start measurement' {:?}", e),
            }
        }

        // Number of clients participating in the measurement (listening and/or probing)
        let number_of_clients = senders.len() as u64;

        if !is_divide {
            println!("[Server] {} clients will listen for probe replies, {} clients will send out probes to the same target {} seconds after each other", number_of_clients, current_active_client, inter_client_interval);
        } else {
            println!("[Server] {} clients will listen for probe replies, {} client will send out probes to a different chunk of the destination addresses", number_of_clients, current_active_client);
        }

        // Shared variable to keep track of the number of clients that have finished
        let clients_finished = Arc::new(Mutex::new(0));
        // Shared channel that clients will wait for till the last client has finished
        let (tx_f, _) = tokio::sync::broadcast::channel::<()>(1);
        let mut active_client_i: u64 = 0; // Index for active clients
        let mut all_client_i = 0; // Index for the client list
        let chunk_size: usize = 10; // TODO try increasing chunk size to reduce overhead
        let p_rate = Duration::from_nanos(((1.0 / rate as f64) * chunk_size as f64 * 1_000_000_000.0) as u64);

        if responsive {
            // Finished signal channel
            let (tx_f, rx_f) = tokio::sync::broadcast::channel::<()>(1);

            println!("Probing for responsive targets from server...");
            let responsive_targets = self.responsive_targets.clone();
            spawn(async move { // thread probing for responsiveness
                let mut interval = tokio::time::interval(p_rate);
                let server_origin = Origin {
                    src: Some(Address::from(IP::from(local_ip().expect("Failed to get local IP").to_string()))),
                    sport: 65535, // TODO ports from task
                    dport: 62321,
                };

                // Group hitlist targets by prefix
                let prefix_targets: HashMap<u64, Vec<Address>> = dst_addresses.iter()
                    .fold(HashMap::new(), |mut acc, target| {
                        let prefix = target.get_prefix();
                        acc.entry(prefix).or_insert_with(Vec::new).push(target.clone());
                        acc
                    });

                // Probe each prefix to find a responsive target
                for chunk in prefix_targets.values() {
                    let chunk = chunk.clone();
                    let server_origin = server_origin.clone();
                    let chaos = chaos.clone();
                    let responsive_targets = responsive_targets.clone();
                    spawn(async move {
                        // Get the responsive address for this chunk
                        let responsive_addr = probe_targets(is_ipv6, chunk, measurement_type as u8, server_origin, chaos).await;
                        if let Some(addr) = responsive_addr {
                            // Add the responsive target to the list (if we found one)
                            responsive_targets.lock().unwrap().push(addr);
                        }
                    });

                    interval.tick().await; // rate limit
                }

                // TODO wait till responsive targets is empty (i.e., all targets have been probed)
                // TODO send finished signal to send_responsive

                loop {
                    if responsive_targets.lock().unwrap().len() == 0 {
                        break;
                    } else {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }

                // Send a message to the other sending threads to let them know the measurement is finished
                tx_f.send(()).expect("Failed to send finished signal");

            });

            println!("instructing clients to probe responsive targets...");
            send_responsive(senders, self.responsive_targets.clone(), inter_client_interval, rx_f).await; // TODO instruct clients to probe responsive targets
            println!("clients finished");

        } else {
            // Create a thread that streams tasks for each client
            for sender in senders.iter() {
                let sender = sender.clone();
                // This client's unique ID
                let client_id = *client_list_u32.get(all_client_i as usize).unwrap();
                all_client_i += 1;
                let clients = selected_clients.clone();
                // If clients is empty, all clients are probing, otherwise only the clients in the list are probing
                let is_probing = clients.len() == 0 || clients.contains(&client_id);

                // Get the hitlist for this client
                let hitlist_targets = if !is_probing {
                    vec![]
                } else if is_divide {
                    // Each client gets its own chunk of the hitlist
                    let targets_chunk = dst_addresses.len() / current_active_client as usize;

                    // Get start and end index of targets to probe for this client
                    let start_index = active_client_i as usize * targets_chunk;
                    let end_index = if active_client_i == current_active_client - 1 {
                        dst_addresses.len() // End of the list
                    } else {
                        start_index + targets_chunk
                    };

                    dst_addresses[start_index..end_index].to_vec()
                } else {
                    // All clients get the same hitlist
                    dst_addresses.clone()
                };

                // increment if this client is sending probes
                if is_probing { active_client_i += 1; }

                let tx_f = tx_f.clone();
                let mut rx_f = tx_f.subscribe();
                let clients_finished = clients_finished.clone();
                let is_active = self.active.clone();

                spawn(async move {
                    // Send out packets at the required interval
                    let mut interval = tokio::time::interval(p_rate);
                    // Synchronize clients probing by sleeping for a certain amount of time (ensures clients send out probes to the same target 1 second after each other)
                    if is_probing && !is_divide {
                        tokio::time::sleep(Duration::from_secs((active_client_i - 1) * inter_client_interval)).await;
                    }

                    for chunk in hitlist_targets.chunks(chunk_size) {
                        // If the CLI disconnects during task distribution, abort
                        if *is_active.lock().unwrap() == false {
                            clients_finished.lock().unwrap().add_assign(1); // This client is 'finished'
                            if clients_finished.lock().unwrap().clone() == number_of_clients {
                                println!("[Server] CLI disconnected during task distribution");
                                tx_f.send(()).expect("Failed to send finished signal");
                            }
                            return; // abort
                        }

                        if is_probing {
                            let task = Task {
                                data: Some(custom_module::verfploeter::task::Data::Targets(Targets {
                                    dst_addresses: chunk.to_vec(),
                                })),
                            };

                            // Send packet to client
                            match sender.send(Ok(task)).await {
                                Ok(_) => (),
                                Err(e) => {
                                    println!("[Server] Failed to send task {:?} to client {}", e, client_id);
                                    if sender.is_closed() { // If the client is no longer connected
                                        println!("[Server] Client {} is no longer connected and removed from the measurement", client_id);
                                        break;
                                    }
                                }
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
                        if *is_active.lock().unwrap() == false {
                            return; // abort
                        }
                    }

                    // Sleep 1 second to give the client time to finish the measurement and receive the last responses (traceroute takes longer)
                    if is_traceroute {
                        tokio::time::sleep(Duration::from_secs(120)).await; // TODO make this dynamic
                    } else {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }

                    // Send a message to the client to let it know it has received everything for the current measurement
                    match sender.send(Ok(Task {
                        data: Some(TaskEnd(End {
                            code: 0,
                        })),
                    })).await {
                        Ok(_) => (),
                        Err(e) => println!("[Server] Failed to send 'end message' {:?} to client {}", e, client_id),
                    }
                });
            }
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
    /// # Arguments
    ///
    /// * 'request' - a TaskResult message containing the results of a task
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

        if *self.traceroute.lock().unwrap() { // If traceroute is enabled
            // Loop over the results and keep track of the clients that have received probe responses
            let client_id = task_result.client_id as u8;
            let mut map = self.traceroute_targets.lock().await;
            for result in task_result.clone().result_list {
                let value = result.value.unwrap();
                let (probe_dst, probe_src) = match value.clone() {
                    PingResult(value) => {
                        match value.ip_result.unwrap().value.unwrap() {
                            Ipv4(v4) => (IP::V4(Ipv4Addr::from(v4.src)), IP::V4(Ipv4Addr::from(v4.dst))),
                            Ipv6(v6) => (IP::V6(Ipv6Addr::from(((v6.src.clone().unwrap().p1 as u128) << 64) | v6.src.unwrap().p2 as u128)),
                                         IP::V6(Ipv6Addr::from(((v6.dst.clone().unwrap().p1 as u128) << 64) | v6.dst.unwrap().p2 as u128))),
                        }
                    }
                    UdpResult(value) => {
                        match value.ip_result.unwrap().value.unwrap() {
                            Ipv4(v4) => (IP::V4(Ipv4Addr::from(v4.src)), IP::V4(Ipv4Addr::from(v4.dst))),
                            Ipv6(v6) => (IP::V6(Ipv6Addr::from(((v6.src.clone().unwrap().p1 as u128) << 64) | v6.src.unwrap().p2 as u128)),
                                         IP::V6(Ipv6Addr::from(((v6.dst.clone().unwrap().p1 as u128) << 64) | v6.dst.unwrap().p2 as u128))),
                        }
                    }
                    TcpResult(value) => {
                        match value.ip_result.unwrap().value.unwrap() {
                            Ipv4(v4) => (IP::V4(Ipv4Addr::from(v4.src)), IP::V4(Ipv4Addr::from(v4.dst))),
                            Ipv6(v6) => (IP::V6(Ipv6Addr::from(((v6.src.clone().unwrap().p1 as u128) << 64) | v6.src.unwrap().p2 as u128)),
                                         IP::V6(Ipv6Addr::from(((v6.dst.clone().unwrap().p1 as u128) << 64) | v6.dst.unwrap().p2 as u128))),
                        }
                    }
                    _ => (IP::None, IP::None),
                };

                // Get port combination that the client received
                let (probe_sport, probe_dport) = match value.clone() {
                    PingResult(_) => {
                        (0, 0)
                    }
                    UdpResult(value) => {
                        (value.sport, value.dport)
                    }
                    TcpResult(value) => {
                        (value.sport, value.dport)
                    }
                    _ => (0, 0)
                };

                // Create origin flows (i.e., a single flow for each client that has received probe replies)
                let origin_flow = Origin {
                    src: Some(Address::from(probe_src)),
                    sport: probe_sport,
                    dport: probe_dport,
                };

                let ttl = match value {
                    PingResult(value) => {
                        value.ip_result.unwrap().ttl
                    }
                    UdpResult(value) => {
                        value.ip_result.unwrap().ttl
                    }
                    TcpResult(value) => {
                        value.ip_result.unwrap().ttl
                    }
                    _ => 0,
                } as u8;

                if probe_dst == IP::None {
                    continue;
                }
                if map.contains_key(&probe_dst) {
                    let (clients, _, ttl_old, origins) = map.get_mut(&probe_dst).unwrap();
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
                    map.insert(probe_dst, (vec![client_id], Instant::now(), ttl, vec![origin_flow]));
                }
            }
        }

        // Forward the result to the CLI
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
        request: Request<Metadata>,
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
        let client_id = {
            let mut current_client_id = self.current_client_id.lock().unwrap();
            let client_id = *current_client_id;
            current_client_id.add_assign(1);
            client_id
        };

        // Add the client to the client list
        let new_client = Client {
            client_id,
            metadata: Some(Metadata {
                hostname: hostname.clone(),
            }),
        };
        clients_list.clients.push(new_client);

        // Accept the client and give it a unique client ID
        Ok(Response::new(ClientId {
            client_id,
        }))
    }
}

/// Start a thread that orchestrates the traceroute measurements.
///
/// This thread will instruct the clients to perform traceroute measurements to targets that sent probe replies toward multiple clients.
///
/// # Arguments
///
/// * 'targets' - a shared hashmap that contains the targets that have sent probe replies to multiple clients
///
/// * 'senders' - a shared list of senders that connect to the clients
async fn traceroute_orchestrator(
    targets: Arc<tokio::sync::Mutex<HashMap<IP, (Vec<u8>, Instant, u8, Vec<Origin>)>>>,
    senders: Arc<Mutex<Vec<Sender<Result<Task, Status>>>>>)
{
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
                        dst: Some(Address::from(target.clone())),
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

/// Start the server.
///
/// Starts the server on the specified port.
///
/// # Arguments
///
/// * 'args' - the parsed command-line arguments
pub async fn start(args: &ArgMatches<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let port = args.value_of("port").expect("No port specified");
    let addr: SocketAddr = "[::]:".to_string().add(port).parse().unwrap();

    // Get a random measurement ID to start with
    let measurement_id = rand::thread_rng().gen_range(0..u32::MAX);

    let controller = ControllerService {
        clients: Arc::new(Mutex::new(ClientList::default())),
        senders: Arc::new(Mutex::new(Vec::new())),
        cli_sender: Arc::new(Mutex::new(None)),
        open_measurements: Arc::new(Mutex::new(HashMap::new())),
        current_measurement_id: Arc::new(Mutex::new(measurement_id)),
        current_client_id: Arc::new(Mutex::new(1)),
        active: Arc::new(Mutex::new(false)),
        traceroute_targets: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        traceroute: Arc::new(Mutex::new(false)),
        responsive_targets: Arc::new(Mutex::new(Vec::new())),
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

/// Probe a set of targets to find a responsive target.
///
/// Probing is done sequentially, with a 1-second delay between each target.
///
/// If a target is responsive, we stop probing and return the target.
async fn probe_targets(
    is_ipv6: bool,
    targets: Vec<Address>,
    measurement_type: u8,
    source: Origin,
    chaos: String,
) -> Option<Address> {
    // Get capture interface
    let ethernet_header = get_ethernet_header(is_ipv6);
    let main_interface = Device::lookup().expect("Failed to get main interface").unwrap();
    let mut cap = Capture::from_device(main_interface).expect("Failed to get capture device")
        .immediate_mode(true)
        .buffer_size(100_000_000) // TODO set buffer size based on probing rate (default 1,000,000) (this sacrifices memory for performance (at 21% currently))
        .open().expect("Failed to open capture device").setnonblock().expect("Failed to set pcap to non-blocking mode");
    cap.direction(pcap::Direction::In).expect("Failed to set pcap direction"); // We only want to receive incoming packets

   for target in targets {
       // Get filter
       let filter = if is_ipv6 {
           if measurement_type == 1 {
               format!("src host {} and icmp6", target)
           } else if measurement_type == 2 | 4 {
               format!("src host {} and ip6[6] == 17", target)
           } else {
               format!("src host {} and ip6[6] == 6", target)
           }
       } else {
            if measurement_type == 1 {
                 format!("src host {} and icmp", target)
            } else if measurement_type == 2 | 4 {
                 format!("src host {} and udp", target)
            } else {
                 format!("src host {} and tcp", target)
            }
       };
       cap.filter(&*filter, true).expect("Failed to set pcap filter");

       let mut packet = ethernet_header.clone();
       match measurement_type {
           1 => {
               packet.extend_from_slice(&create_ping(
                   source.clone(),
                   IP::from(target.clone()),
                   0,
                   0,
               ));
           },
            2 | 4 => {
                 packet.extend_from_slice(&create_udp(
                      source.clone(),
                      IP::from(target.clone()),
                      0,
                      measurement_type,
                      is_ipv6,
                      chaos.clone(),
                 ));
            },
           3 => {
               packet.extend_from_slice(&create_tcp(
                   source.clone(),
                   IP::from(target.clone()),
                   0,
                   is_ipv6,
                   true,
               ));
           },
            _ => {
                 panic!("Invalid measurement type");
            }
       }

       cap.sendpacket(packet).expect("Failed to send packet");
       tokio::time::sleep(Duration::from_secs(1)).await;

       // Check if we have received a response
       if let Ok(_) = cap.next_packet() {
            return Some(target.clone());
       }
   }
    return None; // No responsive target found
}

/// Instruct the clients to probe responsive targets.
///
/// Awaits responsive targets and instructs the clients to probe them.
///
/// Clients will be instructed to probe the responsive targets in a round-robin fashion, with the configured delay between each client.
///
/// # Arguments
///
/// * 'senders' - a list of senders that connect to the clients
///
/// # Returns
///
/// A result containing channel senders for each client.
async fn send_responsive(
    senders: Vec<Sender<Result<Task, Status>>>,
    responsive_targets: Arc<Mutex<Vec<Address>>>,
    client_interval: u64,
    mut rx_f: Receiver<()>,
) {
    // Create thread awaiting responsive targets and sending them to the clients
    loop {
        // Wait for responsive targets
        loop {
            if !responsive_targets.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;

            // Check if the server has finished probing for responsive targets
            if rx_f.try_recv().is_ok() {
                return;
            }
        }

        // Pop up to 10 targets from the list
        let targets: Vec<Address> = {
            let mut all_targets = responsive_targets.lock().unwrap();
            let n = std::cmp::min(10, all_targets.len());

            all_targets.drain(..n).collect()
        };

        // Send to client with 'client_interval' gaps
        let senders = senders.clone();
        spawn(async move {
            let targets = targets.clone();
            let task = Task {
                data: Some(custom_module::verfploeter::task::Data::Targets(Targets {
                    dst_addresses: targets,
                })),
            };

            for sender in senders.iter() {
                // Send packet to client
                match sender.send(Ok(task.clone())).await {
                    Ok(_) => (),
                    Err(e) => {
                        println!("[Server] Failed to send task {:?} to client", e);
                        if sender.is_closed() { // If the client is no longer connected
                            println!("[Server] Client is no longer connected and removed from the measurement");
                            continue;
                        }
                    }
                }
            }
        });

        // Sleep for the client interval
        tokio::time::sleep(Duration::from_secs(client_interval)).await;
    }
}


