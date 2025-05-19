use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::ops::AddAssign;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::custom_module;
use crate::orchestrator::mpsc::Sender;
use clap::ArgMatches;
use custom_module::manycastr::{
    controller_server::Controller, controller_server::ControllerServer, task::Data::End as TaskEnd,
    task::Data::Start as TaskStart, Ack, Empty, End, Finished, Metadata, ScheduleMeasurement,
    Start, Status as ServerStatus, Targets, Task, TaskResult, Worker, WorkerId,
};
use futures_core::Stream;
use rand::Rng;
use tokio::spawn;
use tokio::sync::mpsc;
use tonic::codec::CompressionEncoding;
use tonic::transport::{Identity, ServerTlsConfig};
use tonic::{transport::Server, Request, Response, Status};

/// Struct for the orchestrator service
///
/// # Fields
///
/// * 'workers' - a WorkerList that contains all connected workers (hostname and worker ID)
/// * 'senders' - a list of senders that connect to the workers, these senders are used to stream Tasks
/// * 'cli_sender' - the sender that connects to the CLI, to stream TaskResults
/// * 'open_measurements' - a list of the current open measurements, and the number of clients that are currently working on it
/// * 'current_measurement_id' - keeps track of the last used measurement ID
/// * 'current_worker_id' - keeps track of the last used worker ID and is used to assign a unique worker ID to a new connecting worker
/// * 'active' - a boolean value that is set to true when there is an active measurement
#[derive(Debug, Clone)]
pub struct ControllerService {
    workers: Arc<Mutex<ServerStatus>>,
    senders: Arc<Mutex<Vec<Sender<Result<Task, Status>>>>>,
    cli_sender: Arc<Mutex<Option<Sender<Result<TaskResult, Status>>>>>,
    open_measurements: Arc<Mutex<HashMap<u32, u32>>>,
    current_measurement_id: Arc<Mutex<u32>>,
    current_worker_id: Arc<Mutex<u32>>,
    active: Arc<Mutex<bool>>,
}

/// Special Receiver struct that notices when the worker disconnects.
///
/// When a worker drops we update the open_measurements such that the orchestrator knows this worker is not participating in any measurements.
/// Furthermore, we send a message to the CLI if it is currently performing a measurement, to let it know this worker is finished.
///
/// Finally, remove this worker from the worker list.
///
/// # Fields
///
/// * 'inner' - the receiver that connects to the worker
/// * 'open_measurements' - a list of the current open measurements, and the number of workers that are currently working on it
/// * 'cli_sender' - the sender that connects to the CLI
/// * 'hostname' - the hostname of the worker
/// * 'workers' - a WorkerList that contains all connected workers (hostname and worker ID)
/// * 'active' - a boolean value that is set to true when there is an active measurement
pub struct WorkerReceiver<T> {
    inner: mpsc::Receiver<T>,
    open_measurements: Arc<Mutex<HashMap<u32, u32>>>,
    cli_sender: Arc<Mutex<Option<Sender<Result<TaskResult, Status>>>>>,
    hostname: String,
    workers: Arc<Mutex<ServerStatus>>,
    active: Arc<Mutex<bool>>,
}

impl<T> Stream for WorkerReceiver<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.inner.poll_recv(cx)
    }
}

impl<T> Drop for WorkerReceiver<T> {
    fn drop(&mut self) {
        println!("[Orchestrator] Worker {} lost connection", self.hostname);

        // Remove this worker from the workers list
        {
            self.workers.lock().unwrap().workers.retain(|workers| {
                let Some(metadata) = &workers.metadata else {
                    panic!("Worker without metadata")
                };
                metadata.hostname != self.hostname
            });
        }

        // // Handle the open measurements that involve this worker
        let mut open_measurements = self.open_measurements.lock().unwrap();
        if !open_measurements.is_empty() {
            for (measurement_id, remaining) in open_measurements.clone().iter() {
                // If this measurement is already finished
                if remaining == &0 {
                    continue;
                }
                // If this is the last worker for this open measurement
                if remaining == &1 {
                    // The orchestrator no longer has to wait for this worker
                    open_measurements.remove(&measurement_id);

                    println!("[Orchestrator] The last worker for a measurement dropped, sending measurement finished signal to CLI");
                    *self.active.lock().unwrap() = false;
                    match self
                        .cli_sender
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap()
                        .try_send(Ok(TaskResult::default()))
                    {
                        Ok(_) => (),
                        Err(_) => println!(
                            "[Orchestrator] Failed to send measurement finished signal to CLI"
                        ),
                    }
                } else {
                    // If there are more workers still performing this measurement
                    // The orchestrator no longer has to wait for this worker
                    *open_measurements.get_mut(&measurement_id).unwrap() -= 1;
                }
            }
        }
    }
}

/// Special Receiver struct that notices when the CLI disconnects.
///
/// When a CLI disconnects we cancel all open measurements. We set this orchestrator as available for receiving a new measurement.
///
/// Furthermore, if a measurement is active, we send a termination message to all workers to quit the current measurement.
///
/// # Fields
///
/// * 'inner' - the receiver that connects to the CLI
/// * 'active' - a boolean value that is set to true when there is an active measurement
/// * 'senders' - a list of senders that connect to the workers
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

        // If there is an active measurement we need to cancel it and notify the workers
        if *active {
            println!(
                "[Orchestrator] CLI dropped during an active measurement, terminating measurement"
            );

            // Create termination 'task'
            let end_task = Task {
                data: Some(TaskEnd(End { code: 0 })),
            };

            // Tell each worker to terminate the measurement
            for worker in self.senders.lock().unwrap().iter().cloned() {
                let end_task = end_task.clone();

                spawn(async move {
                    if let Err(e) = worker.send(Ok(end_task)).await {
                        println!(
                            "[Orchestrator] ERROR - Failed to terminate measurement {}",
                            e
                        );
                    }
                });
            }
            println!("[Orchestrator] Terminated the current measurement at all workers");

            *active = false; // No longer an active measurement
        }
    }
}

/// Implementation of the Controller trait for the ControllerService
/// Handles communication with the workers and the CLI
#[tonic::async_trait]
impl Controller for ControllerService {
    /// Called by the worker when it has finished its current measurement.
    ///
    /// When all connected workers have finished this measurement, it will notify the CLI that the measurement is finished.
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
        let worker_id: u32 = finished_measurement.worker_id;
        let tx = self.cli_sender.lock().unwrap().clone().unwrap();

        // Wait till we have received 'measurement_finished' from all workers that executed this measurement
        let is_finished = {
            let mut open_measurements = self.open_measurements.lock().unwrap();

            // Number of workers that still have to finish this measurement
            let remaining = if let Some(remaining) = open_measurements.get(&measurement_id) {
                remaining
            } else {
                println!("[Orchestrator] Received measurement finished signal for non-existent measurement {}", &measurement_id);
                return Ok(Response::new(Ack {
                    success: false,
                    error_message: "Measurement unknown".to_string(),
                }));
            };

            // Update worker-list that this worker is no longer working on this measurement
            let mut workers = self.workers.lock().unwrap();
            if let Some(worker) = workers
                .workers
                .iter_mut()
                .find(|w| w.worker_id == worker_id)
            {
                worker
                    .measurements
                    .retain(|measurement| measurement != &measurement_id);
            }

            if remaining == &(1u32) {
                // If this is the last worker we are finished
                println!("[Orchestrator] All workers finished");

                open_measurements.remove(&measurement_id);
                true // Finished
            } else {
                // If this is not the last worker, decrement the amount of remaining workers
                *open_measurements.get_mut(&measurement_id).unwrap() -= 1;

                false // Not finished yet
            }
        };
        if is_finished {
            println!("[Orchestrator] Notifying CLI that the measurement is finished");
            // There is no longer an active measurement
            *self.active.lock().unwrap() = false;

            // Send an ack to the worker that it has finished
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
            // Send an ack to the worker that it has finished
            Ok(Response::new(Ack {
                success: true,
                error_message: "".to_string(),
            }))
        }
    }

    type WorkerConnectStream = WorkerReceiver<Result<Task, Status>>;

    /// Handles a worker connecting to this orchestrator formally.
    ///
    /// Returns the receiver side of a stream to which the orchestrator will send tasks
    ///
    /// # Arguments
    ///
    /// * 'request' - a Metadata message containing the hostname of the worker
    async fn worker_connect(
        &self,
        request: Request<Metadata>,
    ) -> Result<Response<Self::WorkerConnectStream>, Status> {
        let hostname = request.into_inner().hostname;
        println!("[Orchestrator] New worker connected: {}", hostname);
        let (tx, rx) = mpsc::channel::<Result<Task, Status>>(1000);

        // Store the stream sender to send tasks through later
        self.senders.lock().unwrap().push(tx);

        // Create stream receiver for the worker
        let worker_rx = WorkerReceiver {
            inner: rx,
            open_measurements: self.open_measurements.clone(),
            cli_sender: self.cli_sender.clone(),
            hostname,
            workers: self.workers.clone(),
            active: self.active.clone(),
        };

        // Send the stream receiver to the worker
        Ok(Response::new(worker_rx))
    }
    type DoMeasurementStream = CLIReceiver<Result<TaskResult, Status>>;

    /// Handles the do_measurement command from the CLI.
    ///
    /// Instructs all workers to perform the measurement and returns the receiver side of a stream in which TaskResults will be streamed.
    ///
    /// Will lock active to true, such that no other measurement can start.
    ///
    /// Makes sure all workers are still connected, removes their senders if not.
    ///
    /// Assigns a unique ID to the measurement.
    ///
    /// Streams tasks to the workers, in a round-robin fashion, with 1-second delays between clients.
    ///
    /// Furthermore, lets the workers know of the desired probing rate (defined by the CLI).
    ///
    /// # Arguments
    ///
    /// * 'request' - a ScheduleMeasurement message containing information about the measurement that the CLI wants to perform
    ///
    /// # Errors
    ///
    /// Returns an error if there is already an active measurement, or if there are no connected workers to perform the measurement.
    async fn do_measurement(
        &self,
        request: Request<ScheduleMeasurement>,
    ) -> Result<Response<Self::DoMeasurementStream>, Status> {
        println!("[Orchestrator] Received CLI measurement request for measurement");

        // If there already is an active measurement, we skip
        {
            // If the orchestrator is already working on another measurement
            let mut active = self.active.lock().unwrap();
            if *active {
                println!("[Orchestrator] There is already an active measurement, returning");
                return Err(Status::new(
                    tonic::Code::Cancelled,
                    "There is already an active measurement",
                ));
            }

            // For every open measurement
            for (_, open) in self
                .open_measurements
                .lock()
                .expect("No open measurements map")
                .iter()
            {
                // If there are still workers who are working on a different measurement
                if open > &0 {
                    println!("[Orchestrator] There is already an active measurement, returning");
                    return Err(Status::new(
                        tonic::Code::Cancelled,
                        "There are still workers working on an active measurement",
                    ));
                }
            }

            *active = true;
        }

        // Get the list of Senders (that connect to the workers)
        let senders = {
            // Lock the senders mutex and remove closed senders
            self.senders.lock().unwrap().retain(|sender| {
                if sender.is_closed() {
                    println!(
                        "[Orchestrator] Worker unavailable, connection closed. Worker removed."
                    );
                    false
                } else {
                    true
                }
            });
            self.senders.lock().unwrap().clone()
        };

        // If there are no connected workers that can perform this measurement
        if senders.is_empty() {
            println!("[Orchestrator] No connected workers, terminating measurement.");
            *self.active.lock().unwrap() = false;
            return Err(Status::new(tonic::Code::Cancelled, "No connected workers"));
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
        // Create a list of the connected workers' IDs
        let worker_ids: Vec<u32> = self
            .workers
            .lock()
            .unwrap()
            .workers
            .iter()
            .map(|worker| worker.worker_id)
            .collect();

        // Check if the CLI requested a worker-selective probing measurement
        let mut probing_workers: Vec<u32> = scheduled_measurement.workers;

        // Make sure all worker IDs are valid
        if probing_workers
            .iter()
            .any(|worker| !worker_ids.contains(worker))
        {
            println!("[Orchestrator] Worker ID requested that is not connected, terminating measurement.");
            *self.active.lock().unwrap() = false;
            return Err(Status::new(
                tonic::Code::Cancelled,
                "One or more worker IDs are not connected.",
            ));
        }

        {
            // Update active measurement in the worker list
            let mut workers = self.workers.lock().unwrap();
            workers
                .workers
                .iter_mut()
                .for_each(|worker| worker.measurements.push(measurement_id));
        }

        // Create a measurement from the ScheduleMeasurement
        let is_unicast = scheduled_measurement.unicast;

        // Make sure no unknown workers are in the configuration
        if scheduled_measurement
            .configurations
            .iter()
            .any(|conf| !worker_ids.contains(&conf.worker_id) && conf.worker_id != u32::MAX)
        {
            println!(
                "[Orchestrator] Unknown worker in configuration list, terminating measurement."
            );
            *self.active.lock().unwrap() = false;
            return Err(Status::new(
                tonic::Code::Cancelled,
                "Unknown worker in configuration",
            ));
        }
        // Update selected_workers to contain all workers that are in the configuration list
        for configuration in &scheduled_measurement.configurations {
            // All workers are selected
            if configuration.worker_id == u32::MAX {
                probing_workers = vec![];
                break;
            }

            if !probing_workers.contains(&configuration.worker_id) {
                probing_workers.push(configuration.worker_id);
            }
        }

        // Store the number of workers that will perform this measurement
        self.open_measurements
            .lock()
            .unwrap()
            .insert(measurement_id, senders.len() as u32);

        let rate = scheduled_measurement.rate;
        let measurement_type = scheduled_measurement.measurement_type;
        let is_ipv6 = scheduled_measurement.ipv6;
        let is_divide = scheduled_measurement.divide;
        let probing_interval = scheduled_measurement.interval as u64;
        let dst_addresses = scheduled_measurement
            .targets
            .expect("Received measurement with no targets")
            .dst_addresses;
        let dns_record = scheduled_measurement.record;
        let info_url = scheduled_measurement.url;

        // Establish a stream with the CLI to return the TaskResults through
        let (tx, rx) = mpsc::channel::<Result<TaskResult, Status>>(1000);
        // Store the CLI sender
        let _ = self.cli_sender.lock().unwrap().insert(tx);

        // Create a list of origins used by workers
        let mut rx_origins = vec![];
        // Add all configuration origins to the listen origins
        for configuration in scheduled_measurement.configurations.iter() {
            if let Some(origin) = &configuration.origin {
                // Avoid duplicate origins
                if !rx_origins.contains(origin) {
                    rx_origins.push(*origin);
                }
            }
        }

        // Notify all senders that a new measurement is starting
        let mut current_worker = 0;
        let mut current_active_worker = 0;

        for sender in senders.iter() {
            let mut worker_tx_origins = vec![];
            // Add all configuration probing origins assigned to this worker
            for configuration in &scheduled_measurement.configurations {
                // If the worker is selected to perform the measurement (or all workers are selected (u32::MAX))
                if (configuration.worker_id == *worker_ids.get(current_worker).unwrap())
                    | (configuration.worker_id == u32::MAX)
                {
                    if let Some(origin) = &configuration.origin {
                        worker_tx_origins.push(*origin);
                    }
                }
            }

            // Check if the current worker is selected to send probes
            let is_probing = if probing_workers.is_empty() {
                // No worker-selective probing
                if worker_tx_origins.is_empty() {
                    false // No probe origins -> not probing
                } else {
                    true
                }
            } else {
                // Make sure the current worker is selected to perform the measurement
                probing_workers.contains(
                    worker_ids
                        .get(current_worker)
                        .expect(&*format!("Worker with ID {} not found", current_worker)),
                )
            };
            if is_probing {
                current_active_worker += 1;
            }
            current_worker = current_worker + 1;

            let start_task = Task {
                data: Some(TaskStart(Start {
                    rate,
                    measurement_id,
                    active: is_probing,
                    measurement_type,
                    unicast: is_unicast,
                    ipv6: is_ipv6,
                    tx_origins: worker_tx_origins,
                    rx_origins: rx_origins.clone(),
                    record: dns_record.clone(),
                    url: info_url.clone(),
                })),
            };

            match sender.try_send(Ok(start_task)) {
                Ok(_) => (),
                Err(e) => println!("[Orchestrator] Failed to send 'start measurement' {:?}", e),
            }
        }

        // Sleep 1 second to let the workers start listening for probe replies
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Number of workers participating in the measurement (listening and/or probing)
        let number_of_workers = senders.len() as u64;

        if !is_divide {
            println!("[Orchestrator] {} workers will listen for probe replies, {} workers will send out probes to the same target {} seconds after each other", number_of_workers, current_active_worker, probing_interval);
        } else {
            println!("[Orchestrator] {} workers will listen for probe replies, {} worker will send out probes to a different chunk of the destination addresses", number_of_workers, current_active_worker);
        }

        // Shared variable to keep track of the number of workers that have finished
        let workers_finished = Arc::new(Mutex::new(0));
        // Shared channel that workers will wait for till the last worker has finished
        let (tx_f, _) = tokio::sync::broadcast::channel::<()>(1);
        let mut active_worker_i: u64 = 0; // Index for active workers
        let mut all_worker_i = 0; // Index for the worker list
        let chunk_size: usize = 100; // TODO try increasing chunk size to reduce overhead

        let p_rate = Duration::from_nanos(
            ((1.0 / rate as f64) * chunk_size as f64 * 1_000_000_000.0) as u64,
        );

        // Create a thread that streams tasks for each worker
        for sender in senders.iter() {
            let sender = sender.clone();
            // This worker's unique ID
            let worker_id = *worker_ids.get(all_worker_i as usize).unwrap();
            all_worker_i += 1;
            let workers = probing_workers.clone();
            // If workers is empty, all workers are probing, otherwise only the workers in the list are probing
            let is_probing = workers.is_empty() || workers.contains(&worker_id);

            // Get the hitlist for this worker
            let hitlist_targets = if !is_probing {
                vec![]
            } else if is_divide {
                // Each worker gets its own chunk of the hitlist
                let targets_chunk = dst_addresses.len() / current_active_worker as usize;

                // Get start and end index of targets to probe for this worker
                let start_index = active_worker_i as usize * targets_chunk;
                let end_index = if active_worker_i == current_active_worker - 1 {
                    dst_addresses.len() // End of the list
                } else {
                    start_index + targets_chunk
                };

                dst_addresses[start_index..end_index].to_vec()
            } else {
                // All workers get the same hitlist
                dst_addresses.clone()
            };

            // increment if this worker is sending probes
            if is_probing {
                active_worker_i += 1;
            }

            let tx_f = tx_f.clone();
            let mut rx_f = tx_f.subscribe();
            let clients_finished = workers_finished.clone();
            let is_active = self.active.clone();

            spawn(async move {
                // Send out packets at the required interval
                let mut interval = tokio::time::interval(p_rate);
                // Synchronize clients probing by sleeping for a certain amount of time (ensures clients send out probes to the same target 1 second after each other)
                if is_probing && !is_divide {
                    tokio::time::sleep(Duration::from_secs(
                        (active_worker_i - 1) * probing_interval,
                    ))
                    .await;
                }

                for chunk in hitlist_targets.chunks(chunk_size) {
                    // If the CLI disconnects during task distribution, abort
                    if *is_active.lock().unwrap() == false {
                        clients_finished.lock().unwrap().add_assign(1); // This worker is 'finished'
                        if *clients_finished.lock().unwrap() == number_of_workers {
                            println!("[Orchestrator] CLI disconnected during task distribution");
                            tx_f.send(()).expect("Failed to send finished signal");
                        }
                        return; // abort
                    }

                    if is_probing {
                        let task = Task {
                            data: Some(custom_module::manycastr::task::Data::Targets(Targets {
                                dst_addresses: chunk.to_vec(),
                            })),
                        };

                        // Send packet to worker
                        match sender.send(Ok(task)).await {
                            Ok(_) => (),
                            Err(e) => {
                                println!(
                                    "[Orchestrator] Failed to send task {:?} to worker {}",
                                    e, worker_id
                                );
                                if sender.is_closed() {
                                    // If the worker is no longer connected
                                    println!("[Orchestrator] Worker {} is no longer connected and removed from the measurement", worker_id);
                                    break;
                                }
                            }
                        }
                    }
                    interval.tick().await;
                }

                clients_finished.lock().unwrap().add_assign(1); // This worker is 'finished'
                if *clients_finished.lock().unwrap() == number_of_workers {
                    println!("[Orchestrator] Measurement finished, awaiting clients... ");
                    // Send a message to the other sending threads to let them know the measurement is finished
                    tx_f.send(()).expect("Failed to send finished signal");
                } else {
                    // Wait for the last worker to finish
                    rx_f.recv()
                        .await
                        .expect("Failed to receive finished signal");

                    // If the CLI disconnects whilst waiting for the finished signal, abort
                    if *is_active.lock().unwrap() == false {
                        return; // abort
                    }
                }

                // Sleep 1 second to give the worker time to finish the measurement and receive the last responses
                tokio::time::sleep(Duration::from_secs(1)).await;

                // Send a message to the worker to let it know it has received everything for the current measurement
                match sender
                    .send(Ok(Task {
                        data: Some(TaskEnd(End { code: 0 })),
                    }))
                    .await
                {
                    Ok(_) => (),
                    Err(e) => println!(
                        "[Orchestrator] Failed to send 'end message' {:?} to worker {}",
                        e, worker_id
                    ),
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
    async fn list_workers(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ServerStatus>, Status> {
        Ok(Response::new(self.workers.lock().unwrap().clone()))
    }

    /// Receive a TaskResult from the worker and put it in the stream towards the CLI
    ///
    /// # Arguments
    ///
    /// * 'request' - a TaskResult message containing the results of a task
    ///
    /// # Errors
    ///
    /// Returns an error if the CLI has disconnected.
    async fn send_result(&self, request: Request<TaskResult>) -> Result<Response<Ack>, Status> {
        // Send the result to the CLI through the established stream
        let task_result = request.into_inner();

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

    /// Handles a worker requesting a worker ID.
    ///
    /// Returns a unique worker ID.
    ///
    /// # Arguments
    ///
    /// * 'request' - Metadata message that contains the worker's hostname
    ///
    /// # Errors
    ///
    /// Returns an error if the hostname already exists
    async fn get_worker_id(
        &self,
        request: Request<Metadata>,
    ) -> Result<Response<WorkerId>, Status> {
        let metadata = request.into_inner();
        let hostname = metadata.hostname;
        let mut worker_list = self.workers.lock().unwrap();

        // Check if the hostname already exists
        for worker in &worker_list.workers {
            match &worker.metadata {
                Some(metadata) if hostname == metadata.hostname => {
                    println!(
                        "[Orchestrator] Refusing worker as the hostname already exists: {}",
                        hostname
                    );
                    return Err(Status::new(
                        tonic::Code::AlreadyExists,
                        "This hostname already exists",
                    ));
                }
                _ => {} // Continue to next worker
            }
        }

        // Obtain unique worker id
        let worker_id = {
            let mut current_client_id = self.current_worker_id.lock().unwrap();
            let client_id = *current_client_id;
            current_client_id.add_assign(1);
            client_id
        };

        // Add the worker to the worker list
        let new_worker = Worker {
            worker_id,
            metadata: Some(Metadata { hostname }),
            measurements: vec![],
        };
        worker_list.workers.push(new_worker);

        // Accept the worker and give it a unique worker ID
        Ok(Response::new(WorkerId { worker_id }))
    }
}

/// Start the orchestrator.
///
/// Starts the orchestrator on the specified port.
///
/// # Arguments
///
/// * 'args' - the parsed command-line arguments
pub async fn start(args: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let port = *args.get_one::<u16>("port").unwrap();
    let addr: SocketAddr = format!("[::]:{}", port).parse().unwrap();

    // Get a random measurement ID to start with
    let measurement_id = rand::rng().random_range(0..u32::MAX);

    let controller = ControllerService {
        workers: Arc::new(Mutex::new(ServerStatus::default())),
        senders: Arc::new(Mutex::new(Vec::new())),
        cli_sender: Arc::new(Mutex::new(None)),
        open_measurements: Arc::new(Mutex::new(HashMap::new())),
        current_measurement_id: Arc::new(Mutex::new(measurement_id)),
        current_worker_id: Arc::new(Mutex::new(1)),
        active: Arc::new(Mutex::new(false)),
    };

    let svc = ControllerServer::new(controller)
        .accept_compressed(CompressionEncoding::Zstd)
        .max_decoding_message_size(10 * 1024 * 1024 * 1024) // 10 GB
        .max_encoding_message_size(10 * 1024 * 1024 * 1024);

    // if TLS is enabled create the orchestrator using a TLS configuration
    if args.get_flag("tls") {
        println!("[Orchestrator] Starting orchestrator with TLS enabled");
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(load_tls()))
            .expect("Failed to load TLS certificate")
            .http2_keepalive_interval(Some(Duration::from_secs(60)))
            .http2_keepalive_timeout(Some(Duration::from_secs(10)))
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .add_service(svc)
            .serve(addr)
            .await
            .expect("Failed to start orchestrator with TLS");
    } else {
        Server::builder()
            .http2_keepalive_interval(Some(Duration::from_secs(60)))
            .http2_keepalive_timeout(Some(Duration::from_secs(10)))
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .add_service(svc)
            .serve(addr)
            .await
            .expect("Failed to start orchestrator");
    }

    Ok(())
}

// 1. Generate private key:
// openssl genpkey -algorithm RSA -out orchestrator.key -pkeyopt rsa_keygen_bits:2048
// 2. Generate certificate signing request:
// openssl req -new -key orchestrator.key -out orchestrator.csr
// 3. Generate self-signed certificate:
// openssl x509 -req -in orchestrator.csr -signkey orchestrator.key -out orchestrator.crt -days 3650
// 4. Distribute orchestrator.crt to clients
fn load_tls() -> Identity {
    // Load TLS certificate
    let cert = fs::read("tls/orchestrator.crt")
        .expect("Unable to read certificate file at ./tls/orchestrator.crt");
    // Load TLS private key
    let key = fs::read("tls/orchestrator.key")
        .expect("Unable to read key file at ./tls/orchestrator.key");

    // Create TLS configuration
    let identity = Identity::from_pem(cert, key);

    identity
}
