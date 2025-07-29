use std::cmp::PartialEq;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::ops::AddAssign;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::custom_module;
use crate::custom_module::manycastr::Address;
use crate::orchestrator::mpsc::Sender;
use crate::orchestrator::WorkerStatus::{Disconnected, Idle, Listening, Probing};
use clap::ArgMatches;
use custom_module::manycastr::{
    controller_server::Controller, controller_server::ControllerServer, task::Data::End as TaskEnd,
    task::Data::Start as TaskStart, Ack, Empty, End, Finished, ScheduleMeasurement, Start,
    Status as ServerStatus, Targets, Task, TaskResult, Worker,
};
use futures_core::Stream;
use rand::Rng;
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::time::Instant;
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
/// * 'is_active' - a boolean value that is set to true when there is an active measurement
/// * 'r_prober' - ID of worker that is probing for responsiveness TODO update rustdoc
#[derive(Debug)]
pub struct ControllerService {
    workers: Arc<Mutex<Vec<WorkerSender<Result<Task, Status>>>>>,
    cli_sender: Arc<Mutex<Option<Sender<Result<TaskResult, Status>>>>>,
    open_measurements: Arc<Mutex<HashMap<u32, u32>>>,
    current_measurement_id: Arc<Mutex<u32>>,
    unique_id: Arc<Mutex<u32>>,
    is_active: Arc<Mutex<bool>>,
    is_responsive: Arc<AtomicBool>,
    is_latency: Arc<AtomicBool>,
    // task_sender: Arc<Mutex<Option<Sender<(u32, Task, bool)>>>>,
    worker_config: Option<HashMap<String, u32>>,
    worker_stacks: Arc<Mutex<HashMap<u32, VecDeque<Address>>>>,
}

const BREAK_SIGNAL: u32 = u32::MAX - 1;
const ALL_WORKERS_DIRECT: u32 = u32::MAX;
const ALL_WORKERS_INTERVAL: u32 = u32::MAX - 2;

#[derive(Debug, Clone, Copy)]
pub enum WorkerStatus {
    Idle,         // Connected but not participating in a measurement
    Probing,      // Probing for a measurement
    Listening,    // Only listening for probe replies for a measurement
    Disconnected, // Disconnected
}

impl fmt::Display for WorkerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Idle => "IDLE",
            Probing => "PROBING",
            Listening => "LISTENING",
            Disconnected => "DISCONNECTED",
        };
        write!(f, "{}", s)
    }
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
/// * 'active' - a boolean value that is set to true when there is an active measurement TODO update rustdoc
pub struct WorkerReceiver<T> {
    inner: mpsc::Receiver<T>,
    open_measurements: Arc<Mutex<HashMap<u32, u32>>>,
    cli_sender: Arc<Mutex<Option<Sender<Result<TaskResult, Status>>>>>,
    hostname: String,
    active: Arc<Mutex<bool>>,
    status: Arc<Mutex<WorkerStatus>>,
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
                    // The orchestrator no longer has to wait for this measurement
                    open_measurements.remove(measurement_id);

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
                    *open_measurements.get_mut(measurement_id).unwrap() -= 1;
                }
            }
        }

        let mut status = self.status.lock().unwrap();
        *status = Disconnected;
    }
}

/// Special Sender struct for workers that sends tasks after a delay (based on the Worker interval).
///
/// # Fields
///
/// * inner - the inner sender that connects to the worker
///
/// * interval - the interval in seconds to wait between a task being put in the sender and sending it
///
/// * is_probing - a boolean value that is set to true when the worker is probing (or only listening)

#[derive(Clone)]
pub struct WorkerSender<T> {
    inner: Sender<T>,
    is_probing: Arc<AtomicBool>,
    worker_id: u32,
    hostname: String,
    status: Arc<Mutex<WorkerStatus>>,
}
impl<T> WorkerSender<T> {
    /// Checks if the sender is closed
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Sends a task after the specified interval
    pub async fn send(&self, task: T) -> Result<(), mpsc::error::SendError<T>> {
        match self.inner.send(task).await {
            Ok(_) => Ok(()),
            Err(e) => {
                self.cleanup();
                Err(e)
            }
        }
    }

    fn cleanup(&self) {
        // If the worker is disconnected, we set the status to DISCONNECTED
        let mut status = self.status.lock().unwrap();
        *status = Disconnected;

        // Set the is_probing flag to false
        self.is_probing
            .store(false, std::sync::atomic::Ordering::SeqCst);
        println!(
            "[Orchestrator] Worker {} (ID: {}) dropped",
            self.hostname, self.worker_id
        );
    }

    pub fn is_probing(&self) -> bool {
        self.is_probing.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn get_status(&self) -> String {
        self.status.lock().unwrap().clone().to_string()
    }

    /// Update is_probing flag
    pub fn update_is_probing(&self, is_probing: bool) {
        let mut status = self.status.lock().unwrap();
        if is_probing {
            *status = Probing;
        } else {
            *status = Listening;
        }
        self.is_probing
            .store(is_probing, std::sync::atomic::Ordering::SeqCst);
    }

    /// The worker finished its measurement
    pub fn finished(&self) {
        let mut status = self.status.lock().unwrap();
        // Set the status to Idle if it is not Disconnected
        if *status != Disconnected {
            *status = Idle;
        }
    }
}
impl<T> fmt::Debug for WorkerSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WorkerSender {{ worker_id: {}, hostname: {}, is_probing: {} }}",
            self.worker_id,
            self.hostname,
            self.is_probing.load(std::sync::atomic::Ordering::SeqCst)
        )
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
/// * 'open_measurements' - a list of the current open measurements, and the number of workers that are currently working on it
/// * 'measurement_id' - the ID of the measurement that this receiver is associated with
pub struct CLIReceiver<T> {
    inner: mpsc::Receiver<T>,
    active: Arc<Mutex<bool>>,
    measurement_id: u32,
    open_measurements: Arc<Mutex<HashMap<u32, u32>>>,
}

impl<T> Stream for CLIReceiver<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.inner.poll_recv(cx)
    }
}

impl<T> Drop for CLIReceiver<T> {
    fn drop(&mut self) {
        let mut is_active = self.active.lock().unwrap();

        // If there is an active measurement we need to cancel it and notify the workers
        if *is_active {
            println!(
                "[Orchestrator] CLI dropped during an active measurement, terminating measurement"
            );
        }
        *is_active = false; // No longer an active measurement

        // Remove the current measurement
        let mut open_measurements = self.open_measurements.lock().unwrap();
        open_measurements.remove(&self.measurement_id);
    }
}

impl PartialEq for WorkerStatus {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Idle, Idle)
                | (Probing, Probing)
                | (Listening, Listening)
                | (Disconnected, Disconnected)
        )
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
                    is_success: false,
                    error_message: "Measurement unknown".to_string(),
                }));
            };

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
            *self.is_active.lock().unwrap() = false;

            // Send an ack to the worker that it has finished
            return match tx.send(Ok(TaskResult::default())).await {
                Ok(_) => Ok(Response::new(Ack {
                    is_success: true,
                    error_message: "".to_string(),
                })),
                Err(_) => Ok(Response::new(Ack {
                    is_success: false,
                    error_message: "CLI disconnected".to_string(),
                })),
            };
        } else {
            // Send an ack to the worker that it has finished
            Ok(Response::new(Ack {
                is_success: true,
                error_message: "".to_string(),
            }))
        }
    }

    type WorkerConnectStream = WorkerReceiver<Result<Task, Status>>;

    /// Handles a worker connecting to this orchestrator formally.
    ///
    /// Ensures the hostname is unique and returns a unique worker ID
    ///
    /// Returns the receiver side of a stream to which the orchestrator will send tasks
    ///
    /// # Arguments
    ///
    /// * 'request' - a Metadata message containing the hostname of the worker
    async fn worker_connect(
        &self,
        request: Request<Worker>,
    ) -> Result<Response<Self::WorkerConnectStream>, Status> {
        let hostname = request.into_inner().hostname;
        println!("[Orchestrator] New worker connected: {}", hostname);
        let (tx, rx) = mpsc::channel::<Result<Task, Status>>(1000);
        // TODO split off the worker ID generation into a separate function

        let (worker_id, is_reconnect) = self.get_worker_id(&hostname)?;

        // Send worker ID
        tx.send(Ok(Task {
            worker_id: Some(worker_id),
            data: None,
        }))
        .await
        .expect("Failed to send worker ID");

        let worker_status = Arc::new(Mutex::new(Idle));

        let worker_tx = WorkerSender {
            inner: tx,
            is_probing: Arc::new(AtomicBool::new(false)), // default is not probing
            worker_id,
            hostname: hostname.clone(),
            status: worker_status.clone(),
        };

        // Remove the disconnected worker if it existed
        if is_reconnect {
            let mut senders = self.workers.lock().unwrap();
            senders.retain(|sender| sender.worker_id != worker_id);
        }

        // Add the new worker sender to the list of workers
        self.workers.lock().unwrap().push(worker_tx);

        // Create stream receiver for the worker
        let worker_rx = WorkerReceiver {
            inner: rx,
            open_measurements: self.open_measurements.clone(),
            cli_sender: self.cli_sender.clone(),
            hostname,
            active: self.is_active.clone(),
            status: worker_status,
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
            let mut active = self.is_active.lock().unwrap();
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

        // The measurement that the CLI wants to perform
        let scheduled_measurement = request.into_inner();
        let is_responsive = scheduled_measurement.is_responsive;
        let is_latency = scheduled_measurement.is_latency;
        let is_divide = scheduled_measurement.is_divide;
        let worker_interval = scheduled_measurement.worker_interval as u64;
        let probe_interval = scheduled_measurement.probe_interval as u64;
        let number_of_probes = scheduled_measurement.number_of_probes as u8;

        // Configure and get the senders
        let workers: Vec<WorkerSender<Result<Task, Status>>> = {
            let mut workers = self.workers.lock().unwrap().clone();
            // Only keep connected workers
            workers.retain(|worker| {
                if *worker.status.lock().unwrap() == Disconnected {
                    println!("[Orchestrator] Worker {} unavailable.", worker.hostname);
                    false
                } else {
                    true
                }
            });

            // Make sure no unknown workers are in the configuration
            if scheduled_measurement.configurations.iter().any(|conf| {
                !workers
                    .iter()
                    .any(|sender| sender.worker_id == conf.worker_id)
                    && conf.worker_id != u32::MAX
            }) {
                println!(
                    "[Orchestrator] Unknown worker in configuration list, terminating measurement."
                );
                *self.is_active.lock().unwrap() = false;
                return Err(Status::new(
                    tonic::Code::Cancelled,
                    "Unknown worker in configuration",
                ));
            }

            // Set the is_probing bool for each worker_tx
            for worker in workers.iter_mut() {
                let is_probing = scheduled_measurement.configurations.iter().any(|config| {
                    config.worker_id == worker.worker_id || config.worker_id == u32::MAX
                });

                worker.update_is_probing(is_probing);
            }

            workers
        };

        // If there are no connected workers that can perform this measurement
        if workers.is_empty() {
            println!("[Orchestrator] No connected workers, terminating measurement.");
            *self.is_active.lock().unwrap() = false;
            return Err(Status::new(tonic::Code::Cancelled, "No connected workers"));
        }

        // Assign a unique ID the measurement and increment the measurement ID counter
        let measurement_id = {
            let mut current_measurement_id = self.current_measurement_id.lock().unwrap();
            let id = *current_measurement_id;
            *current_measurement_id = current_measurement_id.wrapping_add(1);
            id
        };

        // Create a measurement from the ScheduleMeasurement
        let is_unicast = scheduled_measurement.is_unicast;

        let number_of_workers = workers.len() as u32;
        let number_of_probing_workers = workers.iter().filter(|sender| sender.is_probing()).count();

        let number_of_listeners = if is_unicast {
            // Only probing workers are listening
            number_of_probing_workers as u32
        } else {
            // All workers are listening
            number_of_workers
        };

        // Store the number of workers that will perform this measurement
        self.open_measurements
            .lock()
            .unwrap()
            .insert(measurement_id, number_of_listeners);

        let probing_rate = scheduled_measurement.probing_rate;
        let measurement_type = scheduled_measurement.measurement_type;
        let is_ipv6 = scheduled_measurement.is_ipv6;
        let dst_addresses = scheduled_measurement
            .targets
            .expect("Received measurement with no targets")
            .dst_list;
        let dns_record = scheduled_measurement.record;
        let info_url = scheduled_measurement.url;

        if !is_divide {
            println!("[Orchestrator] {} workers will listen for probe replies, {} workers will send out probes to the same target {} seconds after each other", number_of_workers, number_of_probing_workers, worker_interval);
        } else {
            println!("[Orchestrator] {} workers will listen for probe replies, {} worker will send out probes to a different chunk of the destination addresses", number_of_workers, number_of_probing_workers);
        }

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

        // Create channel for TaskDistributor (client_id, task, number_of_times)
        let (tx_t, rx_t) = mpsc::channel::<(u32, Task, bool)>(1000);
        // self.task_sender.lock().unwrap().replace(tx_t.clone());

        // Create a cycler of active probing workers (containing their IDs)
        let probing_worker_ids = workers
            .iter()
            .filter(|sender| sender.is_probing())
            .map(|sender| sender.worker_id)
            .collect::<Vec<u32>>();

        // Notify all workers that a measurement is starting
        for worker in workers.iter() {
            let worker_id = worker.worker_id;
            let mut tx_origins = vec![];

            // Add all configuration probing origins assigned to this worker
            for configuration in &scheduled_measurement.configurations {
                // If the worker is selected to perform the measurement (or all workers are selected (u32::MAX))
                if (configuration.worker_id == worker_id) | (configuration.worker_id == u32::MAX) {
                    if let Some(origin) = &configuration.origin {
                        tx_origins.push(*origin);
                    }
                }
            }

            let start_task = Task {
                worker_id: None,
                data: Some(TaskStart(Start {
                    rate: probing_rate,
                    measurement_id,
                    measurement_type,
                    is_unicast,
                    is_ipv6,
                    tx_origins,
                    rx_origins: rx_origins.clone(),
                    record: dns_record.clone(),
                    url: info_url.clone(),
                    is_latency,
                })),
            };

            tx_t.send((worker_id, start_task, false))
                .await
                .expect("Failed to send task to TaskDistributor");
        }

        spawn(async move {
            task_sender(
                rx_t,
                workers,
                worker_interval,
                probe_interval,
                number_of_probes,
            )
            .await;
        });

        // Sleep 1 second to let the workers start listening for probe replies
        tokio::time::sleep(Duration::from_secs(1)).await;

        self.is_responsive
            .store(is_responsive, std::sync::atomic::Ordering::SeqCst);
        println!("[Orchestrator] Responsive probing mode: {}", is_responsive);
        self.is_latency
            .store(is_latency, std::sync::atomic::Ordering::SeqCst);

        let mut probing_rate_interval = if is_latency || is_divide {
            // We send a chunk every probing_rate / number_of_probing_workers seconds (as the probing is spread out over the workers)
            tokio::time::interval(Duration::from_secs(1) / number_of_probing_workers as u32)
        } else {
            // We send a chunk every second
            tokio::time::interval(Duration::from_secs(1))
        };

        let is_active = self.is_active.clone();

        let is_discovery = if is_responsive || is_latency {
            // If we are in responsive or latency mode, we want to discover the targets
            Some(true)
        } else {
            None
        };

        if is_divide || is_responsive || is_latency {
            println!("[Orchestrator] Starting Round-Robin Task Distributor.");

            let is_latency_signal = self.is_latency.clone();
            let is_responsive_signal = self.is_responsive.clone();
            let mut cooldown_timer: Option<Instant> = None;

            // Create a stack for each worker to store targets for follow-up probes (used for --responsive and --latency)
            let worker_stacks = self.worker_stacks.clone();

            spawn(async move {
                // This cycler gives us the next worker to assign a task to
                let mut sender_cycler = probing_worker_ids.into_iter().cycle();
                // TODO update cycler if a worker disconnects
                // TODO update probing_rate_interval if a worker disconnects

                // We create a manual iterator over the general hitlist.
                let mut hitlist_iter = dst_addresses.into_iter();
                let mut hitlist_is_empty = false;

                loop {
                    if !(*is_active.lock().unwrap()) {
                        println!("[Orchestrator] CLI disconnected; ending measurement");
                        break;
                    }

                    // Get the current worker ID to send tasks to.
                    let worker_id = sender_cycler.next().expect("No probing workers available");
                    
                    let f_worker_id = if is_responsive {
                        // Responsive mode checks for responsiveness and sends tasks to all workers
                        ALL_WORKERS_INTERVAL
                    } else {
                        worker_id
                    };

                    // Get the addresses for this tick
                    let mut follow_ups: Vec<Address> = Vec::new();

                    // Attempt to get addresses from the worker stack first
                    {
                        let mut stacks = worker_stacks.lock().unwrap();
                        println!("ID {}, {:?}", worker_id, stacks);
                        if let Some(queue) = stacks.get_mut(&f_worker_id) {
                            let num_to_take = std::cmp::min(probing_rate as usize, queue.len());

                            follow_ups.extend(queue.drain(..num_to_take));
                        }
                    }

                    let follow_ups_len = follow_ups.len();

                    // Send follow-up probes to the worker if we have any
                    if follow_ups_len > 0 {
                        let task = Task {
                            worker_id: None,
                            data: Some(custom_module::manycastr::task::Data::Targets(Targets {
                                dst_list: follow_ups,
                                is_discovery: None,
                            })),
                        };

                        tx_t.send((f_worker_id, task, true))
                            .await
                            .expect("Failed to send task to TaskDistributor");
                    }

                    // Fill up remainder using the general hitlist.
                    let remainder_needed = (probing_rate as usize).saturating_sub(follow_ups_len);

                    let hitlist_targets = if remainder_needed > 0 && !hitlist_is_empty {
                        // Take the exact number of remaining addresses needed from the hitlist.
                        let addresses_from_hitlist: Vec<Address> =
                            hitlist_iter.by_ref().take(remainder_needed).collect();

                        // If we are unable to fill the addresses, the hitlist is empty
                        if addresses_from_hitlist.len() < remainder_needed {
                            hitlist_is_empty = true;
                        }

                        addresses_from_hitlist
                    } else {
                        Vec::new()
                    };

                    // Send the hitlist targets to the worker
                    if !hitlist_targets.is_empty() {
                        // Create a single task from the addresses and send it to the worker
                        let task = Task {
                            worker_id: None,
                            data: Some(custom_module::manycastr::task::Data::Targets(Targets {
                                dst_list: hitlist_targets,
                                is_discovery,
                            })),
                        };

                        tx_t.send((worker_id, task, is_discovery.is_none()))
                            .await
                            .expect("Failed to send task to TaskDistributor");
                    }

                    if hitlist_is_empty {
                        if let Some(start_time) = cooldown_timer {
                            if start_time.elapsed()
                                >= Duration::from_secs(
                                    number_of_probing_workers as u64 * worker_interval + 5,
                                )
                            {
                                println!("[Orchestrator] Task distribution finished.");
                                break;
                            }
                        } else {
                            // Make sure all stacks are empty before we start the cooldown timer
                            let all_stacks_empty = {
                                let stacks_guard = worker_stacks.lock().unwrap();
                                stacks_guard.values().all(|queue| queue.is_empty())
                            };
                            if all_stacks_empty {
                                println!(
                                    "[Orchestrator] No more tasks. Waiting {} seconds for cooldown.",
                                    number_of_probing_workers as u64 * worker_interval + 5
                                );
                                cooldown_timer = Some(Instant::now());
                            }
                        }
                    }

                    probing_rate_interval.tick().await;
                }

                // Send end message to all workers directly to let them know the measurement is finished
                tx_t.send((
                    ALL_WORKERS_DIRECT,
                    Task {
                        worker_id: None,
                        data: Some(TaskEnd(End { code: 0 })),
                    },
                    false,
                ))
                .await
                .expect("Failed to send end task to TaskDistributor");

                // Wait till all workers are finished
                while *is_active.lock().unwrap() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                // Avoid new follow-up probes
                is_latency_signal.store(false, std::sync::atomic::Ordering::SeqCst);
                is_responsive_signal.store(false, std::sync::atomic::Ordering::SeqCst);

                // Empty the stacks
                {
                    let mut stacks_guard = worker_stacks.lock().unwrap();
                    *stacks_guard = HashMap::new();
                }

                // Close the TaskDistributor channel
                tx_t.send((
                    BREAK_SIGNAL,
                    Task {
                        worker_id: None,
                        data: None,
                    },
                    false,
                ))
                .await
                .expect("Failed to send end task to TaskDistributor");
            });
        } else {
            println!("[Orchestrator] Starting Broadcast Task Distributor.");
            spawn(async move {
                // Iterate over the hitlist in chunks of the specified probing rate.
                for chunk in dst_addresses.chunks(probing_rate as usize) {
                    if !(*is_active.lock().unwrap()) {
                        println!("[Orchestrator] Measurement no longer active");
                        break;
                    }

                    tx_t.send((
                        ALL_WORKERS_INTERVAL,
                        Task {
                            worker_id: None,
                            data: Some(custom_module::manycastr::task::Data::Targets(Targets {
                                dst_list: chunk.to_vec(),
                                is_discovery,
                            })),
                        },
                        is_discovery.is_none(),
                    ))
                    .await
                    .expect("Failed to send task to TaskDistributor");

                    probing_rate_interval.tick().await;
                }

                // Wait for the workers to finish their tasks
                tokio::time::sleep(Duration::from_secs(
                    (number_of_probing_workers as u64 * worker_interval) + 1,
                ))
                .await;

                println!("[Orchestrator] Task distribution finished");

                // Send end message to all workers directly to let them know the measurement is finished
                tx_t.send((
                    ALL_WORKERS_DIRECT,
                    Task {
                        worker_id: None,
                        data: Some(TaskEnd(End { code: 0 })),
                    },
                    false,
                ))
                .await
                .expect("Failed to send end task to TaskDistributor");

                // Wait till all workers are finished
                while *is_active.lock().unwrap() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                // Close the TaskDistributor channel
                tx_t.send((
                    BREAK_SIGNAL,
                    Task {
                        worker_id: None,
                        data: None,
                    },
                    false,
                ))
                .await
                .expect("Failed to send end task to TaskDistributor");
            });
        }

        let rx = CLIReceiver {
            inner: rx,
            active: self.is_active.clone(),
            measurement_id,
            open_measurements: self.open_measurements.clone(),
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
        // Lock the workers list and clone it to return
        let workers_list = self.workers.lock().unwrap();
        let mut workers = Vec::new();
        for worker in workers_list.iter() {
            workers.push(Worker {
                worker_id: worker.worker_id,
                hostname: worker.hostname.clone(),
                status: worker.get_status().clone(),
            });
        }

        let status = ServerStatus { workers };
        Ok(Response::new(status))
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
        let mut task_result = request.into_inner();

        // if self.r_prober is not None and equals this task's worker_id
        if self.is_responsive.load(std::sync::atomic::Ordering::SeqCst) {
            // Get the list of targets
            let responsive_targets: Vec<Address> = task_result
                .result_list
                .iter()
                .filter(|result| result.is_discovery)
                .map(|result_f| result_f.src.unwrap())
                .collect();

            if !responsive_targets.is_empty() {
                // Sleep 1 second to avoid rate-limiting issues
                tokio::time::sleep(Duration::from_secs(1)).await;

                // TODO for each origin keep track of the responsive targets already checked
                // TODO enforce that each responsive target gets a single follow-up task

                // Insert the responsive targets into the worker stack
                self.worker_stacks
                    .lock()
                    .unwrap()
                    .entry(ALL_WORKERS_INTERVAL)
                    .or_default()
                    .extend(responsive_targets.clone());

                // Remove discovery results from the result list for the CLI
                task_result
                    .result_list
                    .retain(|result| !result.is_discovery);

                if task_result.result_list.is_empty() {
                    // If there are no regular results, we can return early
                    return Ok(Response::new(Ack {
                        is_success: true,
                        error_message: "".to_string(),
                    }));
                }
            }
        } else if self.is_latency.load(std::sync::atomic::Ordering::SeqCst) {
            println!("received {:?}", task_result);

            let rx_id = task_result.worker_id;

            // Probe from the catching PoP
            let responsive_targets: Vec<Address> = task_result
                .result_list
                .iter()
                .filter(|result| result.is_discovery)
                .map(|result_f| result_f.src.unwrap())
                .collect();

            println!("responsive targets: {:?}", responsive_targets);

            if !responsive_targets.is_empty() {
                // Sleep 1 second to avoid rate-limiting issues
                tokio::time::sleep(Duration::from_secs(1)).await;

                // Insert the responsive targets into the worker stack
                {
                    println!("waiting for lock");
                    let mut worker_stacks = self.worker_stacks.lock().unwrap();
                    println!("lock acquired");
                    worker_stacks
                        .entry(rx_id)
                        .or_default()
                        .extend(responsive_targets.clone());
                }

                println!("worker stacks r: {:?}", self.worker_stacks.lock().unwrap());

                // Keep non-discovery results
                task_result
                    .result_list
                    .retain(|result| !result.is_discovery);

                if task_result.result_list.is_empty() {
                    // If there are no valid results left, we can return early
                    return Ok(Response::new(Ack {
                        is_success: true,
                        error_message: "".to_string(),
                    }));
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
                is_success: true,
                error_message: "".to_string(),
            })),
            Err(_) => Ok(Response::new(Ack {
                is_success: false,
                error_message: "CLI disconnected".to_string(),
            })),
        }
    }
}

impl ControllerService {
    /// Gets a unique worker ID for a new connecting worker.
    /// Increments the unique ID counter after returning the ID (for the next worker).
    fn get_unique_id(&self) -> u32 {
        let mut unique_id = self.unique_id.lock().unwrap();
        let worker_id = *unique_id;
        unique_id.add_assign(1);

        worker_id
    }

    /// Gets a worker ID for a connecting worker based on its hostname.
    /// If the hostname already exists, it returns the existing worker ID.
    /// If the hostname does not exist, it checks for a statically configured ID or generates a new unique ID.
    ///
    /// # Arguments
    /// * 'hostname' - the hostname of the worker
    ///
    /// # Returns
    /// Returns the worker ID
    ///
    /// # Errors
    /// Returns an error if the hostname already exists and is used by a connected worker.
    fn get_worker_id(&self, hostname: &str) -> Result<(u32, bool), Status> {
        {
            let workers = self.workers.lock().unwrap();
            // Check if the hostname already exists in the workers list
            if let Some(existing_worker) = workers.iter().find(|w| w.hostname == hostname) {
                return if !existing_worker.is_closed() {
                    println!(
                        "[Orchestrator] Refusing worker as the hostname already exists: {}",
                        hostname
                    );
                    Err(Status::already_exists("This hostname already exists"))
                } else {
                    // This is a reconnection of a closed worker.
                    println!("[Orchestrator] Worker {} reconnected", hostname);
                    let id = existing_worker.worker_id;
                    Ok((id, true))
                };
            }
        }

        // Check for a statically configured ID
        if let Some(worker_config) = &self.worker_config {
            if let Some(worker_id) = worker_config.get(hostname) {
                return Ok((*worker_id, false));
            }
        }

        // Return a new unique ID
        let new_id = self.get_unique_id();
        Ok((new_id, false))
    }
}

/// Reads from a channel containing Tasks and sends them to the workers, at specified inter-client intervals.
/// Sends repeated tasks (at inter-probe interval) if multiple probes per target are configured.
///
/// Used for starting a measurement, sending tasks to the workers, ending a measurement.
///
/// # Arguments
///
/// * 'rx' - the channel containing the tuple (task_ID, task, multiple_times)
///
/// * 'senders' - a map of worker IDs to their corresponding senders TODO fix rustdoc
async fn task_sender(
    mut rx: mpsc::Receiver<(u32, Task, bool)>,
    workers: Vec<WorkerSender<Result<Task, Status>>>,
    inter_client_interval: u64,
    inter_probe_interval: u64,
    number_of_probes: u8,
) {
    // Loop over the tasks in the channel
    while let Some((worker_id, task, multiple)) = rx.recv().await {
        let nprobes = if multiple { number_of_probes } else { 1 };

        if worker_id == BREAK_SIGNAL {
            break;
        } else if worker_id == ALL_WORKERS_DIRECT {
            // To all direct (used for 'end measurement' only)
            for sender in &workers {
                sender.send(Ok(task.clone())).await.unwrap_or_else(|e| {
                    eprintln!(
                        "[Orchestrator] Failed to send broadcast task to worker {}: {:?}",
                        sender.hostname, e
                    );
                });
                sender.finished();
            }
        } else if worker_id == ALL_WORKERS_INTERVAL {
            // To all workers with an interval (used for --unicast, anycast, --responsive follow-up probes)
            for sender in &workers {
                if sender.is_probing.load(std::sync::atomic::Ordering::SeqCst) {
                    let sender_c = sender.clone();
                    let task_c = task.clone();
                    spawn(async move {
                        spawn(async move {
                            for _ in 0..nprobes {
                                sender_c.send(Ok(task_c.clone())).await.unwrap_or_else(|e| {
                                    eprintln!(
                                        "[Orchestrator] Failed to send broadcast task to probing worker {}: {:?}",
                                        sender_c.hostname, e
                                    );
                                });
                                // Sleep for the inter-probe interval
                                tokio::time::sleep(Duration::from_secs(inter_probe_interval)).await;
                            }
                        });

                        // Wait inter-client probing interval
                        tokio::time::sleep(Duration::from_secs(inter_client_interval)).await;
                    });
                }
            }
        } else {
            // to specific worker (used for --latency follow-up probes)
            if let Some(sender) = workers.iter().find(|s| s.worker_id == worker_id) {
                if nprobes < 2 {
                    // probe once
                    sender.send(Ok(task)).await.unwrap_or_else(|e| {
                        eprintln!(
                            "[Orchestrator] Failed to send task to worker {}: {:?}",
                            sender.hostname, e
                        );
                    });
                } else {
                    // probe multiple times (in separate thread)
                    let sender_clone = sender.clone();
                    spawn(async move {
                        for _ in 0..number_of_probes {
                            sender_clone
                                .send(Ok(task.clone()))
                                .await
                                .unwrap_or_else(|e| {
                                    eprintln!(
                                        "[Orchestrator] Failed to send task to worker {}: {:?}",
                                        sender_clone.hostname, e
                                    );
                                });
                            // Wait inter-probe interval
                            tokio::time::sleep(Duration::from_secs(inter_probe_interval)).await;
                        }
                    });
                }
            } else {
                eprintln!("[Orchestrator] No sender found for worker ID {}", worker_id);
            }
        }
    }

    println!("[Orchestrator] Task distributor finished");
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

    // Get optional configuration file
    let (current_worker_id, worker_config) = args
        .get_one::<String>("config")
        .map(|config_path| load_worker_config(config_path))
        .unwrap_or_else(|| (Arc::new(Mutex::new(1)), None));

    // Get a random measurement ID to start with
    let measurement_id = rand::rng().random_range(0..u32::MAX);

    let controller = ControllerService {
        workers: Arc::new(Mutex::new(Vec::new())),
        cli_sender: Arc::new(Mutex::new(None)),
        open_measurements: Arc::new(Mutex::new(HashMap::new())),
        current_measurement_id: Arc::new(Mutex::new(measurement_id)),
        unique_id: current_worker_id,
        is_active: Arc::new(Mutex::new(false)),
        is_responsive: Arc::new(AtomicBool::new(false)),
        is_latency: Arc::new(AtomicBool::new(false)),
        // task_sender: Arc::new(Mutex::new(None)),
        worker_config,
        worker_stacks: Arc::new(Mutex::new(HashMap::new())),
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

/// Load the worker configuration from a file.
/// This provides a static mapping of hostnames to worker IDs.
/// Formats the file as follows:
/// <hostname>,<id>
///
/// # Arguments
/// * 'config_path' - the path to the configuration file
///
/// # Returns
/// Returns a tuple containing:
/// * An Arc<Mutex<u32>> containing the worker ID for any new hostname, which is the maximum ID + 1 in the configuration file
/// * An Option<HashMap<String, u32>> containing the mapping of hostnames to worker IDs
///
/// # Panics
/// Panics if the configuration file does not exist, or if there are malformed entries, duplicate hostnames, or duplicate IDs.
fn load_worker_config(config_path: &String) -> (Arc<Mutex<u32>>, Option<HashMap<String, u32>>) {
    if !Path::new(config_path).exists() {
        panic!(
            "[Orchestrator] Configuration file {} not found!",
            config_path
        );
    }

    let config_content = fs::read_to_string(config_path)
        .expect("[Orchestrator] Could not read the configuration file.");

    let mut hosts = HashMap::new();
    let mut used_ids = HashSet::new();

    for (i, line) in config_content.lines().enumerate() {
        let line_number = i + 1;

        let trimmed_line = line.trim();

        // Skip empty lines and comments
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }

        // Format: "hostname,id"
        let parts: Vec<&str> = trimmed_line.split(',').collect();
        if parts.len() != 2 {
            panic!(
                "[Orchestrator] Error on line {}: Malformed entry. Expected 'hostname,id', found '{}'",
                line_number, line
            );
        }

        let hostname = parts[0].trim().to_string();
        let id = match parts[1].trim().parse::<u32>() {
            Ok(val) => val,
            Err(_) => {
                panic!(
                    "[Orchestrator] Error on line {}: Invalid ID '{}'. ID must be a non-negative integer.",
                    line_number, parts[1].trim()
                );
            }
        };

        // Check for duplicate hostname before inserting.
        if hosts.contains_key(&hostname) {
            panic!(
                "[Orchestrator] Error on line {}: Duplicate hostname '{}' found. Hostnames must be unique.",
                line_number, hostname
            );
        }

        // Insert the ID (if it is not already used)
        if !used_ids.insert(id) {
            panic!(
                "[Orchestrator] Error on line {}: Duplicate ID '{}' found. IDs must be unique.",
                line_number, id
            );
        }
        
        // Avoid special worker IDs
        if id == ALL_WORKERS_INTERVAL || id == ALL_WORKERS_DIRECT || id == BREAK_SIGNAL {
            panic!(
                "[Orchestrator] Error on line {}: ID '{}' is reserved for special purposes. Please use a different ID.",
                line_number, id
            );
        }

        hosts.insert(hostname, id);
    }

    println!("[Orchestrator] {} hosts loaded.", hosts.len());

    // Current worker ID is the maximum ID + 1 in the configuration file
    let current_worker_id = hosts.values().max().map_or(1, |&max_id| max_id + 1);

    (Arc::new(Mutex::new(current_worker_id)), Some(hosts))
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
    Identity::from_pem(cert, key)
}
