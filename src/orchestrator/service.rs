use crate::custom_module::manycastr::controller_server::Controller;
use crate::custom_module::manycastr::{
    instruction, task, Ack, DiscoveryReply, Empty, Finished, Init, Instruction,
    LiveMeasurementMessage, Probe, Record, Reply, ReplyBatch, ScheduleMeasurement, Start, Task,
    TraceReply, Worker,
};
use crate::orchestrator::cli::CLIReceiver;
use crate::orchestrator::result_handler::{
    discovery_handler, trace_discovery_handler, trace_replies_handler,
};
use crate::orchestrator::task_distributor::{
    broadcast_distributor, round_robin_discovery, round_robin_distributor, task_sender,
    TaskDistributorConfig,
};
use crate::orchestrator::trace::check_trace_timeouts;
use crate::orchestrator::worker::WorkerStatus::{Disconnected, Idle, Listening, Probing};
use crate::orchestrator::worker::{WorkerReceiver, WorkerSender};
use crate::orchestrator::{ControllerService, MeasurementType, OngoingMeasurement};
use crate::{custom_module, ALL_WORKERS};
use futures_core::Stream;
use log::{error, info, warn};
use rand::Rng;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::spawn;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status, Streaming};

// Add the Enum import separately
use crate::custom_module::manycastr::reply::ReplyData;

/// Implementation of the Controller trait for the ControllerService
/// Handles communication with the workers and the CLI
#[tonic::async_trait]
impl Controller for ControllerService {
    /// Called by the worker when it has finished its current measurement.
    /// When all connected workers have finished this measurement, it will notify the CLI that the measurement is finished.
    ///
    /// # Arguments
    /// * `request` - a Finished message containing the measurement ID of the measurement that has finished
    ///
    /// # Errors
    /// Returns an error if the measurement ID is unknown.
    async fn measurement_finished(
        &self,
        request: Request<Finished>,
    ) -> Result<Response<Ack>, Status> {
        let finished_measurement = request.into_inner();
        let m_id: u32 = finished_measurement.m_id;
        let finished_worker_id = finished_measurement.worker_id;

        // Whether the measurement is finished
        let mut should_notify = false;

        {
            let mut lock = self.ongoing_measurement.write().unwrap();
            if let Some(ref mut measurement) = *lock {
                // Remove this worker from the probing workers list (if it was probing)
                measurement
                    .probing_workers
                    .retain(|&id| id != finished_worker_id);

                // Decrement the participating workers count
                measurement.workers_count -= 1;

                if measurement.workers_count == 0 {
                    info!(
                        "[Orchestrator] All workers finished for measurement {m_id}. Notifying CLI"
                    );
                    should_notify = true;

                    // Set the current measurement to None, allowing for a new measurement
                    *lock = None;
                }
            } else {
                warn!(
                "[Orchestrator] Received measurement finished signal for worker {finished_worker_id}, but no measurement is active."
            );
                return Err(Status::not_found("No active measurement found"));
            }
        }

        // Notify the CLI if this was the last worker
        if should_notify {
            let cli_tx = self.cli_sender.lock().unwrap().clone().unwrap();
            cli_tx
                .send(Ok(ReplyBatch::default()))
                .await
                .expect("Unable to send task result");
        }

        // Acknowledge the worker
        Ok(Response::new(Ack {
            is_success: true,
            error_message: "".to_string(),
        }))
    }

    type WorkerConnectStream = WorkerReceiver<Result<Instruction, Status>>;

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
        let worker = request.into_inner();
        let hostname = worker.hostname;
        let unicast_v4 = worker.unicast_v4;
        let unicast_v6 = worker.unicast_v6;
        let (tx, rx) = mpsc::channel::<Result<Instruction, Status>>(1000);
        // Get the worker ID, and check if it is a reconnection
        let (worker_id, is_reconnect) = self
            .get_worker_id(&hostname)
            .map_err(|boxed_status| *boxed_status)?;

        if is_reconnect {
            info!("[Orchestrator] Reconnecting worker: {hostname}");
            // TODO during an active measurement, we need to send the start message such that the worker can participate again
        } else {
            info!("[Orchestrator] New worker connected: {hostname}");
        }

        // Send worker ID
        tx.send(Ok(Instruction {
            instruction_type: Some(instruction::InstructionType::Init(Init { worker_id })),
        }))
        .await
        .expect("Unable to send task");

        let worker_status = Arc::new(Mutex::new(Idle));

        let worker_tx = WorkerSender {
            inner: tx,
            worker_id,
            hostname: hostname.clone(),
            status: worker_status.clone(),
            unicast_v4,
            unicast_v6,
        };

        // Remove the disconnected worker if it existed
        if is_reconnect {
            let mut senders = self.saved_workers.lock().unwrap();
            senders.retain(|sender| sender.worker_id != worker_id);
        }

        // Add the new worker sender to the list of workers
        self.saved_workers.lock().unwrap().push(worker_tx);

        // Create stream receiver for the worker
        let worker_rx = WorkerReceiver {
            inner: rx,
            ongoing_measurement: self.ongoing_measurement.clone(),
            cli_sender: self.cli_sender.clone(),
            hostname,
            status: worker_status,
            worker_id,
        };

        // Send the stream receiver to the worker
        Ok(Response::new(worker_rx))
    }

    type DoMeasurementStream = CLIReceiver<Result<ReplyBatch, Status>>;
    /// Handles the do_measurement command from the CLI.
    /// Instructs all workers to perform the measurement and returns the receiver side of a stream in which TaskResults will be streamed.
    /// Will lock active to true, such that no other measurement can start.
    /// Makes sure all workers are still connected, removes their senders if not.
    /// Assigns a unique ID to the measurement.
    /// Streams tasks to the workers, in a round-robin fashion, with 1-second delays between clients.
    /// Furthermore, lets the workers know of the desired probing rate (defined by the CLI).
    ///
    /// # Arguments
    /// * 'request' - a ScheduleMeasurement message containing information about the measurement that the CLI wants to perform
    ///
    /// # Errors
    /// Returns an error if there is already an active measurement, or if there are no connected workers to perform the measurement.
    async fn do_measurement(
        &self,
        request: Request<ScheduleMeasurement>,
    ) -> Result<Response<Self::DoMeasurementStream>, Status> {
        info!("[Orchestrator] Received CLI measurement request for measurement");
        let m_definition = request.into_inner();
        let is_responsive = m_definition.is_responsive;
        let is_latency = m_definition.is_latency;
        let is_verfploeter = m_definition.is_verfploeter;
        let worker_interval = m_definition.worker_interval as u64;
        let probe_interval = m_definition.probe_interval as u64;
        let number_of_probes = m_definition.number_of_probes as u8;
        let is_traceroute = m_definition.trace_options.is_some();
        let is_record = m_definition.is_record;
        let probing_rate = m_definition.probing_rate;
        let m_type = m_definition.m_type;
        let dst_addresses = m_definition.targets;
        let dns_record = m_definition.record;
        let info_url = m_definition.url;

        // Get participating (listening and/or probing) and probing workers
        let mut participating_worker_ids = Vec::new();
        let mut probing_worker_ids = Vec::new();
        let probing_workers_count;

        // Configure and get the senders
        let workers: Vec<WorkerSender<Result<Instruction, Status>>> = {
            let mut workers = self.saved_workers.lock().unwrap().clone();

            // Set the is_probing bool for each worker_tx
            for worker in workers.iter_mut() {
                let mut status_lock = worker.status.lock().unwrap();

                // Skip over disconnected workers
                if *status_lock == Disconnected {
                    warn!("[Orchestrator] Worker {} unavailable.", worker.hostname);
                    continue;
                }

                // Probing if any configuration is assigned to this worker
                let is_probing = m_definition.configurations.iter().any(|config| {
                    config.worker_id == worker.worker_id || config.worker_id == ALL_WORKERS
                });

                if is_probing {
                    *status_lock = Probing;
                    probing_worker_ids.push(worker.worker_id);
                    participating_worker_ids.push(worker.worker_id);
                } else {
                    // Listening if any worker is probing with anycast
                    let is_listening = m_definition.configurations.iter().any(|config| {
                        !config
                            .origin
                            .as_ref()
                            .and_then(|o| o.src.as_ref())
                            .is_none_or(|s| s.is_unicast())
                    });

                    if is_listening {
                        *status_lock = Listening;
                        participating_worker_ids.push(worker.worker_id);
                    } else {
                        *status_lock = Idle;
                    }
                };
            }

            workers
        };

        // If there are no connected workers that can perform this measurement
        if participating_worker_ids.is_empty() {
            error!("[Orchestrator] No connected workers available for this configuration.");
            return Err(Status::new(tonic::Code::Cancelled, "No connected workers"));
        }

        // Make sure no unknown workers are in the configuration
        if m_definition.configurations.iter().any(|conf| {
            conf.worker_id != ALL_WORKERS && !workers.iter().any(|w| w.worker_id == conf.worker_id)
        }) {
            error!("[Orchestrator] Configuration contains unknown worker IDs.");
            return Err(Status::new(
                tonic::Code::Cancelled,
                "Unknown worker in configuration",
            ));
        }

        // Initialize a new measurement
        {
            let mut measurement_lock = self.ongoing_measurement.write().unwrap();
            // Exit if we have an ongoing measurement
            if measurement_lock.is_some() {
                error!("[Orchestrator] There is already an active measurement, returning");
                return Err(Status::new(
                    tonic::Code::Cancelled,
                    "There is already an active measurement",
                ));
            }

            probing_workers_count = probing_worker_ids.len();
            *measurement_lock = Some(OngoingMeasurement {
                workers_count: participating_worker_ids.len() as u32,
                probing_workers: probing_worker_ids.clone(),
            });
        }

        // Get a random measurement ID
        let m_id = rand::rng().random_range(0..u32::MAX);

        let participating_workers_count = participating_worker_ids.len();

        info!("[Orchestrator] {participating_workers_count} participating workers, {probing_workers_count} will probe ({worker_interval} seconds between probing workers)");

        // Establish a stream with the CLI to return the TaskResults through
        let (tx, rx) = mpsc::channel::<Result<ReplyBatch, Status>>(1000);
        // Store the CLI sender
        let _ = self.cli_sender.lock().unwrap().insert(tx);

        // Create a list of origins used by workers
        let mut rx_origins = vec![];
        // Add all configuration origins to the listen origins
        for configuration in m_definition.configurations.iter() {
            if let Some(origin) = &configuration.origin {
                // Avoid duplicate origins
                if !rx_origins.contains(origin) {
                    rx_origins.push(*origin);
                }
            }
        }

        // Create channel for TaskDistributor (client_id, task, number_of_times)
        let (tx_t, rx_t) = mpsc::channel::<(u32, Instruction, bool)>(1000);

        // Notify all participating workers that a measurement is starting
        for worker in workers.iter() {
            if !worker.is_participating() {
                continue; // Skip non-participating workers
            }
            let worker_id = worker.worker_id;
            let mut tx_origins = vec![];

            // Add all configuration probing origins assigned to this worker
            for configuration in &m_definition.configurations {
                // If the worker is selected to perform the measurement (or all workers are selected (u32::MAX))
                if (configuration.worker_id == worker_id) | (configuration.worker_id == u32::MAX) {
                    if let Some(origin) = &configuration.origin {
                        tx_origins.push(*origin);
                    }
                }
            }

            let start_instruction = Instruction {
                instruction_type: Some(instruction::InstructionType::Start(Start {
                    rate: probing_rate,
                    m_id,
                    m_type,
                    tx_origins,
                    rx_origins: rx_origins.clone(),
                    record: dns_record.clone(),
                    url: info_url.clone(),
                    is_latency,
                    is_traceroute,
                    is_ipv6: m_definition.is_ipv6,
                    is_record,
                })),
            };

            tx_t.send((worker_id, start_instruction, false))
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

        if is_traceroute {
            // Start `TraceSession` timeout handler
            let stacks_clone = self.worker_stacks.clone();
            let tracker_clone = self.trace_session_tracker.clone();
            let ongoing_measurement = self.ongoing_measurement.clone();
            let trace_options = m_definition.trace_options;

            self.trace_max_hops
                .lock()
                .unwrap()
                .replace(trace_options.unwrap().max_hops);
            self.trace_timeout
                .lock()
                .unwrap()
                .replace(trace_options.unwrap().timeout as u64);
            self.inital_hop
                .lock()
                .unwrap()
                .replace(trace_options.unwrap().initial_hop);
            let cli_sender_clone = self.cli_sender.clone();

            std::thread::spawn(move || {
                check_trace_timeouts(
                    stacks_clone,
                    tracker_clone,
                    ongoing_measurement,
                    trace_options.unwrap().timeout as u64,
                    trace_options.unwrap().max_failures,
                    trace_options.unwrap().max_hops,
                    cli_sender_clone, // send '*' results
                );
            });

            self.m_type
                .lock()
                .unwrap()
                .replace(MeasurementType::Traceroute);
        } else if is_responsive {
            self.m_type
                .lock()
                .unwrap()
                .replace(MeasurementType::Responsive);
        } else if is_latency {
            self.m_type
                .lock()
                .unwrap()
                .replace(MeasurementType::Latency);
        } else {
            self.m_type.lock().unwrap().take(); // Set to None
        }

        let probing_rate_interval = if is_latency || is_verfploeter || is_traceroute {
            // We send a chunk every probing_rate / number_of_probing_workers seconds (as the probing is spread out over the workers)
            tokio::time::interval(Duration::from_secs(1) / probing_workers_count as u32)
        } else {
            // We send a chunk every second
            tokio::time::interval(Duration::from_secs(1))
        };

        // Convert dst_addresses into the appropriate TaskType
        let tasks = if is_record {
            // Send Reverse tasks
            dst_addresses
                .iter()
                .map(|addr| Task {
                    task_type: Some(task::TaskType::Record(Record { dst: Some(*addr) })),
                })
                .collect::<Vec<Task>>()
        } else if is_responsive || is_latency || is_traceroute {
            // Send Discovery tasks
            dst_addresses
                .iter()
                .map(|addr| Task {
                    task_type: Some(task::TaskType::Discovery(Probe { dst: Some(*addr) })),
                })
                .collect::<Vec<Task>>()
        } else {
            // Send Probe tasks
            dst_addresses
                .iter()
                .map(|addr| Task {
                    task_type: Some(task::TaskType::Probe(Probe { dst: Some(*addr) })),
                })
                .collect::<Vec<Task>>()
        };

        let task_config = TaskDistributorConfig {
            tasks,
            ongoing_measurement: self.ongoing_measurement.clone(),
            tx_t,
            probing_rate,
            probing_rate_interval,
            number_of_probing_workers: probing_workers_count,
            worker_interval,
        };

        // Spawn appropriate task distributor thread
        if is_verfploeter {
            // Distribute tasks round-robin
            round_robin_distributor(task_config).await;
        } else if is_responsive || is_latency || is_traceroute {
            // Distribute discovery tasks round-robin, handle follow-up tasks using the worker stacks
            round_robin_discovery(task_config, self.worker_stacks.clone(), is_responsive).await;
        } else {
            // Broadcast tasks to all workers (regular anycast, --unicast, --record measurements)
            broadcast_distributor(task_config).await;
        }

        let rx = CLIReceiver {
            inner: rx,
            ongoing_measurement: self.ongoing_measurement.clone(),
        };

        Ok(Response::new(rx))
    }

    // Live measurement stream type
    type LiveMeasurementStream =
        Pin<Box<dyn Stream<Item = Result<ReplyBatch, Status>> + Send + Sync + 'static>>;
    async fn live_measurement(
        &self,
        _request: Request<Streaming<LiveMeasurementMessage>>,
    ) -> Result<Response<Self::LiveMeasurementStream>, Status> {
        Err(Status::unimplemented("Not implemented"))
    }

    /// Handle the list_clients command from the CLI.
    ///
    /// Returns the connected clients.
    async fn list_workers(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<custom_module::manycastr::Status>, Status> {
        // Lock the workers list and clone it to return
        let workers_list = self.saved_workers.lock().unwrap();
        let mut workers = Vec::new();
        for worker in workers_list.iter() {
            workers.push(Worker {
                worker_id: worker.worker_id,
                hostname: worker.hostname.clone(),
                status: worker.get_status().clone(),
                unicast_v4: worker.unicast_v4,
                unicast_v6: worker.unicast_v6,
            });
        }

        let status = custom_module::manycastr::Status { workers };
        Ok(Response::new(status))
    }

    /// Receive a batch of results from a worker and put it in the stream towards the CLI.
    ///
    /// # Arguments
    /// * 'request' - a ReplyBatch containing results from a worker
    ///
    /// # Errors
    /// Returns an error if the CLI has disconnected.
    async fn send_result(&self, request: Request<ReplyBatch>) -> Result<Response<Ack>, Status> {
        // Send the result to the CLI through the established stream
        let task_result = request.into_inner();
        let catcher_id = task_result.rx_id;

        // Split replies into buckets
        let mut results_bucket: Vec<Reply> = Vec::new();
        let mut trace_bucket: Vec<TraceReply> = Vec::new();
        let mut discovery_bucket: Vec<DiscoveryReply> = Vec::new();

        for result_wrapper in task_result.results {
            match result_wrapper.reply_data {
                Some(ReplyData::Trace(t)) => {
                    trace_bucket.push(t);
                }
                Some(ReplyData::Discovery(d)) => {
                    discovery_bucket.push(d);
                }
                Some(inner_data) => {
                    results_bucket.push(Reply {
                        reply_data: Some(inner_data),
                    });
                }
                None => {}
            }
        }

        if !discovery_bucket.is_empty() {
            if *self.m_type.lock().unwrap() == Some(MeasurementType::Responsive) {
                // Perform follow-up tasks from all workers
                discovery_handler(
                    discovery_bucket,
                    ALL_WORKERS,
                    &mut self.worker_stacks.lock().unwrap(),
                );
            } else if *self.m_type.lock().unwrap() == Some(MeasurementType::Latency) {
                // Perform follow-up tasks from the catching worker
                discovery_handler(
                    discovery_bucket,
                    catcher_id,
                    &mut self.worker_stacks.lock().unwrap(),
                );
            } else if *self.m_type.lock().unwrap() == Some(MeasurementType::Traceroute) {
                println!("received discovery traceroute replies");
                // TODO change default probing rate for traceroute to a low value (avoid unintended spam of probes)
                trace_discovery_handler(
                    discovery_bucket,
                    catcher_id,
                    &mut self.worker_stacks.lock().unwrap(),
                    &mut self.trace_session_tracker.lock().unwrap(),
                    self.trace_timeout.lock().unwrap().unwrap(),
                    self.inital_hop.lock().unwrap().unwrap(),
                );
            } else {
                warn!("[Orchestrator] Received discovery results while not in responsive or latency mode");
            }
        }

        if !trace_bucket.is_empty() {
            println!("received non-discovery traceroute replies");
            // Handle traceroute replies (and target replies)
            trace_replies_handler(
                trace_bucket,
                &mut self.worker_stacks.lock().unwrap(),
                &mut self.trace_session_tracker.lock().unwrap(),
                self.trace_max_hops.lock().unwrap().unwrap(),
            );
            println!("handled traceroute replies");
        }

        if !results_bucket.is_empty() {
            // Forward results to the CLI
            let tx = {
                let sender = self.cli_sender.lock().unwrap();
                sender.clone().unwrap()
            };

            tx.send(Ok(ReplyBatch {
                rx_id: catcher_id,
                results: results_bucket,
            }))
            .await
            .expect("failed to send results to CLI");
        }

        Ok(Response::new(Ack {
            is_success: true,
            error_message: "".to_string(),
        }))
    }
}
