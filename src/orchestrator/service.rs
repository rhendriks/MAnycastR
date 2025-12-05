use crate::custom_module::manycastr::controller_server::Controller;
use crate::custom_module::manycastr::{
    instruction, task, Ack, Empty, Finished, Init, Instruction, LiveMeasurementMessage, Probe,
    Record, ScheduleMeasurement, Start, Task, TaskResult, Worker,
};
use crate::orchestrator::cli::CLIReceiver;
use crate::orchestrator::result_handler::{check_trace_timeouts, responsive_handler, symmetric_handler, trace_discovery_handler, trace_replies_handler};
use crate::orchestrator::task_distributor::{
    broadcast_distributor, round_robin_discovery, round_robin_distributor, task_sender,
    TaskDistributorConfig,
};
use crate::orchestrator::worker::WorkerStatus::{Disconnected, Idle, Listening, Probing};
use crate::orchestrator::worker::{WorkerReceiver, WorkerSender};
use crate::orchestrator::{ControllerService, MeasurementType};
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
        let m_id: u32 = finished_measurement.m_id;
        let cli_tx = self.cli_sender.lock().unwrap().clone().unwrap();

        // Decrement the number of active workers
        let mut should_notify = false;
        {
            let mut active_workers = self.active_workers.lock().unwrap();

            if let Some(remaining) = active_workers.as_mut() {
                if *remaining == 1 {
                    info!("[Orchestrator] All workers finished.. Notifying CLI");
                    active_workers.take(); // reset to None
                    should_notify = true;
                } else {
                    *remaining -= 1;
                }
            } else {
                warn!("[Orchestrator] Received measurement finished signal for non-existent measurement {m_id}"
            );
            }
        }

        // Notify the CLI if this was the last worker
        if should_notify {
            cli_tx
                .send(Ok(TaskResult::default()))
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
            let mut senders = self.workers.lock().unwrap();
            senders.retain(|sender| sender.worker_id != worker_id);
        }

        // Add the new worker sender to the list of workers
        self.workers.lock().unwrap().push(worker_tx);

        // Create stream receiver for the worker
        let worker_rx = WorkerReceiver {
            inner: rx,
            active_workers: self.active_workers.clone(),
            cli_sender: self.cli_sender.clone(),
            hostname,
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
        info!("[Orchestrator] Received CLI measurement request for measurement");

        {
            let mut active_workers = self.active_workers.lock().unwrap();
            // If there already is an active measurement, we skip
            if active_workers.is_some() {
                error!("[Orchestrator] There is already an active measurement, returning");
                return Err(Status::new(
                    tonic::Code::Cancelled,
                    "There is already an active measurement",
                ));
            }

            // Set to Some(0) to indicate that a measurement is starting
            active_workers.replace(0);
        }

        // The measurement that the CLI wants to perform
        let m_definition = request.into_inner();
        let is_responsive = m_definition.is_responsive;
        let is_latency = m_definition.is_latency;
        let is_divide = m_definition.is_divide;
        let worker_interval = m_definition.worker_interval as u64;
        let probe_interval = m_definition.probe_interval as u64;
        let number_of_probes = m_definition.number_of_probes as u8;
        let is_traceroute = m_definition.is_traceroute;
        let is_record = m_definition.is_record;
        let is_tracemap = m_definition.is_tracemap;

        // Configure and get the senders
        let workers: Vec<WorkerSender<Result<Instruction, Status>>> = {
            let mut workers = self.workers.lock().unwrap().clone();
            // Only keep connected workers
            workers.retain(|worker| {
                if *worker.status.lock().unwrap() == Disconnected {
                    warn!("[Orchestrator] Worker {} unavailable.", worker.hostname);
                    false
                } else {
                    true
                }
            });

            // Make sure no unknown workers are in the configuration
            if m_definition.configurations.iter().any(|conf| {
                !workers
                    .iter()
                    .any(|sender| sender.worker_id == conf.worker_id)
                    && conf.worker_id != ALL_WORKERS
            }) {
                error!(
                    "[Orchestrator] Unknown worker in configuration list, terminating measurement."
                );
                self.active_workers.lock().unwrap().take(); // Set to None
                return Err(Status::new(
                    tonic::Code::Cancelled,
                    "Unknown worker in configuration",
                ));
            }

            // Set the is_probing bool for each worker_tx
            for worker in workers.iter_mut() {
                // Probing if any configuration is assigned to this worker (or all workers u32::MAX)
                let is_probing = m_definition.configurations.iter().any(|config| {
                    config.worker_id == worker.worker_id || config.worker_id == u32::MAX
                });

                if is_probing {
                    *worker.status.lock().unwrap() = Probing;
                } else {
                    // Listening if any worker is probing with anycast
                    let is_listening = m_definition
                        .configurations
                        .iter()
                        .any(|config| !config.origin.unwrap().src.unwrap().is_unicast());
                    if is_listening {
                        *worker.status.lock().unwrap() = Listening;
                    } else {
                        *worker.status.lock().unwrap() = Idle;
                    }
                };
            }

            workers
        };

        // If there are no connected workers that can perform this measurement
        if workers.is_empty() {
            error!("[Orchestrator] No connected workers, terminating measurement.");
            self.active_workers.lock().unwrap().take(); // Set to None
            return Err(Status::new(tonic::Code::Cancelled, "No connected workers"));
        }

        // Get a random measurement ID
        let m_id = rand::rng().random_range(0..u32::MAX);

        let number_of_probing_workers = workers.iter().filter(|sender| sender.is_probing()).count();
        let number_of_active_workers = workers
            .iter()
            .filter(|sender| sender.is_participating())
            .count() as u32;

        // Store the number of workers that will perform this measurement
        self.active_workers
            .lock()
            .unwrap()
            .replace(number_of_active_workers);

        let probing_rate = m_definition.probing_rate;
        let m_type = m_definition.m_type;
        let dst_addresses = m_definition.targets;
        let dns_record = m_definition.record;
        let info_url = m_definition.url;

        info!("[Orchestrator] {number_of_active_workers} participating workers, {number_of_probing_workers} will probe ({worker_interval} seconds between probing workers)");

        // Establish a stream with the CLI to return the TaskResults through
        let (tx, rx) = mpsc::channel::<Result<TaskResult, Status>>(1000);
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

        // Create a cycler of active probing workers (containing their IDs)
        let probing_worker_ids = workers
            .iter()
            .filter(|sender| sender.is_probing())
            .map(|sender| sender.worker_id)
            .collect::<Vec<u32>>();

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
                    is_tracemap,
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
            check_trace_timeouts(
                self.worker_stacks.clone(),
                self.trace_session_tracker.clone(),
            );

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

        let probing_rate_interval = if is_latency || is_divide {
            // We send a chunk every probing_rate / number_of_probing_workers seconds (as the probing is spread out over the workers)
            tokio::time::interval(Duration::from_secs(1) / number_of_probing_workers as u32)
        } else {
            // We send a chunk every second
            tokio::time::interval(Duration::from_secs(1))
        };

        let active_workers = self.active_workers.clone();

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
            active_workers,
            tx_t,
            probing_rate,
            probing_rate_interval,
            number_of_probing_workers,
            worker_interval,
        };

        // Spawn appropriate task distributor thread
        if is_divide {
            // Distribute tasks round-robin
            round_robin_distributor(task_config, probing_worker_ids).await;
        } else if is_responsive || is_latency || is_traceroute {
            // Distribute discovery tasks round-robin, handle follow-up tasks using the worker stacks
            round_robin_discovery(
                task_config,
                self.worker_stacks.clone(),
                probing_worker_ids,
                is_responsive,
            )
            .await;
        } else {
            // Broadcast tasks to all workers (regular anycast, --unicast, --record measurements)
            broadcast_distributor(task_config).await;
        }

        let rx = CLIReceiver {
            inner: rx,
            active_workers: self.active_workers.clone(),
        };

        Ok(Response::new(rx))
    }

    // Live measurement stream type
    type LiveMeasurementStream =
        Pin<Box<dyn Stream<Item = Result<TaskResult, Status>> + Send + Sync + 'static>>;
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
        let workers_list = self.workers.lock().unwrap();
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

        let status = crate::custom_module::manycastr::Status { workers };
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
        let task_result = request.into_inner();
        let is_discovery = task_result.is_discovery;

        // if self.r_prober is not None and equals this task's worker_id
        if is_discovery {
            // Sleep 1 second to avoid rate-limiting issues
            tokio::time::sleep(Duration::from_secs(1)).await;
            if *self.m_type.lock().unwrap() == Some(MeasurementType::Responsive) {
                return responsive_handler(task_result, &mut self.worker_stacks.lock().unwrap());
            } else if *self.m_type.lock().unwrap() == Some(MeasurementType::Latency) {
                return symmetric_handler(task_result, &mut self.worker_stacks.lock().unwrap());
            } else if *self.m_type.lock().unwrap() == Some(MeasurementType::Traceroute) {
                // TODO start pub fn check_trace_timeouts( as thread when starting a traceroute measurement
                // TODO change default probing rate for traceroute to a low value (avoid unintended spam of probes)
                trace_discovery_handler(&task_result, &mut self.worker_stacks.lock().unwrap());
                // Continue to forward the result to the CLI as well
            } else {
                warn!("[Orchestrator] Received discovery results while not in responsive or latency mode");
            }
        } else if *self.m_type.lock().unwrap() == Some(MeasurementType::Traceroute) {
            // Handle traceroute replies (and target replies) TODO
            trace_replies_handler();
        }

        // Default case: just forward the result to the CLI
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
