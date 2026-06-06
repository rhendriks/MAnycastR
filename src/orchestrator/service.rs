use crate::custom_module::manycastr::controller_server::Controller;
use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{
    instruction, Ack, DiscoveryReply, Empty, Finished, Init, Instruction, MeasurementType, Reply,
    ReplyBatch, ScheduleMeasurement, Start, TraceOptions, TraceReply, Worker,
};
use crate::orchestrator::cli::CLIReceiver;
use crate::orchestrator::result_handler::{
    discovery_handler, trace_discovery_handler, trace_replies_handler, SessionTracker,
};
use crate::orchestrator::task_distributor::{
    distribute_tasks, DistributionStrategy, TaskDistributorConfig,
};
use crate::orchestrator::trace::check_trace_timeouts;
use crate::orchestrator::worker::WorkerStatus::{Disconnected, Idle, Listening, Probing};
use crate::orchestrator::worker::{WorkerReceiver, WorkerSender};
use crate::orchestrator::{ControllerService, MeasurementState, TracerouteConfig};
use crate::{custom_module, ALL_ORIGINS, ALL_WORKERS};
use log::{error, info, warn};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

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
            let mut lock = self.measurement.write().unwrap();
            if let Some(ref mut state) = *lock {
                // Active measurement, remove this worker from the probing workers list (if it was probing)
                state
                    .probing_workers
                    .retain(|&id| id != finished_worker_id);

                // Decrement the participating workers count
                state.workers_count -= 1;

                // Set state to IDLE
                let workers = self.saved_workers.lock().unwrap();
                if let Some(w) = workers.iter().find(|w| w.worker_id == finished_worker_id) {
                    w.finished();
                }

                if state.workers_count == 0 {
                    // This is the last worker
                    info!(
                        "[Orchestrator] All workers finished for measurement {m_id}. Notifying CLI"
                    );
                    should_notify = true;

                    // Drop all measurement state at once
                    *lock = None;
                }
            } else {
                // Worker finished whilst there is no measurement active
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
    /// Ensures the hostname is unique and returns a unique worker ID
    /// Returns the receiver side of a stream to which the orchestrator will send tasks
    ///
    /// # Arguments
    /// * `request` - a Metadata message containing the hostname of the worker
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
            measurement: self.measurement.clone(),
            cli_sender: self.cli_sender.clone(),
            hostname,
            status: worker_status,
            worker_id,
        };

        // Send the stream receiver to the worker
        Ok(Response::new(worker_rx))
    }

    type DoMeasurementStream = CLIReceiver<Result<ReplyBatch, Status>>;

    /// Handles a measurement request from the CLI.
    ///
    /// Classifies workers, initializes measurement state, sends Start instructions to
    /// all participating workers, optionally sets up traceroute, and launches the task
    /// distributor. Returns a stream of results to the CLI.
    ///
    /// # Errors
    /// Returns an error if there is already an active measurement, if there are no
    /// connected workers, or if the configuration references unknown worker IDs.
    async fn do_measurement(
        &self,
        request: Request<ScheduleMeasurement>,
    ) -> Result<Response<Self::DoMeasurementStream>, Status> {
        info!("[Orchestrator] Received CLI measurement request for measurement");
        let mut m_def = request.into_inner();
        let is_responsive = m_def.is_responsive;
        let worker_interval = m_def.worker_interval as u64;
        let probe_interval = m_def.probe_interval as u64;
        let number_of_probes = m_def.number_of_probes as u8;
        let probing_rate = m_def.probing_rate;
        let m_type = m_def.m_type();

        // Classify workers and validate configuration
        let (workers, participating_ids, probing_ids) = self.classify_workers(&m_def)?;
        let probing_workers_count = probing_ids.len();

        // Initialize measurement state (errors if already active)
        self.init_measurement(&m_def, &participating_ids, &probing_ids)?;

        info!(
            "[Orchestrator] {} participating workers, {} will probe ({worker_interval} seconds between probing workers)",
            participating_ids.len(),
            probing_workers_count,
        );

        // Set up CLI result stream
        let (cli_tx, cli_rx) = mpsc::channel::<Result<ReplyBatch, Status>>(1000);
        let _ = self.cli_sender.lock().unwrap().insert(cli_tx);

        // Send Start instructions to all participating workers
        let m_id = rand::random_range(0..u32::MAX);
        send_start_instructions(&workers, &m_def, m_id).await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Initialize traceroute if applicable
        if let Some(trace_options) = m_def.trace_options.take() {
            self.setup_traceroute(trace_options);
        }

        // Determine distribution parameters
        let is_any_protocol = m_def.is_any_protocol;
        let send_discovery = is_responsive
            | matches!(
                m_type,
                MeasurementType::AnycastLatency | MeasurementType::AnycastTraceroute
            );
        let is_round_robin = send_discovery || (m_type == MeasurementType::Catchment);

        let probing_rate_interval = if is_round_robin {
            tokio::time::interval(Duration::from_secs(1) / probing_workers_count as u32)
        } else {
            tokio::time::interval(Duration::from_secs(1))
        };

        // Build ordered list of origin_ids for --any protocol fallback
        let origin_ids: Vec<u32> = if is_any_protocol {
            let mut seen = HashSet::new();
            let mut ids = Vec::new();
            for config in &m_def.configurations {
                if let Some(origin) = &config.origin {
                    if seen.insert(origin.origin_id) {
                        ids.push(origin.origin_id);
                    }
                }
            }
            ids
        } else {
            vec![]
        };
        let first_origin_id = if is_any_protocol {
            origin_ids[0]
        } else {
            ALL_ORIGINS
        };

        // Build config and launch task distribution
        let task_config = TaskDistributorConfig {
            hitlist: std::mem::take(&mut m_def.hitlist),
            is_discovery: send_discovery,
            first_origin_id,
            measurement: self.measurement.clone(),
            workers,
            probing_rate,
            probing_rate_interval,
            number_of_probing_workers: probing_workers_count,
            worker_interval,
            number_of_probes,
            probe_interval,
        };

        let strategy = if m_type == MeasurementType::Catchment {
            DistributionStrategy::RoundRobin
        } else if send_discovery {
            DistributionStrategy::Discovery {
                is_responsive,
                is_any_protocol,
                origin_ids,
            }
        } else {
            DistributionStrategy::Broadcast
        };

        distribute_tasks(task_config, strategy).await;

        //  Return CLI result stream
        Ok(Response::new(CLIReceiver {
            inner: cli_rx,
            measurement: self.measurement.clone(),
        }))
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
    /// * `request` - a ReplyBatch containing results from a worker
    ///
    /// # Errors
    /// Returns an error if the CLI has disconnected.
    async fn send_result(&self, request: Request<ReplyBatch>) -> Result<Response<Ack>, Status> {
        // Send the result to the CLI through the established stream
        let task_result = request.into_inner();
        let catcher_id = task_result.rx_id;
        let origin_id = task_result.origin_id;

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

        // Process discovery and traceroute replies under a single measurement lock
        if !discovery_bucket.is_empty() || !trace_bucket.is_empty() {
            let mut lock = self.measurement.write().unwrap();
            let state = lock
                .as_mut()
                .expect("[Orchestrator] Results received but no measurement is active");

            if !discovery_bucket.is_empty() {
                if state.is_any_protocol {
                    for reply in &discovery_bucket {
                        if let Some(addr) = reply.src {
                            state.resolved_targets.insert(addr);
                        }
                    }
                }

                match state.m_type {
                    // Perform follow-up from ALL workers
                    MeasurementType::Laces | MeasurementType::UnicastLatency => {
                        discovery_handler(
                            discovery_bucket,
                            ALL_WORKERS,
                            &mut state.worker_stacks,
                            origin_id,
                        );
                    }

                    // Follow up from only the catching worker
                    MeasurementType::AnycastLatency => {
                        discovery_handler(
                            discovery_bucket,
                            catcher_id,
                            &mut state.worker_stacks,
                            origin_id,
                        );
                    }

                    // Special handling for Traceroute
                    MeasurementType::AnycastTraceroute => {
                        if let Some(config) = state.trace_config.as_mut() {
                            trace_discovery_handler(
                                discovery_bucket,
                                catcher_id,
                                &mut state.worker_stacks,
                                config,
                                origin_id,
                            );
                        }
                    }

                    MeasurementType::Catchment => warn!(
                        "[Orchestrator] Received discovery results for Origin {origin_id}, from Worker {catcher_id}, for unsupported mode: {}",
                        state.m_type
                    ),
                }
            }

            if !trace_bucket.is_empty() {
                if let Some(config) = state.trace_config.as_mut() {
                    trace_replies_handler(
                        &trace_bucket,
                        &mut state.worker_stacks,
                        config,
                        origin_id,
                    );
                }

                // Add trace replies to the results bucket
                for t in trace_bucket {
                    results_bucket.push(Reply {
                        reply_data: Some(ReplyData::Trace(t)),
                    });
                }
            }
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
                origin_id,
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

impl ControllerService {
    /// Classify connected workers as probing, listening, or idle based on the measurement
    /// configuration. Validates that at least one worker can participate and that all
    /// configured worker IDs correspond to connected workers.
    ///
    /// Returns `(worker_senders, participating_worker_ids, probing_worker_ids)`.
    fn classify_workers(
        &self,
        m_def: &ScheduleMeasurement,
    ) -> Result<
        (
            Vec<WorkerSender<Result<Instruction, Status>>>,
            Vec<u32>,
            Vec<u32>,
        ),
        Status,
    > {
        let mut participating_worker_ids = Vec::new();
        let mut probing_worker_ids = Vec::new();

        // Whether non-probing workers should listen (true when any configuration probes with anycast).
        let has_anycast_origin = m_def.configurations.iter().any(|config| {
            !config
                .origin
                .as_ref()
                .and_then(|o| o.src.as_ref())
                .is_none_or(|s| s.is_unicast())
        });

        let workers = {
            let mut workers = self.saved_workers.lock().unwrap().clone();

            for worker in workers.iter_mut() {
                let mut status_lock = worker.status.lock().unwrap();

                // Skip disconnected workers
                if *status_lock == Disconnected {
                    warn!("[Orchestrator] Worker {} unavailable.", worker.hostname);
                    continue;
                }

                // Probing if any configuration is assigned to this worker
                let is_probing = m_def.configurations.iter().any(|config| {
                    config.worker_id == worker.worker_id || config.worker_id == ALL_WORKERS
                });

                if is_probing {
                    *status_lock = Probing;
                    probing_worker_ids.push(worker.worker_id);
                    participating_worker_ids.push(worker.worker_id);
                } else if has_anycast_origin {
                    *status_lock = Listening;
                    participating_worker_ids.push(worker.worker_id);
                } else {
                    *status_lock = Idle;
                };
            }

            workers
        };

        // Validate: at least one participating worker
        if participating_worker_ids.is_empty() {
            error!("[Orchestrator] No connected workers available for this configuration.");
            return Err(Status::new(tonic::Code::Cancelled, "No connected workers"));
        }

        // Validate: no unknown worker IDs in configuration
        if m_def.configurations.iter().any(|conf| {
            conf.worker_id != ALL_WORKERS
                && !workers.iter().any(|w| w.worker_id == conf.worker_id)
        }) {
            error!("[Orchestrator] Configuration contains unknown worker IDs.");
            return Err(Status::new(
                tonic::Code::Cancelled,
                "Unknown worker in configuration",
            ));
        }

        Ok((workers, participating_worker_ids, probing_worker_ids))
    }

    /// Initialize the shared measurement state. Errors if a measurement is already active.
    fn init_measurement(
        &self,
        m_def: &ScheduleMeasurement,
        participating_ids: &[u32],
        probing_ids: &[u32],
    ) -> Result<(), Status> {
        let mut lock = self.measurement.write().unwrap();
        if lock.is_some() {
            error!("[Orchestrator] There is already an active measurement, returning");
            return Err(Status::new(
                tonic::Code::Cancelled,
                "There is already an active measurement",
            ));
        }

        *lock = Some(MeasurementState {
            workers_count: participating_ids.len() as u32,
            probing_workers: probing_ids.to_vec(),
            m_type: m_def.m_type(),
            is_any_protocol: m_def.is_any_protocol,
            worker_stacks: HashMap::new(),
            trace_config: None,
            resolved_targets: HashSet::new(),
        });

        Ok(())
    }

    /// Initialize traceroute configuration within the measurement state and spawn the
    /// timeout handler thread that monitors active trace sessions.
    fn setup_traceroute(&self, trace_options: TraceOptions) {
        {
            let mut lock = self.measurement.write().unwrap();
            if let Some(ref mut state) = *lock {
                state.trace_config = Some(TracerouteConfig {
                    session_tracker: SessionTracker::new(),
                    timeout: trace_options.timeout as u64,
                    max_hops: trace_options.max_hops,
                    initial_hop: trace_options.initial_hop,
                    max_failures: trace_options.max_failures,
                    star_unresponsive: trace_options.star_unresponsive,
                });
            }
        }

        let measurement_clone = self.measurement.clone();
        let cli_sender_clone = self.cli_sender.clone();
        std::thread::spawn(move || {
            check_trace_timeouts(measurement_clone, cli_sender_clone);
        });
    }
}

/// Build and send Start instructions to all participating workers.
///
/// For each worker, constructs a per-worker Start instruction containing
/// its assigned TX origins and the shared RX origins, then sends it directly.
async fn send_start_instructions(
    workers: &[WorkerSender<Result<Instruction, Status>>],
    m_def: &ScheduleMeasurement,
    m_id: u32,
) {
    // Collect unique RX origins across all configurations
    let mut seen_origins = HashSet::new();
    let mut rx_origins = vec![];
    for configuration in m_def.configurations.iter() {
        if let Some(origin) = &configuration.origin {
            if seen_origins.insert(origin.origin_id) {
                rx_origins.push(*origin);
            }
        }
    }

    for worker in workers {
        if !worker.is_participating() {
            continue;
        }
        let worker_id = worker.worker_id;

        // Collect TX origins assigned to this specific worker
        let mut tx_origins = vec![];
        for configuration in &m_def.configurations {
            if configuration.worker_id == worker_id || configuration.worker_id == ALL_WORKERS {
                if let Some(origin) = &configuration.origin {
                    tx_origins.push(*origin);
                }
            }
        }

        let start_instruction = Instruction {
            instruction_type: Some(instruction::InstructionType::Start(Start {
                rate: m_def.probing_rate,
                m_id,
                tx_origins,
                rx_origins: rx_origins.clone(),
                record: m_def.record.clone(),
                url: m_def.url.clone(),
                is_ipv6: m_def.is_ipv6,
                is_record: m_def.is_record,
                m_type: m_def.m_type,
            })),
        };

        worker
            .send(Ok(start_instruction))
            .await
            .expect("Failed to send Start instruction to worker");
    }
}
