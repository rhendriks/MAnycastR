use crate::custom_module::has_anycast_origin;
use crate::custom_module::manycastr::WorkerStatus::{Disconnected, Idle, Listening, Probing};
use crate::custom_module::manycastr::controller_server::Controller;
use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{
    Ack, CliMessage, DiscoveryReply, Empty, Finished, Init, Instruction, LiveTarget,
    MeasurementType, Probe, Reply, ReplyBatch, ScheduleMeasurement, Start, Task, TraceOptions,
    TraceReply, Worker, WorkerStatus, cli_message, instruction, task,
};
use crate::orchestrator::cli::CLIReceiver;
use crate::orchestrator::result_handler::{
    SessionTracker, discovery_handler, trace_discovery_handler, trace_replies_handler,
};
use crate::orchestrator::task_distributor::{
    DistributionStrategy, TaskDistributorConfig, distribute_live_tasks, distribute_tasks,
};
use crate::orchestrator::trace::check_trace_timeouts;
use crate::orchestrator::worker::{WorkerReceiver, WorkerSender};
use crate::orchestrator::{
    ControllerService, LiveState, MeasurementHandle, MeasurementState, Participant,
    TracerouteConfig, WorkerRegistry, WorkerSel, wire_nprobes,
};
use crate::{ALL_ORIGINS, ALL_WORKERS, custom_module};
use log::{error, info, warn};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tonic::{Request, Response, Status};

/// Live feed buffer size, expressed in seconds of probing at the probing rate.
/// When the buffer is full the CLI stream is no longer read (blocking the feed).
const FEED_BUFFER_SECS: usize = 5;

/// Workers classified by role for a measurement.
struct ClassifiedWorkers {
    participating_ids: Vec<u32>,
    probing_ids: Vec<u32>,
}

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
                if state.m_id != m_id {
                    // A stale signal must not release a claim on the current measurement
                    warn!(
                        "[Orchestrator] Worker {finished_worker_id} finished measurement {m_id}, but the active measurement is {}",
                        state.m_id
                    );
                    return Err(Status::not_found("Measurement ID mismatch"));
                }

                // Remove worker as participant (disallowing reconnect for the current measurement)
                if state.participants.remove(&finished_worker_id).is_none() {
                    warn!(
                        "[Orchestrator] Received finished signal from non-participant worker {finished_worker_id}"
                    );
                    return Ok(Response::new(Ack::ok()));
                }
                state.start_instructions.remove(&finished_worker_id);
                state.probing_workers.retain(|&id| id != finished_worker_id);

                // Set state to IDLE
                {
                    let workers = self.saved_workers.lock().unwrap();
                    if let Some(w) = workers.iter().find(|w| w.worker_id == finished_worker_id) {
                        w.finished();
                    }
                }

                if state.active_workers() == 0 {
                    // This was the last worker still holding a completion claim
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
            let cli_tx = { self.cli_sender.lock().unwrap().clone() };
            if let Some(tx) = cli_tx
                && tx.send(Ok(ReplyBatch::default())).await.is_err()
            {
                warn!("[Orchestrator] CLI disconnected, cannot send measurement-finished signal.");
            }
        }

        // Acknowledge the worker
        Ok(Response::new(Ack::ok()))
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
        let (worker_id, is_reconnect) = self.get_worker_id(&hostname)?;

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
            inner: tx.clone(),
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

        // Check if this is a reconnecting worker
        if is_reconnect {
            self.try_rejoin(worker_id, &hostname, &tx, &worker_status);
        }

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
    /// connected workers, if the configuration references unknown worker IDs, if the
    /// probing rate exceeds the configured `--max_rate`, or if an origin is not
    /// allowed by this orchestrator (`--configs`).
    async fn do_measurement(
        &self,
        request: Request<ScheduleMeasurement>,
    ) -> Result<Response<Self::DoMeasurementStream>, Status> {
        info!("[Orchestrator] Received CLI measurement request for measurement");
        let mut m_def = request.into_inner();

        // Refuse start messages exceeding the rate limit or using disallowed origins
        self.validate_rate(m_def.probing_rate)?;
        self.validate_origins(&m_def)?;
        let worker_interval = m_def.worker_interval as u64;
        let probe_interval = m_def.probe_interval as u64;
        let nprobes = m_def.number_of_probes;
        let probing_rate = m_def.probing_rate;
        let m_type = m_def.m_type();

        // Feed measurements stream their targets over the live measurement RPC
        if m_type.is_feed() {
            return Err(Status::invalid_argument(
                "Feed measurements must use the live measurement stream",
            ));
        }

        // Classify workers and validate configuration
        let ClassifiedWorkers {
            participating_ids,
            probing_ids,
        } = self.classify_workers(&m_def)?;
        let probing_workers_count = probing_ids.len();
        let m_id = self.next_m_id();
        self.init_measurement(&m_def, m_id, &participating_ids, &probing_ids)?;

        info!(
            "[Orchestrator] {} participating workers, {} will probe ({worker_interval} seconds between probing workers)",
            participating_ids.len(),
            probing_workers_count,
        );

        // Set up CLI result stream
        let (cli_tx, cli_rx) = mpsc::channel::<Result<ReplyBatch, Status>>(1000);
        let _ = self.cli_sender.lock().unwrap().insert(cli_tx);

        // Send Start instructions to all participating workers
        send_start_instructions(&self.saved_workers, &self.measurement, &m_def, m_id).await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Initialize traceroute if applicable
        if let Some(trace_options) = m_def.trace_options.take() {
            // Tracemap seed probes must use a single origin TODO test traceroute/tracemap with multi-origins
            let trace_origin_id = m_def
                .configurations
                .first()
                .and_then(|c| c.origin)
                .map(|o| o.origin_id)
                .unwrap_or(ALL_ORIGINS);
            self.setup_traceroute(trace_options, trace_origin_id);
        }

        // The strategy determines task distribution, discovery usage, and pacing
        let strategy = DistributionStrategy::select(&m_def);

        // Round-robin strategies pace each worker at the full rate; Broadcast paces the batch
        let mut probing_rate_interval = if matches!(strategy, DistributionStrategy::Broadcast) {
            tokio::time::interval(Duration::from_secs(1))
        } else {
            tokio::time::interval(Duration::from_secs(1) / probing_workers_count as u32)
        };
        // Skip missed ticks instead of bursting to catch up after a stalled (backpressured) send
        probing_rate_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // Build config and launch task distribution
        let task_config = TaskDistributorConfig {
            m_id,
            hitlist: std::mem::take(&mut m_def.hitlist),
            measurement: self.measurement.clone(),
            workers: Arc::clone(&self.saved_workers),
            probing_rate,
            probing_rate_interval,
            number_of_probing_workers: probing_workers_count,
            worker_interval,
            nprobes,
            probe_interval,
            is_prefix_hitlist: m_def.is_prefix_hitlist,
        };

        distribute_tasks(task_config, strategy).await;

        //  Return CLI result stream
        Ok(Response::new(CLIReceiver {
            inner: cli_rx,
            measurement: self.measurement.clone(),
            workers: Arc::clone(&self.saved_workers),
            m_id,
        }))
    }

    type LiveMeasurementStream = CLIReceiver<Result<ReplyBatch, Status>>;

    /// Handles a live (feed-based) measurement request from the CLI.
    ///
    /// The first message on the stream must be the measurement definition;
    /// subsequent messages carry targets to probe.
    /// # Errors
    /// Returns an error if the first message is not a measurement definition, if the
    /// measurement type is not catchment, if the probing rate exceeds the configured
    /// `--max_rate`, if an origin is not allowed by this orchestrator, if there is
    /// already an active measurement, or if no workers can participate.
    async fn live_measurement(
        &self,
        request: Request<tonic::Streaming<CliMessage>>,
    ) -> Result<Response<Self::LiveMeasurementStream>, Status> {
        let mut inbound = request.into_inner();

        // The first message on the stream must be the measurement definition
        let m_def = match inbound.message().await? {
            Some(CliMessage {
                message: Some(cli_message::Message::Start(m_def)),
            }) => m_def,
            _ => {
                return Err(Status::invalid_argument(
                    "First message on a live stream must be the measurement definition",
                ));
            }
        };

        if !m_def.m_type().is_feed() {
            return Err(Status::invalid_argument(
                "Live measurements require a feed measurement type (-m feed or -m feed-trace)",
            ));
        }

        // Live mode requires every origin to be available on every probing worker
        let mut origin_workers: HashMap<u32, HashSet<u32>> = HashMap::new();
        for config in &m_def.configurations {
            if let Some(origin) = &config.origin {
                origin_workers
                    .entry(origin.origin_id)
                    .or_default()
                    .insert(config.worker_id);
            }
        }
        let all_assignments: HashSet<u32> =
            m_def.configurations.iter().map(|c| c.worker_id).collect();
        for (origin_id, assigned) in &origin_workers {
            if !assigned.contains(&ALL_WORKERS) && *assigned != all_assignments {
                return Err(Status::invalid_argument(format!(
                    "Live measurements require origins shared among all probing workers (origin {origin_id} is not)"
                )));
            }
        }

        // Refuse start messages exceeding the rate limit or using disallowed origins
        self.validate_rate(m_def.probing_rate)?;
        self.validate_origins(&m_def)?;
        let probing_rate = m_def.probing_rate;

        info!(
            "[Orchestrator] Received CLI live measurement request (rate {probing_rate} per worker)"
        );

        // Classify workers and validate configuration
        let ClassifiedWorkers {
            participating_ids,
            probing_ids,
        } = self.classify_workers(&m_def)?;
        let probing_workers_count = probing_ids.len();
        if probing_workers_count == 0 {
            return Err(Status::new(
                tonic::Code::Cancelled,
                "No probing workers available",
            ));
        }

        // Initialize measurement state (errors if already active)
        let m_id = self.next_m_id();
        self.init_measurement(&m_def, m_id, &participating_ids, &probing_ids)?;

        if let Some(state) = self.measurement.write().unwrap().as_mut() {
            state.live = Some(LiveState {
                pending: HashMap::new(),
                set_stacks: HashMap::new(),
                trace_targets: HashMap::new(),
            });
        }

        // Sweep timed-out discovery targets
        self.spawn_discovery_sweeper();

        info!(
            "[Orchestrator] {} participating workers, {} will probe",
            participating_ids.len(),
            probing_workers_count,
        );

        // Set up CLI result stream
        let (cli_tx, cli_rx) = mpsc::channel::<Result<ReplyBatch, Status>>(1000);
        let _ = self.cli_sender.lock().unwrap().insert(cli_tx);

        // Send Start instructions to all participating workers
        send_start_instructions(&self.saved_workers, &self.measurement, &m_def, m_id).await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Rate-limiting: when full, the orchestrator stops reading the CLI stream
        let capacity = (probing_rate as usize * FEED_BUFFER_SECS).max(1000);
        let (feed_tx, feed_rx) = mpsc::channel::<LiveTarget>(capacity);

        // Forward targets into the task distributor until the CLI closes its stream
        tokio::spawn(async move {
            loop {
                match inbound.message().await {
                    Ok(Some(CliMessage {
                        message: Some(cli_message::Message::Targets(batch)),
                    })) => {
                        for target in batch.targets {
                            if feed_tx.send(target).await.is_err() {
                                return; // Distributor is gone (measurement ended)
                            }
                        }
                    }
                    Ok(Some(_)) => {
                        warn!("[Orchestrator] Ignoring unexpected message on live stream");
                    }
                    Ok(None) => return, // CLI closed its stream
                    Err(e) => {
                        warn!("[Orchestrator] Live stream error: {e}");
                        return;
                    }
                }
            }
        });

        distribute_live_tasks(
            feed_rx,
            self.measurement.clone(),
            Arc::clone(&self.saved_workers),
            &m_def,
            m_id,
        );

        // Return CLI result stream
        Ok(Response::new(CLIReceiver {
            inner: cli_rx,
            measurement: self.measurement.clone(),
            workers: Arc::clone(&self.saved_workers),
            m_id,
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
                status: worker.get_status() as i32,
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

        // Process discovery and traceroute replies
        if !discovery_bucket.is_empty() || !trace_bucket.is_empty() {
            let mut lock = self.measurement.write().unwrap();
            let Some(state) = lock.as_mut() else {
                // Discard late results arrived after the measurement was torn down
                warn!(
                    "[Orchestrator] Dropping {} late replies from worker {catcher_id} (no active measurement)",
                    discovery_bucket.len() + trace_bucket.len()
                );
                return Ok(Response::new(Ack::ok()));
            };

            // Create a follow-up task for a discovery reply
            if let Some(live) = state.live.as_mut() {
                for reply in discovery_bucket.drain(..) {
                    let Some(src) = reply.src else { continue };
                    let Some((session_id, pending)) = live.remove_pending(src, reply.session_id)
                    else {
                        continue; // Unknown target or duplicate reply
                    };

                    // Create the follow-up task
                    let task = Task {
                        task_type: Some(task::TaskType::Probe(Probe { dst: Some(src) })),
                        origin_id,
                        nprobes: wire_nprobes(pending.nprobes), // repeat nprobes times
                        session_id,
                    };
                    match pending.worker_sel {
                        // Any-worker follow-ups are performed by the discovery worker
                        WorkerSel::Any => state
                            .worker_stacks
                            .entry(pending.discovery_worker)
                            .or_default()
                            .push_back(task),
                        WorkerSel::All => state
                            .worker_stacks
                            .entry(ALL_WORKERS)
                            .or_default()
                            .push_back(task),
                        // Worker-set follow-ups are staggered by the live distributor
                        WorkerSel::Set(worker_ids) => live
                            .set_stacks
                            .entry(worker_ids)
                            .or_default()
                            .push_back(task),
                    }
                }
            }

            // Drop duplicate discovery replies (e.g., multi-reply targets)
            discovery_bucket.retain(|reply| match reply.src {
                Some(addr) if state.is_prefix_hitlist => {
                    // For ISI hitlist probing, resolve targets at prefix granularity
                    state.resolved_targets.insert(addr.prefix_base())
                }
                Some(addr) => state.resolved_targets.insert(addr),
                None => false,
            });

            if !discovery_bucket.is_empty() {
                match state.m_type {
                    // Determine worker(s) for follow-up probes
                    MeasurementType::Laces | MeasurementType::AnycastLatency => {
                        let follow_up_id = if state.is_responsive {
                            ALL_WORKERS
                        } else {
                            catcher_id
                        };
                        discovery_handler(
                            discovery_bucket,
                            follow_up_id,
                            &mut state.worker_stacks,
                            origin_id,
                            state.nprobes,
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

                    MeasurementType::Catchment
                    | MeasurementType::Tracemap
                    | MeasurementType::Feed
                    | MeasurementType::FeedTrace => warn!(
                        "[Orchestrator] Received discovery results for Origin {origin_id}, from Worker {catcher_id}, for unsupported mode: {}",
                        state.m_type
                    ),
                }
            }

            if !trace_bucket.is_empty() {
                if let Some(config) = state.trace_config.as_mut() {
                    // Only forward trace replies that matched an active trace session
                    let matched_replies = trace_replies_handler(
                        trace_bucket,
                        &mut state.worker_stacks,
                        config,
                        origin_id,
                    );

                    for t in matched_replies {
                        results_bucket.push(Reply {
                            reply_data: Some(ReplyData::Trace(t)),
                        });
                    }
                } else if state.m_type == MeasurementType::FeedTrace {
                    // Check there is a matching trace target for the received reply
                    let now = std::time::Instant::now();
                    if let Some(live) = state.live.as_ref() {
                        for t in trace_bucket {
                            let is_probed_target = t.trace_dst.is_some_and(|dst| {
                                live.trace_targets
                                    .get(&dst)
                                    .is_some_and(|deadline| *deadline > now)
                            });
                            if is_probed_target && state.participants.contains_key(&t.tx_id) {
                                results_bucket.push(Reply {
                                    reply_data: Some(ReplyData::Trace(t)),
                                });
                            }
                        }
                    }
                }
            }
        }

        if !results_bucket.is_empty() {
            // Whether this is a --responsive catchment mapping for multi-prefix targets
            let is_prefix_catchment = {
                let lock = self.measurement.read().unwrap();
                matches!(*lock, Some(ref state) if state.is_prefix_hitlist && state.m_type == MeasurementType::Catchment)
            };
            if is_prefix_catchment {
                // Keep track of resolved prefixes
                let mut lock = self.measurement.write().unwrap();
                if let Some(state) = lock.as_mut() {
                    for reply in &results_bucket {
                        if let Some(ReplyData::Measurement(m)) = &reply.reply_data
                            && let Some(src) = m.src
                        {
                            state.resolved_targets.insert(src.prefix_base());
                        }
                    }
                }
            }
        }

        if !results_bucket.is_empty() {
            // Forward results to the CLI
            let tx = self.cli_sender.lock().unwrap().clone();

            if let Some(tx) = tx
                && tx
                    .send(Ok(ReplyBatch {
                        rx_id: catcher_id,
                        results: results_bucket,
                        origin_id,
                    }))
                    .await
                    .is_err()
            {
                warn!("[Orchestrator] CLI disconnected, dropping result batch.");
            }
        }

        Ok(Response::new(Ack::ok()))
    }
}

impl ControllerService {
    /// Validate a requested probing rate against the orchestrator's configured
    /// maximum (`--max_rate`).
    ///
    /// # Errors
    /// Returns an error naming the requested and maximum rate.
    fn validate_rate(&self, probing_rate: u32) -> Result<(), Status> {
        let Some(max_rate) = self.max_rate else {
            return Ok(()); // No rate limit configured
        };
        if probing_rate > max_rate {
            warn!(
                "[Orchestrator] Refusing measurement: probing rate {probing_rate} exceeds the configured maximum of {max_rate}"
            );
            return Err(Status::invalid_argument(format!(
                "Probing rate {probing_rate} exceeds this orchestrator's maximum rate of {max_rate} (probes per second, per worker)"
            )));
        }
        Ok(())
    }

    /// Validate the origins of a measurement definition against the orchestrator's
    /// origin allow-list (`--origins`). Without an allow-list, every origin is allowed.
    ///
    /// An origin is allowed when a rule matches its source address and permits its protocol.
    ///
    /// # Errors
    /// Returns an error naming the refused origin and listing the available origins.
    fn validate_origins(&self, m_def: &ScheduleMeasurement) -> Result<(), Status> {
        let Some(allowed_origins) = &self.allowed_origins else {
            return Ok(()); // No allow-list configured
        };

        for origin in m_def
            .configurations
            .iter()
            .filter_map(|c| c.origin.as_ref())
        {
            let Some(src) = &origin.src else { continue };
            let p_type = origin.p_type();

            if allowed_origins
                .iter()
                .any(|rule| rule.src == *src && rule.allows(p_type))
            {
                continue;
            }

            // Distinguish an unavailable address from a disallowed protocol
            let reason = if allowed_origins.iter().any(|rule| rule.src == *src) {
                format!(
                    "protocol {} is not allowed for source address {src}",
                    p_type.as_str()
                )
            } else {
                format!("source address {src} is not available")
            };
            warn!("[Orchestrator] Refusing measurement: {reason}");

            let available: Vec<String> = allowed_origins
                .iter()
                .map(|rule| rule.to_string())
                .collect();
            return Err(Status::permission_denied(format!(
                "Origin not allowed by this orchestrator: {reason}. Available origins: {}",
                available.join(", ")
            )));
        }

        Ok(())
    }

    /// Classify connected workers as probing, listening, or idle based on the measurement
    /// configuration. Validates that at least one worker can participate and that all
    /// configured worker IDs correspond to connected workers.
    ///
    /// Returns the worker senders plus the participating and probing worker ID lists.
    fn classify_workers(&self, m_def: &ScheduleMeasurement) -> Result<ClassifiedWorkers, Status> {
        let mut participating_worker_ids = Vec::new();
        let mut probing_worker_ids = Vec::new();

        // Whether non-probing workers should listen (true when any configuration probes with anycast).
        let is_anycast = has_anycast_origin(&m_def.configurations);

        let workers = self.saved_workers.lock().unwrap();

        for worker in workers.iter() {
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
            } else if is_anycast {
                *status_lock = Listening;
                participating_worker_ids.push(worker.worker_id);
            } else {
                *status_lock = Idle;
            };
        }

        // Validate: at least one participating worker
        if participating_worker_ids.is_empty() {
            error!("[Orchestrator] No connected workers available for this configuration.");
            return Err(Status::new(tonic::Code::Cancelled, "No connected workers"));
        }

        // Validate: no unknown worker IDs in configuration
        if m_def.configurations.iter().any(|conf| {
            conf.worker_id != ALL_WORKERS && !workers.iter().any(|w| w.worker_id == conf.worker_id)
        }) {
            error!("[Orchestrator] Configuration contains unknown worker IDs.");
            return Err(Status::new(
                tonic::Code::Cancelled,
                "Unknown worker in configuration",
            ));
        }

        Ok(ClassifiedWorkers {
            participating_ids: participating_worker_ids,
            probing_ids: probing_worker_ids,
        })
    }

    /// Re-admit a reconnecting worker into the active measurement, if it was participating.
    ///
    /// Sends the Start instruction for the worker, and restores it for the task distributor.
    ///
    /// Rejoin is refused if the measurement is finalizing.
    fn try_rejoin(
        &self,
        worker_id: u32,
        hostname: &str,
        tx: &mpsc::Sender<Result<Instruction, Status>>,
        status: &Arc<Mutex<WorkerStatus>>,
    ) {
        let mut lock = self.measurement.write().unwrap();
        let Some(state) = lock.as_mut() else {
            return; // No active measurement
        };
        if !state.participants.contains_key(&worker_id) {
            return; // Not a participant of the measurement
        }
        if state.is_finalizing {
            return; // Measurement being finished
        }
        let Some(start) = state.start_instructions.get(&worker_id) else {
            return; // Should not happen
        };

        // Send the Start instruction to the reconnecting worker
        let start_instruction = Instruction {
            instruction_type: Some(instruction::InstructionType::Start(start.clone())),
        };
        if tx.try_send(Ok(start_instruction)).is_err() {
            // TODO implement try_send function with warn printing
            warn!(
                "[Orchestrator] Could not queue Start instruction for rejoining worker {hostname}"
            );
            return;
        }

        // Restore the worker's role, probing slot for the distributor, and completion claim
        let role = state.participants[&worker_id].role;
        *status.lock().unwrap() = role;
        if role == Probing && !state.probing_workers.contains(&worker_id) {
            state.probing_workers.push(worker_id);
        }
        // Ensure the measurement waits for this worker when finalizing
        if let Some(participant) = state.participants.get_mut(&worker_id) {
            participant.is_counted = true;
        }

        info!(
            "[Orchestrator] Worker {hostname} rejoined measurement {} ({})",
            state.m_id,
            role.as_str_name()
        );
    }

    /// Initialize the shared measurement state. Errors if a measurement is already active.
    fn init_measurement(
        &self,
        m_def: &ScheduleMeasurement,
        m_id: u32,
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

        // Each participant starts with a claim on measurement completion
        let participants = participating_ids
            .iter()
            .map(|&id| {
                let role = if probing_ids.contains(&id) {
                    Probing
                } else {
                    Listening
                };
                (
                    id,
                    Participant {
                        role,
                        is_counted: true,
                    },
                )
            })
            .collect();

        *lock = Some(MeasurementState {
            m_id,
            probing_workers: probing_ids.to_vec(),
            participants,
            start_instructions: HashMap::new(),
            is_finalizing: false,
            m_type: m_def.m_type(),
            is_responsive: m_def.is_responsive,
            is_prefix_hitlist: m_def.is_prefix_hitlist,
            nprobes: m_def.number_of_probes,
            worker_stacks: HashMap::new(),
            trace_config: None,
            resolved_targets: HashSet::new(),
            live: None,
        });

        Ok(())
    }

    /// Spawn the discovery-timeout sweeper for a live measurement.
    ///
    /// Every second, expired pending discovery targets are dropped as unresponsive.
    /// The sweeper exits when the measurement ends.
    fn spawn_discovery_sweeper(&self) {
        let measurement = self.measurement.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;

                let mut lock = measurement.write().unwrap();
                let Some(state) = lock.as_mut() else {
                    break; // Measurement ended
                };
                let Some(live) = state.live.as_mut() else {
                    break;
                };

                let now = Instant::now();
                live.pending.retain(|_, pending| pending.deadline > now);
            }
        });
    }

    /// Initialize traceroute configuration within the measurement state and spawn the
    /// timeout handler thread that monitors active trace sessions.
    fn setup_traceroute(&self, trace_options: TraceOptions, origin_id: u32) {
        {
            let mut lock = self.measurement.write().unwrap();
            if let Some(ref mut state) = *lock {
                state.trace_config = Some(TracerouteConfig {
                    session_tracker: SessionTracker::new(),
                    origin_id,
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

/// Builds Start instruction for all participating workers.
/// Sends them for measurement init, and persists them for re-joining workers.
async fn send_start_instructions(
    workers: &WorkerRegistry,
    measurement: &MeasurementHandle,
    m_def: &ScheduleMeasurement,
    m_id: u32,
) {
    // Collect unique anycast RX origins across all configurations
    let mut seen_origins = HashSet::new();
    let mut anycast_rx_origins = vec![];
    for configuration in m_def.configurations.iter() {
        if let Some(origin) = &configuration.origin
            && !origin.is_unicast()
            && seen_origins.insert(origin.origin_id)
        {
            anycast_rx_origins.push(*origin);
        }
    }

    // Get current workers connected at measurement start
    let participants: Vec<_> = workers
        .lock()
        .unwrap()
        .iter()
        .filter(|w| w.is_participating())
        .cloned()
        .collect();

    for worker in participants {
        let worker_id = worker.worker_id;

        // Collect TX origins assigned to this specific worker
        let mut tx_origins = vec![];
        for configuration in &m_def.configurations {
            if (configuration.worker_id == worker_id || configuration.worker_id == ALL_WORKERS)
                && let Some(origin) = &configuration.origin
            {
                tx_origins.push(*origin);
            }
        }

        // This worker listens on all anycast origins plus its own unicast TX origins
        let mut rx_origins = anycast_rx_origins.clone();
        rx_origins.extend(tx_origins.iter().filter(|o| o.is_unicast()).copied());

        let start = Start {
            rate: m_def.probing_rate,
            m_id,
            tx_origins,
            rx_origins,
            record: m_def.record.clone(),
            url: m_def.url.clone(),
            m_type: m_def.m_type,
            probe_interval: m_def.probe_interval,
        };

        // Persist the Start instruction for re-sending on rejoin
        if let Some(state) = measurement.write().unwrap().as_mut() {
            state.start_instructions.insert(worker_id, start.clone());
        }

        let start_instruction = Instruction {
            instruction_type: Some(instruction::InstructionType::Start(start)),
        };

        worker
            .send(Ok(start_instruction))
            .await
            .expect("Failed to send Start instruction to worker");
    }
}
