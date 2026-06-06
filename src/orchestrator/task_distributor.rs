use crate::custom_module::manycastr::{instruction, End, Instruction, Probe, Task, Tasks};
use crate::orchestrator::worker::WorkerSender;
use crate::orchestrator::worker::WorkerStatus::Probing;
use crate::orchestrator::{MeasurementHandle, ALL_WORKERS_END, BREAK_SIGNAL};
use crate::ALL_WORKERS;
use log::{info, warn};
use std::time::Duration;
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::time::{Instant, Interval};
use tonic::Status;

/// How tasks should be distributed to workers
pub enum DistributionStrategy {
    /// Broadcast tasks to all probing workers simultaneously (LACeS, and unicast mode)
    Broadcast,
    /// Send tasks to probing workers in round-robin fashion (catchment mode)
    RoundRobin,
    /// Send discovery tasks round-robin, with follow-up task interleaving (latency, traceroute, responsive modes)
    Discovery {
        /// --responsive sends follow-ups to ALL workers; otherwise to the catching worker
        is_responsive: bool,
        /// --any protocol fallback mode
        is_any_protocol: bool,
        /// Ordered origin IDs for --any fallback
        origin_ids: Vec<u32>,
    },
}

pub struct TaskDistributorConfig {
    /// Vector of tasks to distribute
    pub tasks: Vec<Task>,
    /// All per-measurement state. `None` when idle.
    pub measurement: MeasurementHandle,
    /// Channel to send tasks to the TaskDistributor
    pub tx_t: Sender<(u32, Instruction, bool)>,
    /// Number of tasks to send per interval (equal to probing rate)
    pub probing_rate: u32,
    /// Interval at which to send tasks
    pub probing_rate_interval: Interval,
    /// Number of probing workers
    pub number_of_probing_workers: usize,
    /// Inter-worker interval between workers
    pub worker_interval: u64,
}

/// Task distributor. Spawns a background task that distributes tasks to workers
/// according to the chosen strategy, handles cooldowns, and sends end/break signals.
///
/// # Arguments
/// * `config` - TaskDistributorConfig with all necessary parameters
/// * `strategy` - How tasks should be distributed (Broadcast, RoundRobin, or Discovery)
pub async fn distribute_tasks(config: TaskDistributorConfig, strategy: DistributionStrategy) {
    let strategy_name = match &strategy {
        DistributionStrategy::Broadcast => "Broadcast",
        DistributionStrategy::RoundRobin => "Round-Robin",
        DistributionStrategy::Discovery { .. } => "Round-Robin Discovery",
    };
    info!("[Orchestrator] Starting {strategy_name} Task Distributor.");

    let is_broadcast = matches!(&strategy, DistributionStrategy::Broadcast);
    let has_follow_ups = matches!(&strategy, DistributionStrategy::Discovery { .. });
    let (is_responsive, is_any_protocol, origin_ids) = match strategy {
        DistributionStrategy::Discovery {
            is_responsive,
            is_any_protocol,
            origin_ids,
        } => (is_responsive, is_any_protocol, origin_ids),
        _ => (false, false, vec![]),
    };

    // Cooldown duration before ending the measurement
    let cooldown_secs = if is_broadcast || is_responsive {
        // Wait for all workers to send their last tasks
        (config.number_of_probing_workers as u64 * config.worker_interval) + 1
    } else {
        1 // TODO re-assess cooldown
    };

    let mut probing_rate_interval = config.probing_rate_interval;

    // For --any: keep the original task list to re-filter for subsequent protocol rounds.
    // For non-any: the original vec is consumed directly (no clone).
    let (all_tasks, initial_tasks) = if is_any_protocol {
        let tasks = config.tasks;
        let initial = tasks.clone();
        (tasks, initial)
    } else {
        (Vec::new(), config.tasks)
    };
    let mut hitlist_iter = initial_tasks.into_iter();
    let mut any_origin_index: usize = 0;

    spawn(async move {
        let mut hitlist_is_empty = false;
        let mut cooldown_timer: Option<Instant> = None;
        let mut current_index: usize = 0;

        loop {
            // Get next worker ID (also verifies measurement is still active)
            let worker_id = {
                let lock = config.measurement.read().unwrap();
                let state = match *lock {
                    Some(ref s) => s,
                    None => {
                        warn!("[Orchestrator] Measurement no longer active");
                        break;
                    }
                };

                // Determine which worker(s) perform the current batch
                if is_broadcast {
                    ALL_WORKERS
                } else {
                    let workers = &state.probing_workers;
                    if workers.is_empty() {
                        warn!(
                            "[Orchestrator] No more probing workers available, ending measurement."
                        );
                        break;
                    }
                    current_index %= workers.len();
                    let id = workers[current_index];
                    current_index = (current_index + 1) % workers.len();
                    id
                }
            };

            // Add follow-up tasks from worker stacks (discovery mode only) to this batch
            let follow_up_count = if has_follow_ups {
                let f_worker_id = if is_responsive { ALL_WORKERS } else { worker_id };

                let follow_up_tasks: Vec<Task> = {
                    let mut lock = config.measurement.write().unwrap();
                    if let Some(ref mut state) = *lock {
                        if let Some(queue) = state.worker_stacks.get_mut(&f_worker_id) {
                            let n = std::cmp::min(config.probing_rate as usize, queue.len());
                            queue.drain(..n).collect()
                        } else {
                            Vec::new()
                        }
                    } else {
                        Vec::new()
                    }
                };

                let count = follow_up_tasks.len();
                if !follow_up_tasks.is_empty() {
                    config
                        .tx_t
                        .send((
                            f_worker_id,
                            Instruction {
                                instruction_type: Some(instruction::InstructionType::Tasks(
                                    Tasks {
                                        tasks: follow_up_tasks,
                                    },
                                )),
                            },
                            true,
                        ))
                        .await
                        .expect("Failed to send follow-up tasks to TaskDistributor");
                }
                count
            } else {
                0
            };

            // Fill remainder of the batch with hitlist tasks
            let remainder = (config.probing_rate as usize).saturating_sub(follow_up_count);

            if remainder > 0 && !hitlist_is_empty {
                let tasks: Vec<Task> = hitlist_iter.by_ref().take(remainder).collect();

                if tasks.len() < remainder {
                    hitlist_is_empty = true;
                    if has_follow_ups {
                        info!(
                            "[Orchestrator] All discovery probes sent, awaiting follow-up probes."
                        );
                    }
                }

                if !tasks.is_empty() {
                    config
                        .tx_t
                        .send((
                            worker_id,
                            Instruction {
                                instruction_type: Some(instruction::InstructionType::Tasks(
                                    Tasks { tasks },
                                )),
                            },
                            !has_follow_ups, // Always send single discovery probes
                        ))
                        .await
                        .expect("Failed to send tasks to TaskDistributor");
                }
            }

            // Check if the measurement is finished
            if hitlist_is_empty {
                if has_follow_ups {
                    // Discovery: wait for stacks + trace sessions to drain before cooldown
                    let (stacks_empty, traces_active) = {
                        let lock = config.measurement.read().unwrap();
                        if let Some(ref state) = *lock {
                            (
                                state.worker_stacks.values().all(|q| q.is_empty()),
                                state
                                    .trace_config
                                    .as_ref()
                                    .is_some_and(|c| !c.session_tracker.sessions.is_empty()),
                            )
                        } else {
                            break; // Measurement canceled
                        }
                    };

                    if stacks_empty && !traces_active {
                        if let Some(start_time) = cooldown_timer {
                            if start_time.elapsed() >= Duration::from_secs(cooldown_secs) {
                                // --any: try next protocol for unresolved targets
                                if is_any_protocol
                                    && try_next_any_protocol(
                                        &config.measurement,
                                        &all_tasks,
                                        &origin_ids,
                                        &mut any_origin_index,
                                        &mut hitlist_iter,
                                        &mut hitlist_is_empty,
                                        &mut cooldown_timer,
                                    )
                                {
                                    continue; // Restart loop with next protocol
                                }
                                break; // All protocols exhausted or not --any
                            }
                        } else {
                            info!(
                                "[Orchestrator] No more tasks. Awaiting a {cooldown_secs}-second cooldown."
                            );
                            cooldown_timer = Some(Instant::now());
                        }
                    } else {
                        // Activity resumed -> cancel any pending cooldown.
                        cooldown_timer = None;
                    }
                } else {
                    // Broadcast/RoundRobin: hitlist exhausted → cooldown and done
                    break;
                }
            }

            probing_rate_interval.tick().await;
        }

        // Discovery handles cooldown inside the loop; other modes sleep here
        if !has_follow_ups {
            info!("[Orchestrator] All tasks sent. Awaiting a {cooldown_secs}-second cooldown.");
            tokio::time::sleep(Duration::from_secs(cooldown_secs)).await;
        }

        info!("[Orchestrator] Task distribution finished.");

        // Send end instruction to all workers
        config
            .tx_t
            .send((
                ALL_WORKERS_END,
                Instruction {
                    instruction_type: Some(instruction::InstructionType::End(End { code: 0 })),
                },
                false,
            ))
            .await
            .expect("Failed to send end task to TaskDistributor");

        // Wait for all workers to finish
        while config.measurement.read().unwrap().is_some() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // Close the TaskDistributor channel
        config
            .tx_t
            .send((
                BREAK_SIGNAL,
                Instruction {
                    instruction_type: None,
                },
                false,
            ))
            .await
            .expect("Failed to send break signal to TaskDistributor");
    });
}

/// Attempts to advance to the next --any protocol round.
/// Returns `true` if a new round was started (caller should `continue` the loop),
/// `false` if all protocols are exhausted or all targets are resolved.
fn try_next_any_protocol(
    measurement: &MeasurementHandle,
    all_tasks: &[Task],
    origin_ids: &[u32],
    any_origin_index: &mut usize,
    hitlist_iter: &mut std::vec::IntoIter<Task>,
    hitlist_is_empty: &mut bool,
    cooldown_timer: &mut Option<Instant>,
) -> bool {
    *any_origin_index += 1;

    if *any_origin_index < origin_ids.len() {
        let next_origin_id = origin_ids[*any_origin_index];
        let lock = measurement.read().unwrap();
        let state = lock.as_ref().unwrap();
        let resolved_count = state.resolved_targets.len();

        // Build tasks for targets that have not responded yet
        let unresolved: Vec<Task> = all_tasks
            .iter()
            .filter_map(|task| {
                if let Some(crate::custom_module::manycastr::task::TaskType::Discovery(probe)) =
                    &task.task_type
                {
                    if let Some(addr) = probe.dst {
                        if !state.resolved_targets.contains(&addr) {
                            return Some(Task {
                                task_type: Some(
                                    crate::custom_module::manycastr::task::TaskType::Discovery(
                                        Probe { dst: Some(addr) },
                                    ),
                                ),
                                origin_id: next_origin_id,
                            });
                        }
                    }
                }
                None
            })
            .collect();
        let unresolved_count = unresolved.len();
        drop(lock);

        if unresolved_count > 0 {
            info!(
                "[Orchestrator] --any: {resolved_count} targets resolved, {unresolved_count} remaining. Trying next protocol (origin {next_origin_id})."
            );
            *hitlist_iter = unresolved.into_iter();
            *hitlist_is_empty = false;
            *cooldown_timer = None;
            return true; // Caller should continue the loop
        }

        info!("[Orchestrator] --any: all {resolved_count} targets resolved.");
    } else {
        let lock = measurement.read().unwrap();
        let resolved_count = lock.as_ref().map(|s| s.resolved_targets.len()).unwrap_or(0);
        let total = all_tasks.len();
        info!(
            "[Orchestrator] --any: all protocols exhausted. {resolved_count}/{total} targets resolved."
        );
    }

    false // No more protocols to try
}

/// Reads from a channel containing Tasks and sends them to the workers, at specified inter-worker intervals.
/// Sends repeated tasks (at inter-probe interval) if multiple probes per target are configured.
///
/// Used for starting a measurement, sending tasks to the workers, ending a measurement.
///
/// # Arguments
///
/// * `rx` - the channel containing the tuple (task_ID, task, multiple_times)
/// * `workers` - the list of worker senders to which the tasks will be sent
/// * `inter_worker_interval` - the interval in seconds between sending tasks to different workers
/// * `inter_probe_interval` - the interval in seconds between sending multiple probes to the same worker
/// * `number_of_probes` - the number of times to probe the same target (for non-discovery probes)
pub async fn task_sender(
    mut rx: mpsc::Receiver<(u32, Instruction, bool)>,
    workers: Vec<WorkerSender<Result<Instruction, Status>>>,
    inter_worker_interval: u64,
    inter_probe_interval: u64,
    number_of_probes: u8,
) {
    // Loop over the tasks in the channel
    while let Some((worker_id, instruction, multiple)) = rx.recv().await {
        let nprobes = if multiple { number_of_probes } else { 1 };

        if worker_id == BREAK_SIGNAL {
            break;
        } else if worker_id == ALL_WORKERS_END {
            // To all direct (used for 'end measurement' only)
            for sender in &workers {
                sender
                    .send(Ok(instruction.clone()))
                    .await
                    .unwrap_or_else(|e| {
                        sender.cleanup();
                        warn!(
                            "[Orchestrator] Failed to send broadcast task to worker {}: {e:?}",
                            sender.hostname
                        );
                    });
                sender.finished();
            }
        } else if worker_id == ALL_WORKERS {
            // To all workers with an interval (used for --unicast, anycast, --responsive follow-up probes)
            let mut probing_index = 0;

            for sender in &workers {
                if *sender.status == Probing {
                    let sender_c = sender.clone();
                    let task_c = instruction.clone();
                    spawn(async move {
                        // Wait inter-client probing interval
                        tokio::time::sleep(Duration::from_secs(
                            probing_index * inter_worker_interval,
                        ))
                        .await;

                        spawn(async move {
                            for _ in 0..nprobes {
                                sender_c.send(Ok(task_c.clone())).await.unwrap_or_else(|e| {
                                    sender_c.cleanup();
                                    warn!(
                                        "[Orchestrator] Failed to send broadcast task to probing worker {}: {e:?}",
                                        sender_c.hostname
                                    );
                                });
                                // Sleep for the inter-probe interval
                                tokio::time::sleep(Duration::from_secs(inter_probe_interval)).await;
                            }
                        });
                    });
                    probing_index += 1;
                }
            }
        } else {
            // to specific worker (used for --latency follow-up probes)
            if let Some(sender) = workers.iter().find(|s| s.worker_id == worker_id) {
                if nprobes < 2 {
                    sender.send(Ok(instruction)).await.unwrap_or_else(|e| {
                        sender.cleanup();
                        warn!(
                            "[Orchestrator] Failed to send task to worker {}: {e:?}",
                            sender.hostname
                        );
                    });
                } else {
                    // Probe multiple times (in separate thread)
                    let sender_clone = sender.clone();
                    spawn(async move {
                        for _ in 0..number_of_probes {
                            sender_clone
                                .send(Ok(instruction.clone()))
                                .await
                                .unwrap_or_else(|e| {
                                    sender_clone.cleanup();
                                    warn!(
                                        "[Orchestrator] Failed to send task to worker {}: {e:?}",
                                        sender_clone.hostname
                                    );
                                });
                            // Wait inter-probe interval
                            tokio::time::sleep(Duration::from_secs(inter_probe_interval)).await;
                        }
                    });
                }
            } else {
                warn!("[Orchestrator] No sender found for worker ID {worker_id}");
            }
        }
    }

    info!("[Orchestrator] Task distributor finished");
}
