use crate::custom_module::manycastr::{
    instruction, task, Address, End, Instruction, Probe, Task, Tasks,
};
use crate::orchestrator::worker::WorkerSender;
use crate::orchestrator::worker::WorkerStatus::Probing;
use crate::orchestrator::MeasurementHandle;
use crate::ALL_WORKERS;
use log::{info, warn};
use std::time::Duration;
use tokio::spawn;
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
    /// Target addresses to probe
    pub hitlist: Vec<Address>,
    /// Whether to wrap addresses in Discovery tasks (true) or Probe tasks (false)
    pub is_discovery: bool,
    /// Origin ID for the first (or only) probing round
    pub first_origin_id: u32,
    /// All per-measurement state. `None` when idle.
    pub measurement: MeasurementHandle,
    /// Worker senders (cloned from the saved_workers list at measurement start)
    pub workers: Vec<WorkerSender<Result<Instruction, Status>>>,
    /// Number of tasks to send per interval (equal to probing rate)
    pub probing_rate: u32,
    /// Interval at which to send tasks
    pub probing_rate_interval: Interval,
    /// Number of probing workers
    pub number_of_probing_workers: usize,
    /// Inter-worker interval in seconds between workers
    pub worker_interval: u64,
    /// Number of times to repeat each measurement probe (discovery probes are always sent once)
    pub number_of_probes: u8,
    /// Inter-probe interval in seconds between repeated probes
    pub probe_interval: u64,
}

/// Build a `Task` from a raw address and the current distribution metadata.
#[inline]
fn make_task(addr: Address, is_discovery: bool, origin_id: u32) -> Task {
    Task {
        task_type: Some(if is_discovery {
            task::TaskType::Discovery(Probe { dst: Some(addr) })
        } else {
            task::TaskType::Probe(Probe { dst: Some(addr) })
        }),
        origin_id,
    }
}

/// Send an instruction to workers according to the specified parameters.
///
/// # Arguments
/// * `workers` - the list of worker senders
/// * `worker_id` - target: `ALL_WORKERS` for broadcast, or a specific worker ID
/// * `instruction` - the instruction to send
/// * `nprobes` - how many times to send (1 = no repeat)
/// * `inter_worker_interval` - seconds between workers for broadcast sends
/// * `inter_probe_interval` - seconds between repeated probes
async fn send_to_workers(
    workers: &[WorkerSender<Result<Instruction, Status>>],
    worker_id: u32,
    instruction: Instruction,
    nprobes: u8,
    inter_worker_interval: u64,
    inter_probe_interval: u64,
) {
    if worker_id == ALL_WORKERS {
        // Broadcast to all probing workers with inter-worker delay
        let mut probing_index: u64 = 0;

        for sender in workers {
            if *sender.status == Probing {
                let sender_c = sender.clone();
                let task_c = instruction.clone();
                spawn(async move {
                    // Wait inter-client probing interval
                    tokio::time::sleep(Duration::from_secs(probing_index * inter_worker_interval))
                        .await;

                    spawn(async move {
                        for _ in 0..nprobes {
                            sender_c.send(Ok(task_c.clone())).await.unwrap_or_else(|e| {
                                sender_c.cleanup();
                                warn!(
                                    "[Orchestrator] Failed to send task to probing worker {}: {e:?}",
                                    sender_c.hostname
                                );
                            });
                            tokio::time::sleep(Duration::from_secs(inter_probe_interval)).await;
                        }
                    });
                });
                probing_index += 1;
            }
        }
    } else {
        // Send to a specific worker
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
                let sender_c = sender.clone();
                spawn(async move {
                    for _ in 0..nprobes {
                        sender_c
                            .send(Ok(instruction.clone()))
                            .await
                            .unwrap_or_else(|e| {
                                sender_c.cleanup();
                                warn!(
                                    "[Orchestrator] Failed to send task to worker {}: {e:?}",
                                    sender_c.hostname
                                );
                            });
                        tokio::time::sleep(Duration::from_secs(inter_probe_interval)).await;
                    }
                });
            }
        } else {
            warn!("[Orchestrator] No sender found for worker ID {worker_id}");
        }
    }
}

/// Send end-of-measurement to all workers and mark them as finished.
async fn end_measurement(workers: &[WorkerSender<Result<Instruction, Status>>]) {
    let end = Instruction {
        instruction_type: Some(instruction::InstructionType::End(End { code: 0 })),
    };
    for sender in workers {
        sender.send(Ok(end.clone())).await.unwrap_or_else(|e| {
            sender.cleanup();
            warn!(
                "[Orchestrator] Failed to send end to worker {}: {e:?}",
                sender.hostname
            );
        });
        sender.finished();
    }
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
    let is_discovery = config.is_discovery;
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

    let (all_addresses, initial_addresses) = if is_any_protocol {
        // Keep the original address list to re-filter for subsequent protocol rounds
        let addrs = config.hitlist;
        let initial = addrs.clone();
        (addrs, initial)
    } else {
        // Keep only the original vec (which gets consumed directly)
        (Vec::new(), config.hitlist)
    };
    let mut round = RoundState {
        origin_index: 0,
        current_origin_id: config.first_origin_id,
        hitlist_iter: initial_addresses.into_iter(),
        hitlist_exhausted: false,
        cooldown_timer: None,
    };

    // nprobes: measurement probes are repeated, discovery probes are not
    let nprobes = config.number_of_probes;
    let inter_worker_interval = config.worker_interval;
    let inter_probe_interval = config.probe_interval;

    spawn(async move {
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
                let f_worker_id = if is_responsive {
                    ALL_WORKERS
                } else {
                    worker_id
                };

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
                    send_to_workers(
                        &config.workers,
                        f_worker_id,
                        Instruction {
                            instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                                tasks: follow_up_tasks,
                            })),
                        },
                        nprobes,
                        inter_worker_interval,
                        inter_probe_interval,
                    )
                    .await;
                }
                count
            } else {
                0
            };

            // Fill remainder of the batch with hitlist tasks
            let remainder = (config.probing_rate as usize).saturating_sub(follow_up_count);

            if remainder > 0 && !round.hitlist_exhausted {
                // Wrap target addresses into tasks
                let tasks: Vec<Task> = round
                    .hitlist_iter
                    .by_ref()
                    .take(remainder)
                    .map(|addr| make_task(addr, is_discovery, round.current_origin_id))
                    .collect();

                if tasks.len() < remainder {
                    round.hitlist_exhausted = true;
                    if has_follow_ups {
                        info!(
                            "[Orchestrator] All discovery probes sent, awaiting follow-up probes."
                        );
                    }
                }

                if !tasks.is_empty() {
                    // Discovery probes are sent once; measurement probes are repeated nprobes times
                    let hitlist_nprobes = if has_follow_ups { 1 } else { nprobes };

                    send_to_workers(
                        &config.workers,
                        worker_id,
                        Instruction {
                            instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                                tasks,
                            })),
                        },
                        hitlist_nprobes,
                        inter_worker_interval,
                        inter_probe_interval,
                    )
                    .await;
                }
            }

            // Check if the measurement is finished
            if round.hitlist_exhausted {
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
                        if let Some(start_time) = round.cooldown_timer {
                            if start_time.elapsed() >= Duration::from_secs(cooldown_secs) {
                                // --any: try next protocol for unresolved targets
                                if is_any_protocol
                                    && try_next_any_protocol(
                                        &config.measurement,
                                        &all_addresses,
                                        &origin_ids,
                                        &mut round,
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
                            round.cooldown_timer = Some(Instant::now());
                        }
                    } else {
                        // Activity resumed -> cancel any pending cooldown.
                        round.cooldown_timer = None;
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

        // Notify all workers that the measurement is over
        end_measurement(&config.workers).await;

        // Wait for all workers to finish
        while config.measurement.read().unwrap().is_some() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

/// Mutable iteration state for the distributor loop, shared with `try_next_any_protocol`.
struct RoundState {
    origin_index: usize,
    current_origin_id: u32,
    hitlist_iter: std::vec::IntoIter<Address>,
    hitlist_exhausted: bool,
    cooldown_timer: Option<Instant>,
}

/// Attempts to advance to the next --any protocol round.
/// Returns `true` if a new round was started (caller should `continue` the loop),
/// `false` if all protocols are exhausted or all targets are resolved.
fn try_next_any_protocol(
    measurement: &MeasurementHandle,
    all_addresses: &[Address],
    origin_ids: &[u32],
    round: &mut RoundState,
) -> bool {
    round.origin_index += 1;

    if round.origin_index < origin_ids.len() {
        let next_origin_id = origin_ids[round.origin_index];
        let lock = measurement.read().unwrap();
        let state = lock.as_ref().unwrap();
        let resolved_count = state.resolved_targets.len();

        // Collect addresses that have not responded yet
        let unresolved: Vec<Address> = all_addresses
            .iter()
            .filter(|addr| !state.resolved_targets.contains(addr))
            .cloned()
            .collect();
        let unresolved_count = unresolved.len();
        drop(lock);

        if unresolved_count > 0 {
            info!(
                "[Orchestrator] --any: {resolved_count} targets resolved, {unresolved_count} remaining. Trying next protocol (origin {next_origin_id})."
            );
            round.hitlist_iter = unresolved.into_iter();
            round.hitlist_exhausted = false;
            round.cooldown_timer = None;
            round.current_origin_id = next_origin_id;
            return true; // Caller should continue the loop
        }

        info!("[Orchestrator] --any: all {resolved_count} targets resolved.");
    } else {
        let lock = measurement.read().unwrap();
        let resolved_count = lock.as_ref().map(|s| s.resolved_targets.len()).unwrap_or(0);
        let total = all_addresses.len();
        info!(
            "[Orchestrator] --any: all protocols exhausted. {resolved_count}/{total} targets resolved."
        );
    }

    false // No more protocols to try
}
