use crate::custom_module::manycastr::WorkerStatus::Probing;
use crate::custom_module::manycastr::{
    Address, End, Instruction, LiveTarget, Probe, Task, Tasks, instruction, task,
};
use crate::orchestrator::trace::seed_tracemap_sessions;
use crate::orchestrator::worker::WorkerSender;
use crate::orchestrator::{LIVE_DISCOVERY_TIMEOUT_SECS, MeasurementHandle, PendingTarget};
use crate::{ALL_WORKERS, ANY_ORIGIN, ANY_WORKER};
use log::{info, warn};
use std::collections::HashMap;
use std::time::Duration;
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::time::{Instant, Interval, MissedTickBehavior};
use tonic::Status;

/// Grace period (seconds) after the hitlist is exhausted
const REPLY_GRACE_SECS: u64 = 5;

/// Pause discovery when the deepest follow-up stack exceeds this many seconds of drain (at the probing rate)
const STACK_HIGH_WATERMARK_SECS: usize = 5;
/// Resume discovery once the deepest follow-up stack drops below this many seconds of drain (at the probing rate)
const STACK_LOW_WATERMARK_SECS: usize = 1;

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
    /// Seed binary-search trace sessions round-robin, with follow-up task interleaving (tracemap mode)
    Tracemap,
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

                    for _ in 0..nprobes {
                        let _ = sender_c.send(Ok(task_c.clone())).await;
                        tokio::time::sleep(Duration::from_secs(inter_probe_interval)).await;
                    }
                });
                probing_index += 1;
            }
        }
    } else {
        // Send to a specific worker
        if let Some(sender) = workers.iter().find(|s| s.worker_id == worker_id) {
            if nprobes < 2 {
                let _ = sender.send(Ok(instruction)).await;
            } else {
                let sender_c = sender.clone();
                spawn(async move {
                    for _ in 0..nprobes {
                        let _ = sender_c.send(Ok(instruction.clone())).await;
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
        let _ = sender.send(Ok(end.clone())).await;
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
        DistributionStrategy::Tracemap => "Round-Robin Tracemap",
    };
    info!("[Orchestrator] Starting {strategy_name} Task Distributor.");

    let is_broadcast = matches!(&strategy, DistributionStrategy::Broadcast);
    let is_tracemap = matches!(&strategy, DistributionStrategy::Tracemap);
    // Tracemap interleaves follow-up trace probes with session seeding, like discovery modes
    let has_follow_ups = matches!(&strategy, DistributionStrategy::Discovery { .. }) || is_tracemap;
    let is_discovery = config.is_discovery;
    let (is_responsive, is_any_protocol, origin_ids) = match strategy {
        DistributionStrategy::Discovery {
            is_responsive,
            is_any_protocol,
            origin_ids,
        } => (is_responsive, is_any_protocol, origin_ids),
        _ => (false, false, vec![]),
    };

    // Wait for the last tasks being sent (accounting for repeated tasks)
    let repeat_secs = (config.number_of_probes.saturating_sub(1)) as u64 * config.probe_interval;
    let cooldown_secs = if is_broadcast || is_responsive {
        // Also wait for the inter-worker staggering of the last broadcast batch
        (config.number_of_probing_workers as u64 * config.worker_interval) + repeat_secs + 1
    } else {
        repeat_secs + 1
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
        hitlist_exhausted_at: None,
        cooldown_timer: None,
    };

    // nprobes: measurement probes are repeated, discovery probes are not
    let nprobes = config.number_of_probes;
    let inter_worker_interval = config.worker_interval;
    let inter_probe_interval = config.probe_interval;

    // Follow-up backlog watermarks, expressed in seconds of drain at the probing rate
    let high_watermark = STACK_HIGH_WATERMARK_SECS * config.probing_rate as usize;
    let low_watermark = STACK_LOW_WATERMARK_SECS * config.probing_rate as usize;

    spawn(async move {
        let mut current_index: usize = 0;
        let mut discovery_paused = false;

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

                let (follow_up_tasks, max_stack_depth): (Vec<Task>, usize) = {
                    let mut lock = config.measurement.write().unwrap();
                    if let Some(ref mut state) = *lock {
                        let tasks = if let Some(queue) = state.worker_stacks.get_mut(&f_worker_id) {
                            let n = std::cmp::min(config.probing_rate as usize, queue.len());
                            queue.drain(..n).collect()
                        } else {
                            Vec::new()
                        };
                        let depth = state
                            .worker_stacks
                            .values()
                            .map(|q| q.len())
                            .max()
                            .unwrap_or(0);
                        (tasks, depth)
                    } else {
                        (Vec::new(), 0)
                    }
                };

                // Hysteresis: pause/resume discovery based on the watermark thresholds
                if discovery_paused {
                    if max_stack_depth <= low_watermark {
                        info!("[Orchestrator] Follow-up backlog drained, resuming discovery.");
                        discovery_paused = false;
                    }
                } else if max_stack_depth >= high_watermark {
                    info!(
                        "[Orchestrator] Follow-up backlog too large ({max_stack_depth} tasks), pausing discovery."
                    );
                    discovery_paused = true;
                }

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

            if remainder > 0 && !round.hitlist_exhausted && !discovery_paused {
                // Wrap target addresses into tasks
                let tasks: Vec<Task> = if is_tracemap {
                    // Register a binary-search session per target, assigned to this round's worker
                    let addrs: Vec<Address> = round.hitlist_iter.by_ref().take(remainder).collect();
                    let mut lock = config.measurement.write().unwrap();
                    match lock.as_mut().and_then(|state| state.trace_config.as_mut()) {
                        Some(trace_config) => seed_tracemap_sessions(
                            addrs,
                            worker_id,
                            round.current_origin_id,
                            trace_config,
                        ),
                        None => {
                            warn!(
                                "[Orchestrator] No traceroute configuration for tracemap, ending measurement."
                            );
                            break;
                        }
                    }
                } else {
                    round
                        .hitlist_iter
                        .by_ref()
                        .take(remainder)
                        .map(|addr| make_task(addr, is_discovery, round.current_origin_id))
                        .collect()
                };

                if tasks.len() < remainder {
                    round.hitlist_exhausted = true;
                    round.hitlist_exhausted_at = Some(Instant::now());
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
                        } else if round
                            .hitlist_exhausted_at
                            .is_some_and(|t| t.elapsed() >= Duration::from_secs(REPLY_GRACE_SECS))
                        {
                            // Grace period elapsed — start the idle cooldown
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

/// Live task distributor for feed-based measurements.
///
/// Ticks once per second: first drains follow-up tasks (discovery follow-ups and
/// `origin:any` retries) from the worker stacks, then drains targets from `feed`
/// up to the remaining rate budget (`probing_rate`, enforced via the orchestrator's
/// `--live_rate`; no worker receives more than `probing_rate` tasks per second).
///
/// Each target carries a worker assignment: `ANY_WORKER` (round-robin, default),
/// `ALL_WORKERS` (broadcast, staggered by the worker interval), or a specific worker ID.
/// Targets requiring discovery (--responsive, or `origin:any`) are sent as discovery
/// tasks to a single worker and registered as pending; their measurement probes
/// follow once a discovery reply arrives (see `send_result` and the sweeper).
///
/// The measurement ends when the feed has closed (the CLI ended its stream or
/// disconnected) and all follow-ups and pending discoveries have resolved,
/// or when no probing workers remain.
pub fn distribute_live_tasks(
    mut feed: mpsc::Receiver<LiveTarget>,
    measurement: MeasurementHandle,
    workers: Vec<WorkerSender<Result<Instruction, Status>>>,
    probing_rate: u32,
    worker_interval: u64,
    is_responsive: bool,
) {
    info!("[Orchestrator] Starting Live Task Distributor.");

    spawn(async move {
        let mut tick_interval = tokio::time::interval(Duration::from_secs(1));
        tick_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut current_index: usize = 0;
        let batch_capacity = probing_rate as usize;
        let mut feed_closed = false;

        loop {
            tick_interval.tick().await;

            // Drain follow-up tasks from the worker stacks
            let (follow_ups, probing_workers, pending_count) = {
                let mut lock = measurement.write().unwrap();
                let Some(state) = lock.as_mut() else {
                    warn!("[Orchestrator] Measurement no longer active");
                    break;
                };

                if state.probing_workers.is_empty() {
                    warn!("[Orchestrator] No more probing workers available, ending measurement.");
                    break;
                }

                let mut follow_ups: Vec<(u32, Vec<Task>)> = Vec::new();
                for (worker_id, stack) in state.worker_stacks.iter_mut() {
                    if !stack.is_empty() {
                        let n = stack.len().min(batch_capacity);
                        follow_ups.push((*worker_id, stack.drain(..n).collect()));
                    }
                }

                let pending_count = state.live.as_ref().map_or(0, |live| live.pending.len());
                (follow_ups, state.probing_workers.clone(), pending_count)
            };

            let follow_up_count: usize = follow_ups.iter().map(|(_, tasks)| tasks.len()).sum();
            for (worker_id, tasks) in follow_ups {
                // The worker interval only applies to ALL_WORKERS (broadcast) stacks
                send_to_workers(
                    &workers,
                    worker_id,
                    Instruction {
                        instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                            tasks,
                        })),
                    },
                    1, // TODO enable 'nprobes:'
                    worker_interval,
                    0,
                )
                .await;
            }

            // Drain the feed (non-blocking) up to the remaining rate budget
            let remainder = batch_capacity.saturating_sub(follow_up_count);
            let mut batch: Vec<LiveTarget> = Vec::new();
            while batch.len() < remainder {
                match feed.try_recv() {
                    Ok(target) => batch.push(target),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        if !feed_closed {
                            info!("[Orchestrator] Live feed closed, finishing outstanding tasks.");
                            feed_closed = true;
                        }
                        break;
                    }
                }
            }
            let dispatched = batch.len();

            // Partition the batch by worker assignment, registering discovery targets
            let mut per_worker: HashMap<u32, Vec<Task>> = HashMap::new();
            let mut broadcast: Vec<Task> = Vec::new();
            {
                let mut lock = measurement.write().unwrap();
                let Some(state) = lock.as_mut() else {
                    warn!("[Orchestrator] Measurement no longer active");
                    break;
                };

                for target in batch {
                    let Some(dst) = target.dst else { continue };

                    // Do not send discovery probes when the measurement is a single probe
                    let needs_discovery = target.origin_id == ANY_ORIGIN
                        || (is_responsive && target.worker_id == ALL_WORKERS);
                    if needs_discovery {
                        // Discovery is performed by a single worker
                        let discovery_worker = match target.worker_id {
                            ANY_WORKER | ALL_WORKERS => {
                                current_index %= probing_workers.len();
                                let id = probing_workers[current_index];
                                current_index += 1;
                                id
                            }
                            id if probing_workers.contains(&id) => id,
                            id => {
                                warn!(
                                    "[Orchestrator] Dropping target {dst}: worker {id} is not probing in this measurement"
                                );
                                continue;
                            }
                        };

                        let Some(live) = state.live.as_mut() else {
                            continue;
                        };

                        // origin:any starts with the first origin and retries the rest on timeout
                        let (origin_id, next_origin_idx) = if target.origin_id == ANY_ORIGIN {
                            let Some(&first) = live.origin_ids.first() else {
                                continue;
                            };
                            (first, Some(1))
                        } else {
                            (target.origin_id, None)
                        };

                        live.pending.insert(
                            dst,
                            PendingTarget {
                                worker_sel: target.worker_id,
                                discovery_worker,
                                next_origin_idx,
                                deadline: std::time::Instant::now()
                                    + Duration::from_secs(LIVE_DISCOVERY_TIMEOUT_SECS),
                            },
                        );

                        per_worker
                            .entry(discovery_worker)
                            .or_default()
                            .push(make_task(dst, true, origin_id));
                        continue;
                    }

                    // Regular probe task
                    let task = make_task(dst, false, target.origin_id);
                    match target.worker_id {
                        ANY_WORKER => {
                            // Round-robin across probing workers
                            current_index %= probing_workers.len();
                            per_worker
                                .entry(probing_workers[current_index])
                                .or_default()
                                .push(task);
                            current_index += 1;
                        }
                        ALL_WORKERS => broadcast.push(task),
                        id if probing_workers.contains(&id) => {
                            per_worker.entry(id).or_default().push(task);
                        }
                        id => warn!(
                            "[Orchestrator] Dropping target {dst}: worker {id} is not probing in this measurement"
                        ),
                    }
                }
            }

            // Send the per-worker tasks (specific, round-robin, and discovery assignments)
            for (worker_id, tasks) in per_worker {
                send_to_workers(
                    &workers,
                    worker_id,
                    Instruction {
                        instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                            tasks,
                        })),
                    },
                    1, // TODO enable 'nprobes:'
                    0,
                    0,
                )
                .await;
            }

            // Broadcast tasks to all probing workers, staggered by the worker interval
            if !broadcast.is_empty() {
                send_to_workers(
                    &workers,
                    ALL_WORKERS,
                    Instruction {
                        instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                            tasks: broadcast,
                        })),
                    },
                    1, // TODO enable 'nprobes:'
                    worker_interval,
                    0,
                )
                .await;
            }

            // Done once the feed is closed and all outstanding work has resolved
            if feed_closed && dispatched == 0 && follow_up_count == 0 && pending_count == 0 {
                break;
            }
        }

        // Wait for the last (staggered) probes to be sent and their replies to arrive
        let cooldown_secs = workers.len() as u64 * worker_interval + REPLY_GRACE_SECS;
        info!("[Orchestrator] Awaiting a {cooldown_secs}-second cooldown.");
        tokio::time::sleep(Duration::from_secs(cooldown_secs)).await;

        info!("[Orchestrator] Live task distribution finished.");

        // Notify all workers that the measurement is over
        end_measurement(&workers).await;

        // Wait for all workers to finish
        while measurement.read().unwrap().is_some() {
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
    /// When the hitlist was first exhausted (used for the reply grace period).
    hitlist_exhausted_at: Option<Instant>,
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
            round.hitlist_exhausted_at = None;
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
