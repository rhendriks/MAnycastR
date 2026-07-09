use crate::custom_module::has_anycast_origin;
use crate::custom_module::manycastr::WorkerStatus::Probing;
use crate::custom_module::manycastr::{
    Address, End, Instruction, LiveTarget, MeasurementType, Probe, ScheduleMeasurement, Task,
    Tasks, instruction, task,
};
use crate::orchestrator::trace::seed_tracemap_sessions;
use crate::orchestrator::{
    LIVE_DISCOVERY_TIMEOUT_SECS, MeasurementHandle, PendingTarget, WorkerRegistry, WorkerSel,
    wire_nprobes,
};
use crate::{ALL_ORIGINS, ALL_WORKERS, ANY_ORIGIN};
use log::{info, warn};
use std::collections::HashMap;
use std::time::Duration;
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::time::{Instant, Interval, MissedTickBehavior};

/// Grace period (seconds) after the hitlist is exhausted
const REPLY_GRACE_SECS: u64 = 5;

/// Pause discovery when the deepest follow-up stack exceeds this many seconds of drain (at the probing rate)
const STACK_HIGH_WATERMARK_SECS: usize = 5;
/// Resume discovery once the deepest follow-up stack drops below this many seconds of drain (at the probing rate)
const STACK_LOW_WATERMARK_SECS: usize = 1;

/// How tasks should be distributed to workers
pub enum DistributionStrategy {
    /// Broadcast tasks to all probing workers simultaneously (LACeS, and unicast-only latency)
    Broadcast,
    /// Send tasks to probing workers in round-robin fashion (catchment mode)
    RoundRobin,
    /// Send discovery tasks round-robin, with follow-up task interleaving (latency, traceroute, responsive modes)
    Discovery {
        /// --responsive sends follow-ups to ALL workers; otherwise to the catching worker
        is_responsive: bool,
    },
    /// Seed binary-search trace sessions round-robin, with follow-up task interleaving (tracemap mode)
    Tracemap,
}

impl DistributionStrategy {
    /// Select the distribution strategy for a measurement definition.
    ///
    /// * **catchment** → RoundRobin: one probe per target, which is itself the
    ///   responsiveness check (--any retries unresolved targets origin by origin)
    /// * **tracemap** → Tracemap
    /// * **anycast-traceroute** → Discovery: find the catching worker first
    /// * **latency** with an anycast origin → Discovery: measure from the catching worker
    /// * **latency** with only unicast origins → Broadcast: every worker measures
    ///   from its own unicast address (no discovery needed)
    /// * **laces** → Broadcast
    /// * `--responsive` turns a Broadcast mode into Discovery, gating the broadcast
    ///   behind a single-worker responsiveness probe
    pub fn select(m_def: &ScheduleMeasurement) -> Self {
        let is_responsive = m_def.is_responsive;
        match m_def.m_type() {
            MeasurementType::Catchment => Self::RoundRobin,
            MeasurementType::Tracemap => Self::Tracemap,
            MeasurementType::AnycastTraceroute => Self::Discovery { is_responsive },
            MeasurementType::AnycastLatency if has_anycast_origin(&m_def.configurations) => {
                Self::Discovery { is_responsive }
            }
            MeasurementType::AnycastLatency | MeasurementType::Laces => {
                if is_responsive {
                    Self::Discovery { is_responsive }
                } else {
                    Self::Broadcast
                }
            }
        }
    }
}

pub struct TaskDistributorConfig {
    /// Target addresses to probe
    pub hitlist: Vec<Address>,
    /// --any protocol fallback mode: unresolved targets are retried origin by origin
    pub is_any: bool,
    /// Ordered origin IDs for IPv4 and IPv6 for --any fallback (empty when not --any);
    pub origin_ids: Vec<(u32, bool)>,
    /// Origin ID for the first (or only) probing round
    pub first_origin_id: u32,
    /// All per-measurement state. `None` when idle.
    pub measurement: MeasurementHandle,
    /// Shared list of worker senders, updated on reconnect.
    pub workers: WorkerRegistry,
    /// Number of tasks to send per interval (equal to probing rate)
    pub probing_rate: u32,
    /// Interval at which to send tasks
    pub probing_rate_interval: Interval,
    /// Number of probing workers
    pub number_of_probing_workers: usize,
    /// Inter-worker interval in seconds between workers
    pub worker_interval: u64,
    /// Number of times to repeat each measurement probe (discovery probes are always sent once)
    pub nprobes: u32,
    /// Inter-probe interval in seconds between repeated probes
    pub probe_interval: u64,
}

/// Build a `Task` from a raw address and the current distribution metadata.
/// The worker sends the probe `nprobes` times (spaced by the measurement's probe interval).
#[inline]
fn make_task(addr: Address, is_discovery: bool, origin_id: u32, nprobes: u32) -> Task {
    Task {
        task_type: Some(if is_discovery {
            task::TaskType::Discovery(Probe { dst: Some(addr) })
        } else {
            task::TaskType::Probe(Probe { dst: Some(addr) })
        }),
        origin_id,
        nprobes: wire_nprobes(nprobes),
    }
}

/// Send an instruction to workers according to the specified parameters.
///
/// # Arguments
/// * `workers` - registry of worker senders
/// * `worker_id` - target: `ALL_WORKERS` for broadcast, or a specific worker ID
/// * `instruction` - the instruction to send
/// * `inter_worker_interval` - seconds between workers for broadcast sends
async fn send_to_workers(
    workers: &WorkerRegistry,
    worker_id: u32,
    instruction: Instruction,
    inter_worker_interval: u64,
) {
    if worker_id == ALL_WORKERS {
        // Broadcast to all probing workers with inter-worker delay
        let probing_ids: Vec<u32> = workers
            .lock()
            .unwrap()
            .iter()
            .filter(|sender| *sender.status == Probing)
            .map(|sender| sender.worker_id)
            .collect();

        send_staggered(workers, &probing_ids, instruction, inter_worker_interval);
    } else {
        // Send to a specific worker
        let sender = {
            let workers = workers.lock().unwrap();
            workers.iter().find(|s| s.worker_id == worker_id).cloned()
        };
        if let Some(sender) = sender {
            let _ = sender.send(Ok(instruction)).await;
        } else {
            warn!("[Orchestrator] No sender found for worker ID {worker_id}");
        }
    }
}

/// Send an instruction to each listed worker, spaced by the inter-worker interval.
fn send_staggered(
    workers: &WorkerRegistry,
    worker_ids: &[u32],
    instruction: Instruction,
    inter_worker_interval: u64,
) {
    let senders: Vec<_> = {
        let registry = workers.lock().unwrap();
        worker_ids
            .iter()
            .filter_map(|id| {
                let sender = registry.iter().find(|s| s.worker_id == *id).cloned();
                if sender.is_none() {
                    warn!("[Orchestrator] No sender found for worker ID {id}");
                }
                sender
            })
            .collect()
    };

    for (probing_index, sender) in (0_u64..).zip(senders) {
        let task_c = instruction.clone();
        spawn(async move {
            // Wait inter-worker probing interval
            tokio::time::sleep(Duration::from_secs(probing_index * inter_worker_interval)).await;

            let _ = sender.send(Ok(task_c)).await;
        });
    }
}

/// Resolve a live target's `worker_ids` into a worker selection:
/// empty selects any worker (round-robin), `[ALL_WORKERS]` selects all probing
/// workers, and anything else is an explicit set of worker IDs (sorted,
/// deduplicated, and filtered to probing workers).
///
/// Returns `None` (drop the target) when none of the requested workers is probing.
fn resolve_worker_sel(
    mut worker_ids: Vec<u32>,
    probing_workers: &[u32],
    dst: Address,
) -> Option<WorkerSel> {
    if worker_ids.is_empty() {
        return Some(WorkerSel::Any);
    }
    if worker_ids.contains(&ALL_WORKERS) {
        return Some(WorkerSel::All);
    }

    worker_ids.sort_unstable();
    worker_ids.dedup();
    let requested = worker_ids.len();
    worker_ids.retain(|id| probing_workers.contains(id));
    match worker_ids.len() {
        0 => {
            warn!(
                "[Orchestrator] Dropping target {dst}: none of its workers are probing in this measurement"
            );
            None
        }
        probing => {
            if probing < requested {
                warn!(
                    "[Orchestrator] Target {dst}: ignoring {} worker(s) not probing in this measurement",
                    requested - probing
                );
            }
            Some(WorkerSel::Set(worker_ids))
        }
    }
}

/// Finalize a measurement once task distribution is done: send the end-of-measurement
/// instruction to all workers (marking them finished), then wait for every worker to
/// report back before the distributor task exits.
async fn finalize_measurement(workers: &WorkerRegistry, measurement: &MeasurementHandle) {
    info!("[Orchestrator] Task distribution finished.");

    // Start the finalizing, disallowing reconnects
    if let Some(state) = measurement.write().unwrap().as_mut() {
        state.is_finalizing = true;
    }

    // Notify all workers that the measurement is over
    let end = Instruction {
        instruction_type: Some(instruction::InstructionType::End(End { code: 0 })),
    };
    let senders: Vec<_> = workers.lock().unwrap().clone();
    for sender in &senders {
        let _ = sender.send(Ok(end.clone())).await;
        sender.finished();
    }

    // Wait for all workers to finish
    while measurement.read().unwrap().is_some() {
        tokio::time::sleep(Duration::from_secs(1)).await;
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
    // Discovery mode wraps hitlist addresses in Discovery tasks (Probe tasks otherwise)
    let is_discovery = matches!(&strategy, DistributionStrategy::Discovery { .. });
    // Tracemap interleaves follow-up trace probes with session seeding, like discovery modes
    let has_follow_ups = is_discovery || is_tracemap;
    let is_any_protocol = config.is_any;
    let origin_ids = config.origin_ids;
    let is_responsive = matches!(
        strategy,
        DistributionStrategy::Discovery {
            is_responsive: true
        }
    );

    // Wait for the last tasks being sent (accounting for repeated probes)
    let repeat_secs = (config.nprobes.saturating_sub(1)) as u64 * config.probe_interval;
    let cooldown_secs = if is_broadcast || is_responsive {
        // Also wait for the inter-worker staggering of the last broadcast batch
        (config.number_of_probing_workers as u64 * config.worker_interval) + repeat_secs + 1
    } else {
        repeat_secs + 1
    };

    let mut probing_rate_interval = config.probing_rate_interval;

    let (all_addresses, initial_addresses) = if is_any_protocol {
        // Keep track of all hitlist targets, and targets discovered for --any
        let addrs = config.hitlist;
        let first_is_v6 = origin_ids[0].1;
        let initial: Vec<Address> = addrs
            .iter()
            .filter(|addr| addr.is_v6() == first_is_v6)
            .cloned()
            .collect();
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

    // nprobes: measurement probes are repeated (by the worker), discovery probes are not
    let task_nprobes = if has_follow_ups { 1 } else { config.nprobes };
    let inter_worker_interval = config.worker_interval;

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
                        inter_worker_interval,
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
                        .map(|addr| {
                            make_task(addr, is_discovery, round.current_origin_id, task_nprobes)
                        })
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
                    send_to_workers(
                        &config.workers,
                        worker_id,
                        Instruction {
                            instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                                tasks,
                            })),
                        },
                        inter_worker_interval,
                    )
                    .await;
                }
            }

            // Check if the measurement is finished
            if round.hitlist_exhausted {
                if has_follow_ups || is_any_protocol {
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

        // Discovery and --any handle the cooldown inside the loop; other modes sleep here
        if !has_follow_ups && !is_any_protocol {
            info!("[Orchestrator] All tasks sent. Awaiting a {cooldown_secs}-second cooldown.");
            tokio::time::sleep(Duration::from_secs(cooldown_secs)).await;
        }

        finalize_measurement(&config.workers, &config.measurement).await;
    });
}

/// Live task distributor for feed-based measurements.
///
/// Prioritizes follow-up tasks for workers (--discovery, or --any).
/// Drains targets up to the probing rate (optinally enforced by the orchestrator).
///
/// Measurement probes are optionally repeated by the worker (nprobes > 1).
///
/// The measurement ends when the feed has closed (the CLI ended its stream or
/// disconnected) and all follow-ups and pending discoveries have resolved,
/// or when no probing workers remain.
pub fn distribute_live_tasks(
    mut feed: mpsc::Receiver<LiveTarget>,
    measurement: MeasurementHandle,
    workers: WorkerRegistry,
    probing_rate: u32,
    worker_interval: u64,
    probe_interval: u64,
    is_responsive: bool,
) {
    info!("[Orchestrator] Starting Live Task Distributor.");

    spawn(async move {
        let mut tick_interval = tokio::time::interval(Duration::from_secs(1));
        tick_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut current_index: usize = 0;
        let batch_capacity = probing_rate as usize;
        let mut feed_closed = false;
        let mut max_nprobes: u32 = 1; // Max nprobes used

        loop {
            tick_interval.tick().await;

            // Drain follow-up tasks from the worker and worker-set stacks
            let (follow_ups, set_follow_ups, probing_workers, pending_count) = {
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

                let mut set_follow_ups: Vec<(Vec<u32>, Vec<Task>)> = Vec::new();
                if let Some(live) = state.live.as_mut() {
                    for (worker_ids, stack) in live.set_stacks.iter_mut() {
                        if !stack.is_empty() {
                            let n = stack.len().min(batch_capacity);
                            set_follow_ups.push((worker_ids.clone(), stack.drain(..n).collect()));
                        }
                    }
                }

                let pending_count = state.live.as_ref().map_or(0, |live| live.pending.len());
                (
                    follow_ups,
                    set_follow_ups,
                    state.probing_workers.clone(),
                    pending_count,
                )
            };

            let follow_up_count: usize = follow_ups.iter().map(|(_, tasks)| tasks.len()).sum::<usize>()
                + set_follow_ups.iter().map(|(_, tasks)| tasks.len()).sum::<usize>();
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
                    worker_interval,
                )
                .await;
            }
            // Worker-set follow-ups are staggered by the worker interval
            for (worker_ids, tasks) in set_follow_ups {
                send_staggered(
                    &workers,
                    &worker_ids,
                    Instruction {
                        instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                            tasks,
                        })),
                    },
                    worker_interval,
                );
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

            // Partition the batch by worker-set assignment, registering discovery targets
            let mut per_set: HashMap<Vec<u32>, Vec<Task>> = HashMap::new();
            let mut broadcast: Vec<Task> = Vec::new();
            {
                let mut lock = measurement.write().unwrap();
                let Some(state) = lock.as_mut() else {
                    warn!("[Orchestrator] Measurement no longer active");
                    break;
                };

                for mut target in batch {
                    let Some(dst) = target.dst else { continue };
                    max_nprobes = max_nprobes.max(target.nprobes);

                    // Resolve the target's worker selection (drops targets with no probing worker)
                    let Some(sel) = resolve_worker_sel(
                        std::mem::take(&mut target.worker_ids),
                        &probing_workers,
                        dst,
                    ) else {
                        continue;
                    };

                    // Ignore origin:any when there is only a single origin of the target's IP version
                    if target.origin_id == ANY_ORIGIN
                        && state
                            .live
                            .as_ref()
                            .is_some_and(|l| l.origin_ids_for(dst.is_v6()).len() == 1)
                    {
                        target.origin_id = ALL_ORIGINS;
                    }

                    // Check whether discovery probes are needed (--any or --responsive)
                    let is_origin_any = target.origin_id == ANY_ORIGIN;
                    let needs_probe_gate = is_origin_any || (is_responsive && sel.is_multi());
                    if needs_probe_gate {
                        // The discovery probe is sent by a single worker (round-robin)
                        let probe_worker = match &sel {
                            WorkerSel::Any | WorkerSel::All => {
                                current_index %= probing_workers.len();
                                let id = probing_workers[current_index];
                                current_index += 1;
                                id
                            }
                            WorkerSel::Set(ids) => {
                                let id = ids[current_index % ids.len()];
                                current_index += 1;
                                id
                            }
                        };

                        let Some(live) = state.live.as_mut() else {
                            continue;
                        };

                        // origin:any starts with the first origin of the target's IP version
                        let (origin_id, next_origin_idx) = if is_origin_any {
                            let Some(&first) = live.origin_ids_for(dst.is_v6()).first() else {
                                warn!(
                                    "[Orchestrator] Dropping target {dst}: no origin of its IP version is configured"
                                );
                                continue;
                            };
                            (first, Some(1))
                        } else {
                            (target.origin_id, None)
                        };

                        // For a single-worker origin:any target send measurement probes iteratively
                        let probe_is_measurement = is_origin_any && !sel.is_multi();

                        live.pending.insert(
                            dst,
                            PendingTarget {
                                worker_sel: sel,
                                discovery_worker: probe_worker,
                                next_origin_idx,
                                probe_is_measurement,
                                nprobes: target.nprobes,
                                deadline: std::time::Instant::now()
                                    + Duration::from_secs(LIVE_DISCOVERY_TIMEOUT_SECS),
                            },
                        );

                        // A discovery probe is sent once, a measurement probe is repeated (nprobes)
                        let count = if probe_is_measurement {
                            target.nprobes
                        } else {
                            1
                        };
                        per_set.entry(vec![probe_worker]).or_default().push(make_task(
                            dst,
                            !probe_is_measurement,
                            origin_id,
                            count,
                        ));
                        continue;
                    }

                    // Regular probe task
                    let task = make_task(dst, false, target.origin_id, target.nprobes);
                    match sel {
                        WorkerSel::Any => {
                            // Round-robin across probing workers
                            current_index %= probing_workers.len();
                            per_set
                                .entry(vec![probing_workers[current_index]])
                                .or_default()
                                .push(task);
                            current_index += 1;
                        }
                        WorkerSel::All => broadcast.push(task),
                        WorkerSel::Set(ids) => {
                            per_set.entry(ids).or_default().push(task);
                        }
                    }
                }
            }

            // Send the per-worker-set tasks, staggered by the worker interval
            for (worker_ids, tasks) in per_set {
                send_staggered(
                    &workers,
                    &worker_ids,
                    Instruction {
                        instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                            tasks,
                        })),
                    },
                    worker_interval,
                );
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
                    worker_interval,
                )
                .await;
            }

            // Done once the feed is closed and all outstanding work has resolved
            if feed_closed && dispatched == 0 && follow_up_count == 0 && pending_count == 0 {
                break;
            }
        }

        // Wait for the last probes to be sent and their replies
        let worker_count = workers.lock().unwrap().len() as u64;
        let repeat_secs = (max_nprobes as u64 - 1) * probe_interval;
        let cooldown_secs = worker_count * worker_interval + repeat_secs + REPLY_GRACE_SECS;
        info!("[Orchestrator] Awaiting a {cooldown_secs}-second cooldown.");
        tokio::time::sleep(Duration::from_secs(cooldown_secs)).await;

        finalize_measurement(&workers, &measurement).await;
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

/// Iteratively go over the origins (depending on IP version).
/// At each iteration get the currently unresolved targets, which are probed.
/// Returns `true` if a new round was started (caller should `continue` the loop),
/// `false` if all protocols are exhausted or all targets are resolved.
fn try_next_any_protocol(
    measurement: &MeasurementHandle,
    all_addresses: &[Address],
    origin_ids: &[(u32, bool)],
    round: &mut RoundState,
) -> bool {
    while round.origin_index + 1 < origin_ids.len() {
        round.origin_index += 1;
        let (next_origin_id, next_is_v6) = origin_ids[round.origin_index];

        let lock = measurement.read().unwrap();
        let state = lock.as_ref().unwrap();
        let resolved_count = state.resolved_targets.len();

        // Collect same-version addresses that have not responded yet
        let unresolved: Vec<Address> = all_addresses
            .iter()
            .filter(|addr| addr.is_v6() == next_is_v6 && !state.resolved_targets.contains(addr))
            .cloned()
            .collect();
        let unresolved_count = unresolved.len();
        drop(lock);

        if unresolved_count == 0 {
            continue; // No unresolved targets for this origin's IP version
        }

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

    let lock = measurement.read().unwrap();
    let resolved_count = lock.as_ref().map(|s| s.resolved_targets.len()).unwrap_or(0);
    let total = all_addresses.len();
    info!(
        "[Orchestrator] --any: all protocols exhausted. {resolved_count}/{total} targets resolved."
    );

    false // No more protocols to try
}
