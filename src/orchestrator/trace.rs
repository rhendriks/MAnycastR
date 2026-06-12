use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{Address, Reply, ReplyBatch, Task, Trace, TraceReply, task};
use crate::orchestrator::{CliHandle, MeasurementHandle, TracerouteConfig};
use log::warn;
use std::collections::{HashMap, VecDeque};
use std::thread;
use std::time::{Duration, Instant};

/// Session Tracker for fast lookups (based on expiration queue)
#[derive(Debug)]
pub struct SessionTracker {
    pub sessions: HashMap<TraceIdentifier, TraceSession>,
    pub expiration_queue: VecDeque<(TraceIdentifier, Instant)>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            expiration_queue: VecDeque::new(),
        }
    }
}

#[derive(Debug)]
pub struct TraceSession {
    /// Worker from which the traceroute is being performed
    pub worker_id: u32,
    /// Target destination address to which the traceroute is being performed
    pub target: Option<Address>,
    /// Origin used for the traceroute (source address, port mappings) [None if a single origin is used]
    pub origin_id: u32,
    /// How this session advances through TTLs
    pub progress: TraceProgress,
    /// Time at which last trace was performed
    pub last_updated: Instant,
}

/// TTL advancement strategy of a trace session
#[derive(Debug)]
pub enum TraceProgress {
    /// Hop-by-hop walk from initial_hop upward (anycast-traceroute)
    Linear {
        /// Current TTL being traced
        current_ttl: u8,
        /// Consecutive failures counter
        consecutive_failures: u8,
    },
    /// Binary search for the deepest hop that replies with Time Exceeded (tracemap)
    Binary {
        /// Lower search bound: every responding hop found so far is below this TTL
        lo: u8,
        /// Upper search bound: the deepest TTL that may still respond
        hi: u8,
        /// Midpoint TTL at which the current confirmation window started
        mid: u8,
        /// TTL of the probe currently in flight (mid, or a confirmation probe above it)
        probing_ttl: u8,
        /// Remaining confirmation probes before concluding the silent tail starts at mid
        window_left: u8,
    },
}

/// Midpoint of two TTLs without u8 overflow
#[inline]
pub fn ttl_midpoint(lo: u8, hi: u8) -> u8 {
    ((lo as u16 + hi as u16) / 2) as u8
}

/// First-probe TTL for the tracemap binary search.
const TRACEMAP_FIRST_TTL: u8 = 12;

/// Create tracemap binary-search sessions for a batch of (unresponsive) targets and
/// return the initial `Trace` tasks (probing [`TRACEMAP_FIRST_TTL`]) for the probing worker.
///
/// # Arguments
/// * `targets` - Target addresses to map
/// * `worker_id` - Worker that will probe these targets (with the anycast source)
/// * `origin_id` - Origin to probe with
/// * `config` - Traceroute parameters and session tracker
pub fn seed_tracemap_sessions(
    targets: Vec<Address>,
    worker_id: u32,
    origin_id: u32,
    config: &mut TracerouteConfig,
) -> Vec<Task> {
    let lo = config.initial_hop as u8;
    let hi = config.max_hops as u8;
    let mid = TRACEMAP_FIRST_TTL.clamp(lo, hi);
    let now = Instant::now();
    let deadline = now + Duration::from_secs(config.timeout);

    targets
        .into_iter()
        .map(|target| {
            let identifier = TraceIdentifier {
                worker_id,
                target,
                origin_id,
            };

            config.session_tracker.sessions.insert(
                identifier.clone(),
                TraceSession {
                    worker_id,
                    target: Some(target),
                    origin_id,
                    progress: TraceProgress::Binary {
                        lo,
                        hi,
                        mid,
                        probing_ttl: mid,
                        window_left: config.max_failures as u8,
                    },
                    last_updated: now,
                },
            );
            config
                .session_tracker
                .expiration_queue
                .push_back((identifier, deadline));

            Task {
                task_type: Some(task::TaskType::Trace(Trace {
                    dst: Some(target),
                    ttl: mid as u32,
                })),
                origin_id,
            }
        })
        .collect()
}

/// Identify unique TraceSession
#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct TraceIdentifier {
    pub worker_id: u32,
    pub target: Address,
    pub origin_id: u32,
}

/// Check ongoing Trace tasks that have timed out (i.e., a hop didn't respond within the timeout)
///
/// - **Linear** sessions follow up with TTL + 1, terminating after `max_failures`
///   consecutive unresponsive hops
/// - **Binary** sessions (tracemap) first extend the confirmation window past the
///   silent midpoint (to rule out an interior unresponsive hop); once the window is
///   exhausted the silent tail is assumed to start at the midpoint and the search
///   continues in the lower half
///
/// # Arguments
/// * `measurement` - Shared measurement state containing worker_stacks and trace_config
/// * `cli_sender` - Sender handle for forwarding '*' hops to the CLI
pub fn check_trace_timeouts(measurement: MeasurementHandle, cli_sender: CliHandle) {
    // Get traceroute parameters (read once at start — they don't change during a measurement)
    let (timeout, max_hops, max_failures, star_unresponsive) = {
        let lock = measurement.read().unwrap();
        let Some(config) = lock.as_ref().and_then(|state| state.trace_config.as_ref()) else {
            // The measurement was torn down before this thread started
            warn!("[Orchestrator] No active traceroute measurement, stopping timeout checker");
            return;
        };
        (
            config.timeout,
            config.max_hops,
            config.max_failures,
            config.star_unresponsive,
        )
    };

    loop {
        // Check if measurement is finished
        if measurement.read().unwrap().is_none() {
            break;
        }

        // Keep track of tasks to send to the workers
        let mut tasks_to_send = Vec::new();
        // `*` (no-reply) hops to forward to the CLI for timed-out hops: (rx_id, origin_id, reply)
        let mut star_replies: Vec<(u32, u32, TraceReply)> = Vec::new();
        let now = Instant::now();

        {
            // Lock measurement state
            let mut lock = measurement.write().unwrap();
            if let Some(ref mut state) = *lock
                && let Some(ref mut config) = state.trace_config
            {
                let session_tracker = &mut config.session_tracker;

                // Iteratively check top of the stack (oldest sessions) to see if they timed out
                while let Some((_id, deadline)) = session_tracker.expiration_queue.front() {
                    // Deadline is in the future
                    if *deadline > now {
                        break;
                    }
                    // Pop candidate
                    let (id, _old_deadline) = session_tracker.expiration_queue.pop_front().unwrap();

                    // The session may have ended in the meantime (drop from the queue)
                    let Some(session) = session_tracker.sessions.get_mut(&id) else {
                        continue;
                    };

                    // Verify the session is still timed out (might have been updated)
                    let expiration = session.last_updated + Duration::from_secs(timeout);
                    if expiration > now {
                        // Still alive (received update during check) -> re-queue with its new deadline
                        session_tracker.expiration_queue.push_back((id, expiration));
                        continue;
                    }

                    // Hop timed out: emit a '*' hop to the CLI for it, if enabled
                    if star_unresponsive {
                        let timed_out_ttl = match &session.progress {
                            TraceProgress::Linear { current_ttl, .. } => *current_ttl,
                            TraceProgress::Binary { probing_ttl, .. } => *probing_ttl,
                        };
                        star_replies.push((
                            session.worker_id,
                            session.origin_id,
                            TraceReply {
                                tx_id: session.worker_id,
                                trace_dst: session.target,
                                hop_count: timed_out_ttl as u32,
                                ..Default::default() // unresponsive -> None fields
                            },
                        ));
                    }

                    session.last_updated = now;

                    // Advance the session; None means it is finished
                    let next_ttl = match &mut session.progress {
                        TraceProgress::Linear {
                            current_ttl,
                            consecutive_failures,
                        } => {
                            *consecutive_failures += 1;
                            *current_ttl += 1;

                            if *consecutive_failures > max_failures as u8
                                || *current_ttl > max_hops as u8
                            {
                                None
                            } else {
                                Some(*current_ttl)
                            }
                        }
                        TraceProgress::Binary {
                            lo,
                            hi,
                            mid,
                            probing_ttl,
                            window_left,
                        } => {
                            if *window_left > 0 && *probing_ttl < *hi {
                                // Probe the next TTL to rule out an interior unresponsive hop
                                *probing_ttl += 1;
                                *window_left -= 1;
                                Some(*probing_ttl)
                            } else {
                                // Window exhausted: [mid, probing_ttl] is silent → the tail starts at or before mid
                                *hi = mid.saturating_sub(1);
                                if *hi < *lo {
                                    None // Search converged: deepest responder found
                                } else {
                                    *mid = ttl_midpoint(*lo, *hi);
                                    *probing_ttl = *mid;
                                    *window_left = max_failures as u8;
                                    Some(*probing_ttl)
                                }
                            }
                        }
                    };

                    let Some(next_ttl) = next_ttl else {
                        session_tracker.sessions.remove(&id);
                        continue;
                    };

                    // Measure the next hop and re-queue the session with a fresh deadline
                    tasks_to_send.push((
                        session.worker_id,
                        Task {
                            task_type: Some(task::TaskType::Trace(Trace {
                                dst: session.target,
                                ttl: next_ttl as u32,
                            })),
                            origin_id: session.origin_id,
                        },
                    ));
                    session_tracker
                        .expiration_queue
                        .push_back((id, now + Duration::from_secs(timeout)));
                }

                // Put tasks in worker stacks (while we still hold the write lock)
                for (worker_id, task_to_send) in tasks_to_send {
                    state
                        .worker_stacks
                        .entry(worker_id)
                        .or_default()
                        .push_back(task_to_send);
                }
            }
        }

        // Forward '*' hops for timed-out hops to the CLI
        if !star_replies.is_empty() {
            let tx_opt = cli_sender.lock().unwrap().clone();
            if let Some(tx) = tx_opt {
                for (rx_id, origin_id, reply) in star_replies {
                    let _ = tx.blocking_send(Ok(ReplyBatch {
                        rx_id,
                        results: vec![Reply {
                            reply_data: Some(ReplyData::Trace(reply)),
                        }],
                        origin_id,
                    }));
                }
            }
        }

        // Sleep for the timeout interval before checking timeouts again
        thread::sleep(Duration::from_secs(timeout));
    }
}
