use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{Address, Reply, ReplyBatch, Task, Trace, TraceReply, task};
use crate::orchestrator::{CliHandle, MeasurementHandle};
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
    /// Current TTL being traced
    pub current_ttl: u8,
    /// Consecutive failures counter
    pub consecutive_failures: u8,
    /// Time at which last trace was performed
    pub last_updated: Instant,
}

/// Identify unique TraceSession
#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct TraceIdentifier {
    pub worker_id: u32,
    pub target: Address,
    pub origin_id: u32,
}

/// Check ongoing Trace tasks that have timed out (i.e., a hop didn't respond for a full second)
/// If the last successful hop was more than 3 hops ago, terminate the Trace task
/// Else follow up the Trace task for TTL + 1
///
/// # Arguments
/// * `measurement` - Shared measurement state containing worker_stacks and trace_config
/// * `cli_sender` - Sender handle for forwarding '*' hops to the CLI
pub fn check_trace_timeouts(measurement: MeasurementHandle, cli_sender: CliHandle) {
    // Get traceroute parameters (read once at start — they don't change during a measurement)
    let (timeout, max_hops, max_failures, star_unresponsive) = {
        let lock = measurement.read().unwrap();
        let state = lock.as_ref().expect("MeasurementState not initialized");
        let config = state
            .trace_config
            .as_ref()
            .expect("TracerouteConfig not initialized");
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

                    // Get session belonging to identifier
                    let should_recycle =
                        if let Some(session) = session_tracker.sessions.get_mut(&id) {
                            // Verify the session is still timed out (might have been updated)
                            let expiration = session.last_updated + Duration::from_secs(timeout);

                            if expiration > now {
                                // Still alive (received update during check) -> update deadline
                                Some((id.clone(), expiration))
                            } else {
                                // No longer alive: Emit a '*' hop to the CLI for it, if enabled
                                if star_unresponsive {
                                    star_replies.push((
                                        session.worker_id,
                                        session.origin_id,
                                        TraceReply {
                                            hop_addr: None, // unresponsive hop → written as `*`
                                            ttl: 0,
                                            rtt: 0.0,
                                            tx_id: session.worker_id,
                                            trace_dst: session.target,
                                            hop_count: session.current_ttl as u32,
                                        },
                                    ));
                                }

                                session.consecutive_failures += 1;
                                session.last_updated = now;
                                session.current_ttl += 1;

                                // Check termination conditions
                                if session.consecutive_failures > max_failures as u8
                                    || session.current_ttl > max_hops as u8
                                {
                                    // Remove from tracker
                                    session_tracker.sessions.remove(&id);
                                    None // Nothing to update
                                } else {
                                    // Measure the next hop (hop timed out)
                                    tasks_to_send.push((
                                        session.worker_id,
                                        Task {
                                            task_type: Some(task::TaskType::Trace(Trace {
                                                dst: session.target,
                                                ttl: session.current_ttl as u32,
                                            })),
                                            origin_id: session.origin_id,
                                        },
                                    ));

                                    // Update deadline for current session
                                    Some((id.clone(), now + Duration::from_secs(timeout)))
                                }
                            }
                        } else {
                            // Session removed during process (drop from tracker)
                            None
                        };

                    // If we need to keep tracking the current session, put it in the end of the queue
                    if let Some(item) = should_recycle {
                        session_tracker.expiration_queue.push_back(item);
                    }
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
