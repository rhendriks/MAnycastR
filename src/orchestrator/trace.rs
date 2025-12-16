use crate::custom_module::manycastr::{task, Address, Task, Trace};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Traceroute parameters
const MAX_CONSECUTIVE_FAILURES: u8 = 3; // Unreachable identifier
pub const HOP_TIMEOUT: Duration = Duration::from_secs(1); // 1-second timeout
pub const MAX_TTL: u8 = 30; // Prevent routing loops

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
    /// Origin used for the traceroute (source address, port mappings)
    pub origin_id: u32,
    /// Current TTL being traced
    pub current_ttl: u8,
    /// Consecutive failures counter
    pub consecutive_failures: u8,
    /// Time at which last trace was performed
    pub last_updated: Instant,
}

// TODO as we keep state for traceroutes, we can avoid encoding the TTL in traceroute probes (and re-use the field)
/// Identify unique TraceSession TODO encode a unique ID in traceroute packets instead?
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
/// * 'worker_stacks' - Shared stack to put Trace tasks in for workers.
/// * 'sessions' - Shared map that tracks ongoing sessions.
/// * 'active_workers' - Break signal that is set to None when measurement is finished
pub fn check_trace_timeouts(
    worker_stacks: Arc<Mutex<HashMap<u32, VecDeque<Task>>>>,
    session_tracker: Arc<Mutex<SessionTracker>>,
    active_workers:  Arc<Mutex<Option<u32>>>,
) {
    loop {
        println!("[x] checking trace timeouts");

        // Check if we are finished
        {
            let worker_guard = active_workers.lock().unwrap();
            if worker_guard.is_none() {
                println!("[x] FINISHED");
                break;
            }
        }

        // Keep track of tasks to send to the workers
        let mut tasks_to_send = Vec::new();
        let now = Instant::now();

        {
            // Lock tracker
            let mut session_tracker = session_tracker.lock().unwrap();


            // Iteratively check top of the stack (oldest sessions) to see if they timed out
            while let Some((_id, deadline)) = session_tracker.expiration_queue.front() {
                if *deadline > now {
                    // Deadline is in the future
                    println!("[x] deadline in the future");
                    break; // release lock and exit
                }
                println!("[x] expired!!!!");
                // Pop candidate
                let (id, _old_deadline) = session_tracker.expiration_queue.pop_front().unwrap();

                // Get session belonging to identifier
                let should_recycle = if let Some(session) = session_tracker.sessions.get_mut(&id) {
                    // Verify the session is still timed out (might have been updated)
                    let expiration = session.last_updated + HOP_TIMEOUT;

                    if expiration > now {
                        // Still alive (received update during check) -> update deadline
                        Some((id.clone(), expiration))
                    } else {
                        // No longer alive
                        session.consecutive_failures += 1;
                        session.last_updated = now;
                        session.current_ttl += 1;

                        // Check termination conditions
                        if session.consecutive_failures > MAX_CONSECUTIVE_FAILURES
                            || session.current_ttl > MAX_TTL
                        {
                            println!("[xxx] trace failed for dst {} with failures {} and current_ttl {}", session.target.unwrap(), session.consecutive_failures, session.current_ttl);
                            // Remove from tracker
                            session_tracker.sessions.remove(&id);
                            None // Nothing to update
                        } else {
                            // Measure the next hop (current hop timed out)

                            println!("[x] Hop timed out performing follow-up trace from {} to {} with TTL {}", session.worker_id, session.target.unwrap(), session.current_ttl);

                            tasks_to_send.push((
                                session.worker_id,
                                Task {
                                    task_type: Some(task::TaskType::Trace(Trace {
                                        dst: session.target,
                                        ttl: session.current_ttl as u32,
                                        origin_id: session.origin_id,
                                    })),
                                },
                            ));

                            // Update deadline for current session
                            Some((id.clone(), now + HOP_TIMEOUT))
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
        }

        // Put tasks in worker stacks
        if !tasks_to_send.is_empty() {
            let mut stacks = worker_stacks.lock().unwrap();
            for (worker_id, task_to_send) in tasks_to_send {
                stacks.entry(worker_id).or_default().push_back(task_to_send);
            }
        }

        // Sleep for the timeout interval before checking timeouts again
        thread::sleep(HOP_TIMEOUT);
    }

    println!("[x] [Orchestrator] Finished trace timeout thread")
}
