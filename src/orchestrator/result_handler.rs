use crate::custom_module::manycastr::{task, Ack, Address, Probe, Task, TaskResult, Trace};
use crate::orchestrator::ALL_WORKERS_INTERVAL;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tonic::{Response, Status};

/// Takes a TaskResult from a worker containing discovery results and inserts it into the
/// 'catcher' (i.e., receiving worker) stack for follow-up probing.
///
/// # Arguments
///
/// * 'task_result' - The TaskResult received from a worker containing anycast discovery probe replies.
/// * 'worker_stacks' - A mutable reference to the HashMap containing stacks of addresses for each worker.
///
/// # Returns
///
/// * 'Result<Response<Ack>, Status>' - An acknowledgment response indicating success or failure.
pub fn symmetric_handler(
    task_result: TaskResult,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
) -> Result<Response<Ack>, Status> {
    // Get 'catcher' that received the anycast probes
    let catcher = task_result.worker_id;

    // Get the target addresses from the results
    let responsive_targets: Vec<Task> = task_result
        .result_list
        .iter()
        .map(|result| Task {
            task_type: Some(task::TaskType::Probe(Probe { dst: result.src })),
        })
        .collect();

    // Assign follow-up probes to the 'catcher' stack
    worker_stacks
        .entry(catcher)
        .or_default()
        .extend(responsive_targets);

    Ok(Response::new(Ack {
        is_success: true,
        error_message: "".to_string(),
    }))
}

/// Takes a TaskResult containing discovery probe replies for --responsive probes.
/// Puts the responsive targets in the worker stack for all workers.
pub fn responsive_handler(
    task_result: TaskResult,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
) -> Result<Response<Ack>, Status> {
    // Get the target addresses from the results
    let responsive_targets: Vec<Task> = task_result
        .result_list
        .iter()
        .map(|result| Task {
            task_type: Some(task::TaskType::Probe(Probe { dst: result.src })),
        })
        .collect();

    // Assign follow-up probes to the 'all workers' stack
    worker_stacks
        .entry(ALL_WORKERS_INTERVAL)
        .or_default()
        .extend(responsive_targets);

    Ok(Response::new(Ack {
        is_success: true,
        error_message: "".to_string(),
    }))
}

#[derive(Debug)]
pub struct TraceSession { // TODO move to appropriate place
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
pub struct TraceIdentifier { // TODO move to appropriate place
    pub worker_id: u32,
    pub target: Address,
    pub origin_id: u32,
}

/// Traceroute parameters
const MAX_CONSECUTIVE_FAILURES: u8 = 3; // Unreachable identifier
const HOP_TIMEOUT: Duration = Duration::from_secs(1); // 1-second timeout
const MAX_TTL: u8 = 30; // Prevent routing loops

/// Handles discovery replies for traceroute measurements.
/// Initializes a `TraceSession` for a traceroute from the catching worker to the target.
/// Also instruct the catching Worker to send a `Trace` with TTL = 1.
pub fn trace_discovery_handler(
    task_result: &TaskResult,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
    trace_sessions: &mut HashMap<TraceIdentifier, TraceSession>,
) {
    // Get catcher that received the anycast probe reply
    let catcher = task_result.worker_id;

    // Discovery replies
    for result in &task_result.result_list {
        // Create an ongoing TraceSession for each discovery reply
        let target = result.src;
        let origin_id = result.origin_id;

        // Create Trace identifier
        let identifier = TraceIdentifier {
            worker_id: catcher,
            target: target.unwrap(),
            origin_id,
        };

        // Init Trace session
        let session = TraceSession {
            worker_id: catcher,
            target,
            origin_id,
            current_ttl: 1,
            consecutive_failures: 0,
            last_updated: Instant::now(),
        };

        // Track Trace session
        trace_sessions.insert(identifier, session);

        // Perform first Trace (TTL = 1) TODO send as batch of tasks (instead of individual tasks)
        worker_stacks
            .entry(catcher)
            .or_default()
            .push_back(Task {
                task_type: Some(task::TaskType::Trace(Trace {
                    dst: target,
                    ttl: 1,
                    origin_id,
                })),
            });
    }
}

/// Awaits `Trace` replies (i.e., ICMP Time Exceeded).
/// Follows up with Time exceeded with the next `Trace` using TTL + 1.
/// Updates the corresponding `TraceSession`.
///
/// If a regular reply (from the target) is received, it closes the `TraceSession`.
pub fn trace_replies_handler(

) {
    todo!()
}


/// Check ongoing Trace tasks that have timed out (i.e., a hop didn't respond for a full second)
/// If the last successful hop was more than 3 hops ago, terminate the Trace task
/// Else follow up the Trace task for TTL + 1
///
/// # Arguments
/// * 'worker_stacks' - Shared stack to put Trace tasks in for workers.
/// * 'sessions' - Shared map that tracks ongoing sessions.
pub fn check_trace_timeouts(
    worker_stacks: Arc<Mutex<HashMap<u32, VecDeque<Task>>>>,
    sessions: Arc<Mutex<HashMap<TraceIdentifier, TraceSession>>>,
) {
    let now = Instant::now();
    let mut finished_sessions = Vec::new();
    let mut tasks_to_send: Vec<(u32, Task)> = Vec::new();


    // TODO do stack-based? (oldest session on top) -> sleep if timeout has not occurred

    for (identifier, session) in sessions.iter_mut() {
        // Check for hop timeout
        if now.duration_since(session.last_updated) > HOP_TIMEOUT {
            // Timeout occurred for the current TTL
            session.consecutive_failures += 1;
            // Update time to now
            session.last_updated = now;
            // Increment TTL
            session.current_ttl += 1;

            // Terminate if 3 consecutive failures or routing loop measured
            if session.consecutive_failures >= MAX_CONSECUTIVE_FAILURES || session.current_ttl > MAX_TTL {
                finished_sessions.push(identifier.clone());
                continue;
            }

            // Send task for next trace
            worker_stacks
                .entry(session.worker_id)
                .or_default()
                .push_back(Task {
                    task_type: Some(task::TaskType::Trace(Trace {
                        dst: session.target,
                        ttl: session.current_ttl as u32,
                        origin_id: session.origin_id,
                    })),
                });
        }
    }

    // Clean up finished traceroutes
    for key in finished_sessions {
        sessions.remove(&key);
    }
}
