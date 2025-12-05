use crate::custom_module::manycastr::{task, Ack, Address, Probe, Task, TaskResult, Trace};
use crate::orchestrator::ALL_WORKERS_INTERVAL;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tonic::{Response, Status};
pub(crate) use crate::orchestrator::trace::{SessionTracker, TraceIdentifier, TraceSession};

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

/// Handles discovery replies for traceroute measurements.
/// Initializes a `TraceSession` for a traceroute from the catching worker to the target.
/// Also instruct the catching Worker to send a `Trace` with TTL = 1.
pub fn trace_discovery_handler(
    task_result: &TaskResult,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
    session_tracker: &mut SessionTracker,
) {
    // Get catcher that received the anycast probe reply
    let catcher = task_result.worker_id;
    let mut tasks_to_send = Vec::new();

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

        session_tracker.sessions.insert(identifier, session);

        tasks_to_send.push(Task {
            task_type: Some(task::TaskType::Trace(Trace {
                dst: target,
                ttl: 1,
                origin_id,
            })),
        });
    }

    // Put tasks in worker stacks
    if !tasks_to_send.is_empty() {
        let stack = worker_stacks.entry(catcher).or_default();
        for task in tasks_to_send {
            stack.push_back(task);
        }
    }
}

/// Awaits `Trace` replies (i.e., ICMP Time Exceeded).
/// Follows up with Time exceeded with the next `Trace` using TTL + 1.
/// Updates the corresponding `TraceSession`.
///
/// If a regular reply (from the target) is received, it closes the `TraceSession`.
pub fn trace_replies_handler(
    task_result: &TaskResult,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
    session_tracker: &mut SessionTracker,
) {
    for result in &task_result.result_list {
        todo!()
    }
}
