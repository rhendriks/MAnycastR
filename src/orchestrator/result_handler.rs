use crate::custom_module::manycastr::{task, Ack, Probe, Task, TaskResult, Trace};
pub(crate) use crate::orchestrator::trace::{SessionTracker, TraceIdentifier, TraceSession};
use crate::orchestrator::ALL_WORKERS_INTERVAL;
use std::collections::{HashMap, VecDeque};
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

/// Handles discovery replies for traceroute measurements.
/// Initializes a `TraceSession` for a traceroute from the catching worker to the target.
/// Also instruct the catching Worker to send a `Trace` with TTL = 1.
pub fn trace_discovery_handler(
    task_result: &TaskResult,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
    session_tracker: &mut SessionTracker,
    hop_timeout: u64,
    initial_hop: u32,
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
            current_ttl: initial_hop as u8,
            consecutive_failures: 0,
            last_updated: Instant::now(),
        };

        println!("added to session tracker");
        session_tracker.sessions.insert(identifier.clone(), session);
        // Add deadline
        let deadline = Instant::now() + Duration::from_secs(hop_timeout);
        session_tracker
            .expiration_queue
            .push_back((identifier, deadline));

        println!(
            "worker {} started a traceroute towards {} with TTL 1",
            catcher,
            target.unwrap()
        );

        tasks_to_send.push(Task {
            task_type: Some(task::TaskType::Trace(Trace {
                dst: target,
                ttl: initial_hop,
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
/// Updates the corresponding `TraceSession`, including the timeout.
///
/// If a regular reply (from the target) is received, it closes the `TraceSession`.
///
/// # Arguments
/// * 'task_result' - Non-discovery TraceTask replies (either probe replies or trace replies)
/// * 'worker_stacks' - Stacks for workers to put follow-up trace tasks into
/// * 'session_tracker' - Tracker for ongoing trace tasks, to update based on replies received
/// * 'max_hops' - Maximum hop count before terminating trace sessions (default 30)
pub fn trace_replies_handler(
    task_result: &TaskResult,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
    session_tracker: &mut SessionTracker,
    max_hops: u32,
) {
    println!("Received ICMP time exceeded");
    let catcher_worker_id = task_result.worker_id;

    for result in &task_result.result_list {
        if let Some(trace_dst) = result.trace_dst {
            // ICMP TTL exceeded
            // Get identifier of corresponding trace
            let identifier = TraceIdentifier {
                worker_id: catcher_worker_id,
                target: trace_dst,
                origin_id: result.origin_id,
            };
            let mut remove = false;

            // Find session of corresponding trace
            if let Some(session) = session_tracker.sessions.get_mut(&identifier) {
                // Update the corresponding trace session
                session.current_ttl += 1;
                session.last_updated = Instant::now();
                session.consecutive_failures = 0;

                if session.current_ttl > max_hops as u8 || result.src.unwrap() == result.trace_dst.unwrap() {
                    // Routing loop suspected -> close session
                    remove = true;
                } else {
                    // Send tracetask for the next hop
                    println!("successful hop discovered {} ; discovering next hop from worker {} to dst {} with TTL {}", result.src.unwrap(), catcher_worker_id, trace_dst, session.current_ttl);

                    worker_stacks
                        .entry(catcher_worker_id)
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

            if remove {
                session_tracker.sessions.remove(&identifier);
            }
        } else {
            // Probe reply
            let identifier = TraceIdentifier {
                worker_id: catcher_worker_id,
                target: result.src.unwrap(), // Target source address is the traceroute target
                origin_id: result.origin_id,
            };

            // Close session (destination reached)
            session_tracker.sessions.remove(&identifier);
            // Expiration queue will time out as it gets popped and no associated session is found
        }
    }
}
