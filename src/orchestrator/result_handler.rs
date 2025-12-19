use crate::custom_module::manycastr::{
    task, Probe, DiscoveryReply, Task, Trace, TraceReply,
};
pub(crate) use crate::orchestrator::trace::{SessionTracker, TraceIdentifier, TraceSession};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Takes a TaskResult containing discovery probe replies for --responsive or --latency probes.
///
/// # Arguments
/// * 'discovery_results' - List of discovery results
/// * 'worker_id' - worker that will perform the follow-up tasks
/// * 'worker_stacks' - shared stack to put worker tasks in
pub fn discovery_handler(
    discovery_results: Vec<DiscoveryReply>,
    worker_id: u32,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
) {
    // Get the target addresses from the results
    let responsive_targets: Vec<Task> = discovery_results
        .iter()
        .map(|result| Task {
            task_type: Some(task::TaskType::Probe(Probe { dst: result.src })),
        })
        .collect();

    // Assign follow-up probes to the 'catcher' stack
    worker_stacks
        .entry(worker_id)
        .or_default()
        .extend(responsive_targets);
}

/// Handles discovery replies for traceroute measurements.
/// Initializes a `TraceSession` for a traceroute from the catching worker to the target.
/// Also instruct the catching Worker to send a `Trace` with TTL = 1.
///
/// # Arguments
/// * 'discovery_results' - List of discovery results
/// * 'worker_id' - Worker that received the discovery results and will perform the traceroute
/// * 'worker_stacks' - Shared stack to put follow-up tasks into
/// * 'session_tracker' - Keeps track of ongoing traceroute sessions
/// * 'hop_timeout' - Hop timeout interval before being considered unresponsive
/// * 'initial_hop' - TTL value to start traceroutes with
pub fn trace_discovery_handler(
    discovery_results: Vec<DiscoveryReply>,
    catcher_id: u32,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
    session_tracker: &mut SessionTracker,
    hop_timeout: u64,
    initial_hop: u32,
) {
    let mut tasks_to_send = Vec::new();

    // Discovery replies
    for result in discovery_results {
        // Create an ongoing TraceSession for each discovery reply
        let target = result.src;
        let origin_id = result.origin_id;

        // Create Trace identifier
        let identifier = TraceIdentifier {
            worker_id: catcher_id,
            target: target.unwrap(),
            origin_id,
        };

        // Init Trace session
        let session = TraceSession {
            worker_id: catcher_id,
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
            catcher_id,
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
        let stack = worker_stacks.entry(catcher_id).or_default();
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
/// * 'trace_replies' - A list of traceroute results
/// * 'worker_stacks' - Stacks for workers to put follow-up trace tasks into
/// * 'session_tracker' - Tracker for ongoing trace tasks, to update based on replies received
/// * 'max_hops' - Maximum hop count before terminating trace sessions (default 30)
pub fn trace_replies_handler(
    trace_replies: Vec<TraceReply>,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
    session_tracker: &mut SessionTracker,
    max_hops: u32,
) {
    println!("Received trace replies");

    for trace_reply in trace_replies {
        // Get identifier of corresponding trace
        let identifier = TraceIdentifier {
            worker_id: trace_reply.tx_id,
            target: trace_reply.trace_dst.unwrap(),
            origin_id: trace_reply.origin_id,
        };
        let mut remove = false;

        // Find session of corresponding trace
        if let Some(session) = session_tracker.sessions.get_mut(&identifier) {
            // Update the corresponding trace session
            session.current_ttl += 1;
            session.last_updated = Instant::now();
            session.consecutive_failures = 0;

            if session.current_ttl > max_hops as u8
                || trace_reply.hop_addr.unwrap() == trace_reply.trace_dst.unwrap()
            {
                // Routing loop or destination reached -> close session
                println!(
                    "closing trace session after hop {}",
                    trace_reply.hop_addr.unwrap()
                );

                remove = true;
            } else {
                // Send tracetask for the next hop
                println!("successful hop discovered {} ; discovering next hop from worker {} to dst {} with TTL {}", trace_reply.hop_addr.unwrap(), trace_reply.tx_id, trace_reply.trace_dst.unwrap(), session.current_ttl);

                worker_stacks
                    .entry(trace_reply.tx_id)
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
            println!("removing trace from session tracker {:?}", identifier);
            session_tracker.sessions.remove(&identifier);
        }
    }
}
