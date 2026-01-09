use crate::custom_module::manycastr::{task, DiscoveryReply, Probe, Task, Trace, TraceReply};
pub(crate) use crate::orchestrator::trace::{SessionTracker, TraceIdentifier, TraceSession};
use crate::orchestrator::TracerouteConfig;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Takes a TaskResult containing discovery probe replies for --responsive or --latency probes.
///
/// # Arguments
/// * `discovery_results` - List of discovery results
/// * `worker_id` - worker that will perform the follow-up tasks
/// * `worker_stacks` - shared stack to put worker tasks in
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
/// * `discovery_results` - List of discovery results
/// * `worker_id` - Worker that received the discovery results and will perform the traceroute
/// * `worker_stacks` - Shared stack to put follow-up tasks into
/// * `traceroute_config`
pub fn trace_discovery_handler(
    discovery_results: Vec<DiscoveryReply>,
    catcher_id: u32,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
    traceroute_config: &mut TracerouteConfig,
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
            current_ttl: traceroute_config.initial_hop as u8,
            consecutive_failures: 0,
            last_updated: Instant::now(),
        };

        traceroute_config
            .session_tracker
            .sessions
            .insert(identifier.clone(), session);
        // Add deadline
        let deadline = Instant::now() + Duration::from_secs(traceroute_config.timeout);
        traceroute_config
            .session_tracker
            .expiration_queue
            .push_back((identifier, deadline));

        tasks_to_send.push(Task {
            task_type: Some(task::TaskType::Trace(Trace {
                dst: target,
                ttl: traceroute_config.initial_hop,
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
/// * `trace_replies` - A list of traceroute results
/// * `worker_stacks` - Stacks for workers to put follow-up trace tasks into
/// * `traceroute_config` - Configuration and state for the ongoing traceroute measurement
pub fn trace_replies_handler(
    trace_replies: Vec<TraceReply>,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
    traceroute_config: &mut TracerouteConfig,
) {
    let session_tracker = &mut traceroute_config.session_tracker;

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

            if session.current_ttl > traceroute_config.max_hops as u8
                || trace_reply.hop_addr.unwrap() == trace_reply.trace_dst.unwrap()
            {
                // Routing loop or destination reached -> close session
                remove = true;
            } else {
                // Send tracetask for the next hop
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
            session_tracker.sessions.remove(&identifier);
        }
    }
}
