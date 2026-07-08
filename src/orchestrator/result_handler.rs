use crate::custom_module::manycastr::{DiscoveryReply, Probe, Task, Trace, TraceReply, task};
use crate::orchestrator::TracerouteConfig;
pub(crate) use crate::orchestrator::trace::{
    SessionTracker, TraceIdentifier, TraceProgress, TraceSession, ttl_midpoint,
};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Takes a TaskResult containing discovery probe replies for --responsive or --latency probes.
///
/// # Arguments
/// * `discovery_results` - List of discovery results
/// * `worker_id` - worker that will perform the follow-up tasks
/// * `worker_stacks` - shared stack to put worker tasks in
/// * `origin_id` - Origin for which these replies are received
/// * `nprobes` - number of times the worker sends each follow-up probe
pub fn discovery_handler(
    discovery_results: Vec<DiscoveryReply>,
    worker_id: u32,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
    origin_id: u32,
    nprobes: u32,
) {
    // Get the target addresses from the results
    let responsive_targets: Vec<Task> = discovery_results
        .iter()
        .map(|result| Task {
            task_type: Some(task::TaskType::Probe(Probe { dst: result.src })),
            origin_id,
            nprobes,
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
/// * `traceroute_config` - Traceroute parameters
/// * `origin_id` - Origin for which these replies are received
pub fn trace_discovery_handler(
    discovery_results: Vec<DiscoveryReply>,
    catcher_id: u32,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
    traceroute_config: &mut TracerouteConfig,
    origin_id: u32,
) {
    let stack = worker_stacks.entry(catcher_id).or_default();

    // Discovery replies
    for result in discovery_results {
        // Create an ongoing TraceSession for each discovery reply
        let target = result.src;

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
            progress: TraceProgress::Linear {
                current_ttl: traceroute_config.initial_hop as u8,
                consecutive_failures: 0,
            },
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

        stack.push_back(Task {
            task_type: Some(task::TaskType::Trace(Trace {
                dst: target,
                ttl: traceroute_config.initial_hop,
            })),
            origin_id,
            nprobes: 1,
        });
    }
}

/// Awaits `Trace` replies (i.e., ICMP Time Exceeded).
/// Updates the corresponding `TraceSession`, including the timeout, and follows
/// up with the next `Trace` task according to the session's progress strategy:
///
/// - **Linear** (anycast-traceroute): probe TTL + 1
/// - **Binary** (tracemap): the responding TTL becomes the new lower search bound;
///   probe the midpoint of the remaining range
///
/// If a regular reply (from the target) is received, it closes the `TraceSession`.
///
/// # Arguments
/// * `trace_replies` - A list of traceroute results
/// * `worker_stacks` - Stacks for workers to put follow-up trace tasks into
/// * `traceroute_config` - Configuration and state for the ongoing traceroute measurement
///
/// # Returns
/// The replies that matched an active trace session (to be forwarded to the CLI).
/// Replies without a matching session (stray/foreign packets that passed the
/// worker's filters, or replies arriving after their session closed) are dropped.
pub fn trace_replies_handler(
    trace_replies: Vec<TraceReply>,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
    traceroute_config: &mut TracerouteConfig,
    origin_id: u32,
) -> Vec<TraceReply> {
    let max_hops = traceroute_config.max_hops;
    let max_failures = traceroute_config.max_failures;
    let session_tracker = &mut traceroute_config.session_tracker;
    let mut matched = Vec::with_capacity(trace_replies.len());

    for trace_reply in trace_replies {
        // Get identifier of corresponding trace
        let identifier = TraceIdentifier {
            worker_id: trace_reply.tx_id,
            target: trace_reply.trace_dst.unwrap(),
            origin_id,
        };

        // Find session of corresponding trace (drop replies without one)
        let Some(session) = session_tracker.sessions.get_mut(&identifier) else {
            continue;
        };

        let dest_reached = trace_reply.hop_addr.unwrap() == trace_reply.trace_dst.unwrap();
        let target = session.target;

        // Advance the session; None means it is finished
        let next_ttl = match &mut session.progress {
            TraceProgress::Linear {
                current_ttl,
                consecutive_failures,
            } => {
                *current_ttl += 1;
                *consecutive_failures = 0;

                if *current_ttl > max_hops as u8 || dest_reached {
                    // Routing loop or destination reached -> close session
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
                let answered = trace_reply.hop_count as u8;
                if answered < *lo {
                    // Duplicate reply for an already-measured TTL
                    continue;
                }

                if dest_reached {
                    None
                } else {
                    // Deepest responder so far -> search the deeper half
                    *lo = answered + 1;
                    if *lo > *hi {
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

        session.last_updated = Instant::now();

        if let Some(next_ttl) = next_ttl {
            // Send trace task for the next hop
            worker_stacks
                .entry(trace_reply.tx_id)
                .or_default()
                .push_back(Task {
                    task_type: Some(task::TaskType::Trace(Trace {
                        dst: target,
                        ttl: next_ttl as u32,
                    })),
                    origin_id,
                    nprobes: 1,
                });
        } else {
            session_tracker.sessions.remove(&identifier);
        }

        matched.push(trace_reply);
    }

    matched
}
