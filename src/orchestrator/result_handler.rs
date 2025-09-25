use std::collections::{HashMap, VecDeque};
use tonic::{Response, Status};
use crate::custom_module::manycastr::{task, Ack, Probe, Task, TaskResult, Trace};
use crate::orchestrator::ALL_WORKERS_INTERVAL;

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
)
    -> Result<Response<Ack>, Status> {
    // Get 'catcher' that received the anycast probes
    let catcher = task_result.worker_id;

    // Get the target addresses from the results
    let responsive_targets: Vec<Task> = task_result
        .result_list
        .iter()
        .map(|result|
            Task {
                task_type: Some(task::TaskType::Probe(
                    Probe {
                        dst: result.src,
                    }
                ))
            }
        )
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
        .map(|result|
        Task {
            task_type: Some(task::TaskType::Probe(
                Probe {
                    dst: result.src,
                }
            ))
        }
        )
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

/// Handles traceroute discovery probe replies, used to determine the catching worker.
/// Instructs that worker to perform an initial TraceTask towards that target.
///
/// Returns a list of TraceTasks to be sent to the catching worker.
pub fn trace_discovery_handler(
    task_result: TaskResult,
    worker_stacks: &mut HashMap<u32, VecDeque<Task>>,
) -> Result<Response<Ack>, Status> {
    // Get catcher that received the anycast probe reply
    let catcher = task_result.worker_id;

    // For each result, create a series of Trace tasks with increasing TTL
    // starting from TTL=1 up to the hop count to the target (capped at 20)
    let trace_tasks: Vec<Task> = task_result.result_list.iter().flat_map(|result| {
        // Get hop count to the target
        let ttl = result.ttl;
        // Default TTL values: 64, 128, 255
        let hop_count = if ttl < 64 {
            64 - ttl
        } else if ttl < 128 {
            128 - ttl
        } else {
            255 - ttl
        };

        // Cap at 20 hops (avoid excessive hops)
        let hop_count = hop_count.min(20);

        // Generate an iterator of Trace task from TTL = 1 up to hop_count
        (1..=hop_count).map(move |i| Task {
            task_type: Some(task::TaskType::Trace(Trace {
                dst: result.src,
                ttl: i,
                origin_id: result.origin_id,
            })),
        })
    }).collect();

    // Assign follow-up trace tasks to the 'catcher' stack
    worker_stacks
        .entry(catcher)
        .or_default()
        .extend(trace_tasks);

    Ok(Response::new(Ack {
        is_success: true,
        error_message: "".to_string(),
    }))
}
