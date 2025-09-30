use crate::custom_module::manycastr::{
    instruction, task, Address, End, Instruction, Probe, Reverse, Task, Tasks,
};
use crate::orchestrator::worker::WorkerSender;
use crate::orchestrator::worker::WorkerStatus::Probing;
use crate::orchestrator::{ALL_WORKERS_DIRECT, ALL_WORKERS_INTERVAL, BREAK_SIGNAL};
use log::{info, warn};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::time::{Instant, Interval};
use tonic::Status;

/// Broadcast task distributor.
/// Distributes tasks from the hitlist in broadcast fashion to all probing workers.
/// Ends the measurement when all probes have been sent.
///
/// Used for --unicast and regular anycast measurements.
///
/// # Arguments
/// * 'dst_addresses' - the hitlist of target addresses to probe
/// * 'probing_rate' - number of tasks to send per interval
/// * 'active_workers' - number of active workers (None if no measurement is active)
/// * 'tx_t' - channel to send tasks to the TaskDistributor
/// * 'probing_rate_interval' - interval at which to send tasks
/// * 'number_of_probing_workers' - number of probing workers
/// * 'worker_interval' - inter-client interval between workers
pub async fn broadcast_distributor(
    dst_addresses: Vec<Address>,
    probing_rate: u32,
    active_workers: Arc<Mutex<Option<u32>>>,
    tx_t: Sender<(u32, Instruction, bool)>,
    mut probing_rate_interval: Interval,
    number_of_probing_workers: usize,
    worker_interval: u64,
) {
    info!("[Orchestrator] Starting Broadcast Task Distributor.");
    spawn(async move {
        // Iterate over the hitlist in chunks of the specified probing rate.
        for chunk in dst_addresses.chunks(probing_rate as usize) {
            if active_workers.lock().unwrap().is_none() {
                warn!("[Orchestrator] Measurement no longer active");
                break;
            }

            // Convert Addresses to a Tasks message
            let tasks = chunk
                .iter()
                .map(|addr| Task {
                    task_type: Some(task::TaskType::Probe(Probe { dst: Some(*addr) })),
                })
                .collect::<Vec<Task>>();

            tx_t.send((
                ALL_WORKERS_INTERVAL,
                Instruction {
                    instruction_type: Some(instruction::InstructionType::Tasks(Tasks { tasks })),
                },
                true,
            ))
            .await
            .expect("Failed to send task to TaskDistributor");

            probing_rate_interval.tick().await;
        }

        // Wait for the workers to finish their tasks
        tokio::time::sleep(Duration::from_secs(
            (number_of_probing_workers as u64 * worker_interval) + 1,
        ))
        .await;

        info!("[Orchestrator] Task distribution finished");

        // Send end instruction to all workers directly to let them know the measurement is finished
        tx_t.send((
            ALL_WORKERS_DIRECT,
            Instruction {
                instruction_type: Some(instruction::InstructionType::End(End { code: 0 })),
            },
            false,
        ))
        .await
        .expect("Failed to send end task to TaskDistributor");

        // Wait till all workers are finished
        while active_workers.lock().unwrap().is_some() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // Close the TaskDistributor channel
        tx_t.send((
            BREAK_SIGNAL,
            Instruction {
                instruction_type: None,
            },
            false,
        ))
        .await
        .expect("Failed to send end task to TaskDistributor");
    });
}

/// Round-robin task distributor.
/// Distributes tasks from the hitlist in a round-robin fashion to the probing workers.
/// Also checks the worker stacks for follow-up tasks and sends them to the appropriate workers.
/// Ends the measurement when all discovery probes have been sent and all stacks are empty.
///
/// Used for --divide and --reverse measurements.
///
/// # Arguments
/// * 'probing_worker_ids' - IDs of the probing workers
/// * 'dst_addresses' - the hitlist of target addresses to probe
/// * 'active_workers' - number of active workers (None if no measurement is active)
/// * 'tx_t' - channel to send tasks to the TaskDistributor
/// * 'probing_rate' - number of tasks to send per interval
/// * 'probing_rate_interval' - interval at which to send tasks
/// * 'number_of_probing_workers' - number of probing workers
/// * 'worker_interval' - inter-client interval between workers
/// * 'is_reverse' - whether the measurement type is --reverse (true)
pub async fn round_robin_distributor(
    probing_worker_ids: Vec<u32>,
    dst_addresses: Vec<Address>,
    active_workers: Arc<Mutex<Option<u32>>>,
    tx_t: Sender<(u32, Instruction, bool)>,
    probing_rate: u32,
    mut probing_rate_interval: Interval,
    number_of_probing_workers: usize,
    worker_interval: u64,
    is_reverse: bool,
) {
    info!("[Orchestrator] Starting Round-Robin Task Distributor.");

    spawn(async move {
        // This cycler gives us the next worker to assign a task to
        let mut sender_cycler = probing_worker_ids.into_iter().cycle();
        // TODO update cycler if a worker disconnects
        // TODO update probing_rate_interval if a worker disconnects

        for chunk in dst_addresses.chunks(probing_rate as usize) {
            if active_workers.lock().unwrap().is_none() {
                warn!("[Orchestrator] CLI disconnected; ending measurement");
                break;
            }

            // Get the current worker ID to send tasks to.
            let worker_id = sender_cycler.next().expect("No probing workers available");

            // Convert Addresses to appropriate Tasks message
            let tasks = if is_reverse {
                // Send Reverse tasks
                chunk
                    .iter()
                    .map(|addr| Task {
                        task_type: Some(task::TaskType::Reverse(Reverse { dst: Some(*addr) })),
                    })
                    .collect::<Vec<Task>>()
            } else {
                // Send Probe tasks
                chunk
                    .iter()
                    .map(|addr| Task {
                        task_type: Some(task::TaskType::Probe(Probe { dst: Some(*addr) })),
                    })
                    .collect::<Vec<Task>>()
            };

            // Send the instruction to the current round-robin worker
            tx_t.send((
                worker_id,
                Instruction {
                    instruction_type: Some(instruction::InstructionType::Tasks(Tasks { tasks })),
                },
                true,
            ))
            .await
            .expect("Failed to send task to TaskDistributor");

            probing_rate_interval.tick().await;
        } // end of round-robin loop

        // Wait for the workers to finish their tasks
        tokio::time::sleep(Duration::from_secs(
            (number_of_probing_workers as u64 * worker_interval) + 1,
        ))
        .await;

        info!("[Orchestrator] Task distribution finished");

        // Send end message to all workers directly to let them know the measurement is finished
        tx_t.send((
            ALL_WORKERS_DIRECT,
            Instruction {
                instruction_type: Some(instruction::InstructionType::End(End { code: 0 })),
            },
            false,
        ))
        .await
        .expect("Failed to send end task to TaskDistributor");

        // Wait till all workers are finished
        while active_workers.lock().unwrap().is_some() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // Close the TaskDistributor channel
        tx_t.send((
            BREAK_SIGNAL,
            Instruction {
                instruction_type: None,
            },
            false,
        ))
        .await
        .expect("Failed to send end task to TaskDistributor");
    });
}

/// Sends discovery tasks to all probing workers in round-robin fashion.
/// Also checks the worker stacks for follow-up tasks and sends them to the appropriate workers.
/// Ends the measurement when all discovery probes have been sent and all stacks are empty.
///
/// Used for --responsive, --latency, and --traceroute measurements.
///
/// # Arguments
/// * 'worker_stacks' - stacks of follow-up tasks for each worker
/// * 'probing_worker_ids' - IDs of the probing workers
/// * 'dst_addresses' - the hitlist of target addresses to probe
/// * 'active_workers' - number of active workers (None if no measurement is active)
/// * 'tx_t' - channel to send tasks to the TaskDistributor
/// * 'probing_rate' - number of tasks to send per interval
/// * 'probing_rate_interval' - interval at which to send tasks
/// * 'number_of_probing_workers' - number of probing workers
/// * 'worker_interval' - inter-client interval between workers
/// * 'is_responsive' - whether the measurement type is --responsive (true) or --latency/--traceroute (false)
pub async fn round_robin_discovery(
    worker_stacks: Arc<Mutex<HashMap<u32, VecDeque<Task>>>>,
    probing_worker_ids: Vec<u32>,
    dst_addresses: Vec<Address>,
    active_workers: Arc<Mutex<Option<u32>>>,
    tx_t: Sender<(u32, Instruction, bool)>,
    probing_rate: u32,
    mut probing_rate_interval: Interval,
    number_of_probing_workers: usize,
    worker_interval: u64,
    is_responsive: bool,
) {
    info!("[Orchestrator] Starting Round-Robin Discovery Task Distributor.");
    let mut cooldown_timer: Option<Instant> = None;

    spawn(async move {
        // This cycler gives us the next worker to assign a task to
        let mut sender_cycler = probing_worker_ids.into_iter().cycle();
        // TODO update cycler if a worker disconnects
        // TODO update probing_rate_interval if a worker disconnects

        // We create a manual iterator over the general hitlist.
        let mut hitlist_iter = dst_addresses.into_iter();
        let mut hitlist_is_empty = false;

        loop {
            if active_workers.lock().unwrap().is_none() {
                warn!("[Orchestrator] CLI disconnected; ending measurement");
                break;
            }

            // Get the current worker ID to send tasks to.
            let worker_id = sender_cycler.next().expect("No probing workers available");

            // Worker to send follow-up tasks to
            let f_worker_id = if is_responsive {
                // --responsive sends follow-up tasks to all probing workers
                ALL_WORKERS_INTERVAL
            } else {
                // --latency and --traceroute send follow-up tasks to the catching worker
                worker_id
            };

            // Check for follow-up tasks
            let follow_up_tasks: Vec<Task> = {
                let mut stacks = worker_stacks.lock().unwrap();
                // Fill up till the probing rate for 'f_worker_id'
                if let Some(follow_up_tasks) = stacks.get_mut(&f_worker_id) {
                    let num_to_take = std::cmp::min(probing_rate as usize, follow_up_tasks.len());

                    follow_up_tasks.drain(..num_to_take).collect::<Vec<Task>>()
                } else {
                    Vec::new() // No follow-up tasks for this worker
                }
            };

            let follow_up_count = follow_up_tasks.len();

            // Send follow-up tasks to 'f_worker_id'
            if !follow_up_tasks.is_empty() {
                let instruction = Instruction {
                    instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                        tasks: follow_up_tasks,
                    })),
                };

                // Send the instruction to the follow-up worker
                tx_t.send((f_worker_id, instruction, true))
                    .await
                    .expect("Failed to send task to TaskDistributor");
            }

            // Get discovery targets
            let remainder_needed = if is_responsive {
                // In responsive mode, we always send a full batch of discovery probes
                probing_rate as usize
            } else {
                // In non-responsive modes, we limit the batch size to the remaining slots
                (probing_rate as usize).saturating_sub(follow_up_count)
            };

            let discovery_tasks = if remainder_needed > 0 && !hitlist_is_empty {
                // Fill up the remainder with new discovery probes from the hitlist
                let discovery_tasks: Vec<Task> = hitlist_iter
                    .by_ref()
                    .take(remainder_needed)
                    .map(|addr| Task {
                        task_type: Some(task::TaskType::Discovery(Probe { dst: Some(addr) })),
                    })
                    .collect();

                // If we could not fill up the entire batch, we mark the hitlist as empty (only once)
                if discovery_tasks.len() < remainder_needed {
                    info!("[Orchestrator] All discovery probes sent, awaiting follow-up probes.");
                    hitlist_is_empty = true;
                }

                discovery_tasks
            } else {
                Vec::new() // No discovery tasks needed
            };

            // Send discovery tasks only to the current worker
            if !discovery_tasks.is_empty() {
                // Send the Tasks to the worker
                let instruction = Instruction {
                    instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                        tasks: discovery_tasks,
                    })),
                };

                // Send the instruction to the current round-robin worker
                tx_t.send((worker_id, instruction, false))
                    .await
                    .expect("Failed to send task to TaskDistributor");
            }

            // Check if we finished sending all discovery probes and all stacks are empty
            if hitlist_is_empty {
                if let Some(start_time) = cooldown_timer {
                    if start_time.elapsed()
                        >= Duration::from_secs(
                            number_of_probing_workers as u64 * worker_interval + 5,
                        )
                    {
                        info!("[Orchestrator] Task distribution finished.");
                        break;
                    }
                } else {
                    // Make sure all stacks are empty before we start the cooldown timer
                    let all_stacks_empty = {
                        let stacks_guard = worker_stacks.lock().unwrap();
                        stacks_guard.values().all(|queue| queue.is_empty())
                    };
                    if all_stacks_empty {
                        info!(
                            "[Orchestrator] No more tasks. Waiting {} seconds for cooldown.",
                            number_of_probing_workers as u64 * worker_interval + 5
                        );
                        cooldown_timer = Some(Instant::now());
                    }
                }
            }

            probing_rate_interval.tick().await;
        } // end of round-robin loop

        // Send end message to all workers directly to let them know the measurement is finished
        tx_t.send((
            ALL_WORKERS_DIRECT,
            Instruction {
                instruction_type: Some(instruction::InstructionType::End(End { code: 0 })),
            },
            false,
        ))
        .await
        .expect("Failed to send end task to TaskDistributor");

        // Wait till all workers are finished
        while active_workers.lock().unwrap().is_some() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // Empty the stacks
        {
            let mut stacks_guard = worker_stacks.lock().unwrap();
            *stacks_guard = HashMap::new();
        }

        // Close the TaskDistributor channel
        tx_t.send((
            BREAK_SIGNAL,
            Instruction {
                instruction_type: None,
            },
            false,
        ))
        .await
        .expect("Failed to send end task to TaskDistributor");
    });
}

/// Reads from a channel containing Tasks and sends them to the workers, at specified inter-client intervals.
/// Sends repeated tasks (at inter-probe interval) if multiple probes per target are configured.
///
/// Used for starting a measurement, sending tasks to the workers, ending a measurement.
///
/// # Arguments
///
/// * 'rx' - the channel containing the tuple (task_ID, task, multiple_times)
///
/// * 'workers' - the list of worker senders to which the tasks will be sent
///
/// * 'inter_client_interval' - the interval in seconds between sending tasks to different workers
///
/// * 'inter_probe_interval' - the interval in seconds between sending multiple probes to the same worker
///
/// * 'number_of_probes' - the number of times to probe the same target (for non-discovery probes)
pub async fn task_sender(
    mut rx: mpsc::Receiver<(u32, Instruction, bool)>,
    workers: Vec<WorkerSender<Result<Instruction, Status>>>,
    inter_client_interval: u64,
    inter_probe_interval: u64,
    number_of_probes: u8,
) {
    // Loop over the tasks in the channel
    while let Some((worker_id, instruction, multiple)) = rx.recv().await {
        let nprobes = if multiple { number_of_probes } else { 1 };

        if worker_id == BREAK_SIGNAL {
            break;
        } else if worker_id == ALL_WORKERS_DIRECT {
            // To all direct (used for 'end measurement' only)
            for sender in &workers {
                sender
                    .send(Ok(instruction.clone()))
                    .await
                    .unwrap_or_else(|e| {
                        sender.cleanup();
                        warn!(
                            "[Orchestrator] Failed to send broadcast task to worker {}: {e:?}",
                            sender.hostname
                        );
                    });
                sender.finished();
            }
        } else if worker_id == ALL_WORKERS_INTERVAL {
            // To all workers with an interval (used for --unicast, anycast, --responsive follow-up probes)
            let mut probing_index = 0;

            for sender in &workers {
                if *sender.status == Probing {
                    let sender_c = sender.clone();
                    let task_c = instruction.clone();
                    spawn(async move {
                        // Wait inter-client probing interval
                        tokio::time::sleep(Duration::from_secs(
                            probing_index * inter_client_interval,
                        ))
                        .await;

                        spawn(async move {
                            for _ in 0..nprobes {
                                sender_c.send(Ok(task_c.clone())).await.unwrap_or_else(|e| {
                                    sender_c.cleanup();
                                    warn!(
                                        "[Orchestrator] Failed to send broadcast task to probing worker {}: {e:?}",
                                        sender_c.hostname
                                    );
                                });
                                // Sleep for the inter-probe interval
                                tokio::time::sleep(Duration::from_secs(inter_probe_interval)).await;
                            }
                        });
                    });
                    probing_index += 1;
                }
            }
        } else {
            // to specific worker (used for --latency follow-up probes)
            if let Some(sender) = workers.iter().find(|s| s.worker_id == worker_id) {
                if nprobes < 2 {
                    sender.send(Ok(instruction)).await.unwrap_or_else(|e| {
                        sender.cleanup();
                        warn!(
                            "[Orchestrator] Failed to send task to worker {}: {e:?}",
                            sender.hostname
                        );
                    });
                } else {
                    // Probe multiple times (in separate thread)
                    let sender_clone = sender.clone();
                    spawn(async move {
                        for _ in 0..number_of_probes {
                            sender_clone
                                .send(Ok(instruction.clone()))
                                .await
                                .unwrap_or_else(|e| {
                                    sender_clone.cleanup();
                                    warn!(
                                        "[Orchestrator] Failed to send task to worker {}: {e:?}",
                                        sender_clone.hostname
                                    );
                                });
                            // Wait inter-probe interval
                            tokio::time::sleep(Duration::from_secs(inter_probe_interval)).await;
                        }
                    });
                }
            } else {
                warn!("[Orchestrator] No sender found for worker ID {worker_id}");
            }
        }
    }

    info!("[Orchestrator] Task distributor finished");
}
