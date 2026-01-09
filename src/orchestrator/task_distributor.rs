use crate::custom_module::manycastr::{instruction, End, Instruction, Task, Tasks};
use crate::orchestrator::worker::WorkerSender;
use crate::orchestrator::worker::WorkerStatus::Probing;
use crate::orchestrator::{OngoingMeasurement, ALL_WORKERS_END, BREAK_SIGNAL};
use crate::ALL_WORKERS;
use log::{info, warn};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::time::{Instant, Interval};
use tonic::Status;

pub struct TaskDistributorConfig {
    /// Vector of tasks to distribute
    pub tasks: Vec<Task>,
    /// Active workers (None if no measurement is active)
    pub ongoing_measurement: Arc<RwLock<Option<OngoingMeasurement>>>,
    /// Channel to send tasks to the TaskDistributor
    pub tx_t: Sender<(u32, Instruction, bool)>,
    /// Number of tasks to send per interval (equal to probing rate)
    pub probing_rate: u32,
    /// Interval at which to send tasks
    pub probing_rate_interval: Interval,
    /// Number of probing workers
    pub number_of_probing_workers: usize,
    /// Inter-worker interval between workers
    pub worker_interval: u64,
}

/// Broadcast task distributor.
/// Distributes tasks from the hitlist in broadcast fashion to all probing workers.
/// Ends the measurement when all probes have been sent.
///
/// Used for --unicast and regular anycast measurements.
///
/// # Arguments
/// * `config` - TaskDistributorConfig with all necessary parameters.
pub async fn broadcast_distributor(config: TaskDistributorConfig) {
    info!("[Orchestrator] Starting Broadcast Task Distributor.");
    let mut probing_rate_interval = config.probing_rate_interval;
    spawn(async move {
        // Iterate over the hitlist in chunks of the specified probing rate.
        for chunk in config.tasks.chunks(config.probing_rate as usize) {
            if config.ongoing_measurement.read().unwrap().is_none() {
                warn!("[Orchestrator] Measurement no longer active");
                break;
            }

            config
                .tx_t
                .send((
                    ALL_WORKERS,
                    Instruction {
                        instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                            tasks: chunk.to_vec(),
                        })),
                    },
                    true,
                ))
                .await
                .expect("Failed to send task to TaskDistributor");

            probing_rate_interval.tick().await;
        }

        // Wait for the workers to finish their tasks
        tokio::time::sleep(Duration::from_secs(
            (config.number_of_probing_workers as u64 * config.worker_interval) + 1,
        ))
        .await;

        info!("[Orchestrator] Task distribution finished");

        // Send end instruction to all workers directly to let them know the measurement is finished
        config
            .tx_t
            .send((
                ALL_WORKERS_END,
                Instruction {
                    instruction_type: Some(instruction::InstructionType::End(End { code: 0 })),
                },
                false,
            ))
            .await
            .expect("Failed to send end task to TaskDistributor");

        // Wait till all workers are finished
        while config.ongoing_measurement.read().unwrap().is_some() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // Close the TaskDistributor channel
        config
            .tx_t
            .send((
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
/// Used for --verfploeter and --reverse measurements.
///
/// # Arguments
/// * `config` - TaskDistributorConfig with all necessary parameters.
pub async fn round_robin_distributor(config: TaskDistributorConfig) {
    info!("[Orchestrator] Starting Round-Robin Task Distributor.");
    let mut probing_rate_interval = config.probing_rate_interval;

    // Index to cycle over the probing workers
    let mut current_index = 0;

    spawn(async move {
        for chunk in config.tasks.chunks(config.probing_rate as usize) {
            if config.ongoing_measurement.read().unwrap().is_none() {
                warn!("[Orchestrator] CLI disconnected; ending measurement");
                break;
            }

            // Get the next probing Worker
            let worker_id = {
                let lock = config.ongoing_measurement.read().unwrap();

                // If the measurement was canceled (None), exit the loop
                let measurement = match *lock {
                    Some(ref m) => m,
                    None => {
                        warn!("[Orchestrator] CLI disconnected; ending measurement");
                        break;
                    }
                };

                let workers = &measurement.probing_workers;

                if workers.is_empty() {
                    warn!("[Orchestrator] No more probing workers available, ending measurement.");
                    break;
                }

                current_index %= workers.len();
                let id = workers[current_index];

                // Move to next worker for the next loop iteration
                current_index = (current_index + 1) % workers.len();
                id
            };

            // Send the instruction to the current round-robin worker
            config
                .tx_t
                .send((
                    worker_id,
                    Instruction {
                        instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                            tasks: chunk.to_vec(),
                        })),
                    },
                    true,
                ))
                .await
                .expect("Failed to send task to TaskDistributor");

            probing_rate_interval.tick().await;
        } // end of round-robin loop

        // Wait for the workers to finish their tasks
        tokio::time::sleep(Duration::from_secs(
            (config.number_of_probing_workers as u64 * config.worker_interval) + 1,
        ))
        .await;

        info!("[Orchestrator] Task distribution finished");

        // Send end message to all workers directly to let them know the measurement is finished
        config
            .tx_t
            .send((
                ALL_WORKERS_END,
                Instruction {
                    instruction_type: Some(instruction::InstructionType::End(End { code: 0 })),
                },
                false,
            ))
            .await
            .expect("Failed to send end task to TaskDistributor");

        // Wait till all workers are finished
        while config.ongoing_measurement.read().unwrap().is_some() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // Close the TaskDistributor channel
        config
            .tx_t
            .send((
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
/// * `config` - TaskDistributorConfig with all necessary parameters.
/// * `worker_stacks` - stacks of follow-up tasks for each worker
/// * `is_responsive` - whether the measurement type is --responsive (true) or --latency/--traceroute (false)
pub async fn round_robin_discovery(
    config: TaskDistributorConfig,
    worker_stacks: Arc<Mutex<HashMap<u32, VecDeque<Task>>>>,
    is_responsive: bool,
) {
    info!("[Orchestrator] Starting Round-Robin Discovery Task Distributor.");
    let mut cooldown_timer: Option<Instant> = None;
    let mut probing_rate_interval = config.probing_rate_interval;

    // Index to cycle over the probing workers
    let mut current_index = 0;
    // We create a manual iterator over the general hitlist.
    let mut hitlist_iter = config.tasks.into_iter();

    spawn(async move {
        let mut hitlist_is_empty = false;

        loop {
            // Get the next probing Worker
            let worker_id = {
                let lock = config.ongoing_measurement.read().unwrap();

                // If the measurement was canceled (None), exit the loop
                let measurement = match *lock {
                    Some(ref m) => m,
                    None => {
                        warn!("[Orchestrator] CLI disconnected; ending measurement");
                        break;
                    }
                };

                let workers = &measurement.probing_workers;

                if workers.is_empty() {
                    warn!("[Orchestrator] No more probing workers available, ending measurement.");
                    break;
                }

                current_index %= workers.len();
                let id = workers[current_index];

                // Move to next worker for the next loop iteration
                current_index = (current_index + 1) % workers.len();
                id
            };

            // Worker to send follow-up tasks to
            let f_worker_id = if is_responsive {
                // --responsive sends follow-up tasks to all probing workers
                ALL_WORKERS
            } else {
                // --latency and --traceroute send follow-up tasks to the catching worker
                worker_id
            };

            // Check for follow-up tasks
            let follow_up_tasks: Vec<Task> = {
                let mut stacks = worker_stacks.lock().unwrap();
                // Fill up till the probing rate for 'f_worker_id'
                if let Some(follow_up_tasks) = stacks.get_mut(&f_worker_id) {
                    let num_to_take =
                        std::cmp::min(config.probing_rate as usize, follow_up_tasks.len());

                    follow_up_tasks.drain(..num_to_take).collect::<Vec<Task>>()
                } else {
                    Vec::new() // No follow-up tasks for this worker
                }
            };

            let follow_up_count = follow_up_tasks.len();

            // Send follow-up tasks to 'f_worker_id'
            if !follow_up_tasks.is_empty() {
                println!("sending follow-up task to worker {f_worker_id}");
                let instruction = Instruction {
                    instruction_type: Some(instruction::InstructionType::Tasks(Tasks {
                        tasks: follow_up_tasks,
                    })),
                };

                // Send the instruction to the follow-up worker
                config
                    .tx_t
                    .send((f_worker_id, instruction, true))
                    .await
                    .expect("Failed to send task to TaskDistributor");
            }

            // Get remaining discovery tasks (fill up bucket)
            let remainder_needed = (config.probing_rate as usize).saturating_sub(follow_up_count);

            let discovery_tasks = if remainder_needed > 0 && !hitlist_is_empty {
                // Fill up the remainder with new discovery probes from the hitlist
                let discovery_tasks: Vec<Task> =
                    hitlist_iter.by_ref().take(remainder_needed).collect();

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
                config
                    .tx_t
                    .send((worker_id, instruction, false))
                    .await
                    .expect("Failed to send task to TaskDistributor");
            }

            // Check if we finished sending all discovery probes and all stacks are empty
            if hitlist_is_empty {
                if let Some(start_time) = cooldown_timer {
                    if start_time.elapsed()
                        >= Duration::from_secs(
                            config.number_of_probing_workers as u64 * config.worker_interval + 5,
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
                            config.number_of_probing_workers as u64 * config.worker_interval + 5
                        );
                        cooldown_timer = Some(Instant::now());
                    }
                }
            }

            probing_rate_interval.tick().await;
        } // end of round-robin loop

        // Send end message to all workers directly to let them know the measurement is finished
        config
            .tx_t
            .send((
                ALL_WORKERS_END,
                Instruction {
                    instruction_type: Some(instruction::InstructionType::End(End { code: 0 })),
                },
                false,
            ))
            .await
            .expect("Failed to send end task to TaskDistributor");

        // Wait till all workers are finished
        while config.ongoing_measurement.read().unwrap().is_some() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // Empty the stacks
        {
            let mut stacks_guard = worker_stacks.lock().unwrap();
            *stacks_guard = HashMap::new();
        }

        // Close the TaskDistributor channel
        config
            .tx_t
            .send((
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

/// Reads from a channel containing Tasks and sends them to the workers, at specified inter-worker intervals.
/// Sends repeated tasks (at inter-probe interval) if multiple probes per target are configured.
///
/// Used for starting a measurement, sending tasks to the workers, ending a measurement.
///
/// # Arguments
///
/// * `rx` - the channel containing the tuple (task_ID, task, multiple_times)
/// * `workers` - the list of worker senders to which the tasks will be sent
/// * `inter_worker_interval` - the interval in seconds between sending tasks to different workers
/// * `inter_probe_interval` - the interval in seconds between sending multiple probes to the same worker
/// * `number_of_probes` - the number of times to probe the same target (for non-discovery probes)
pub async fn task_sender(
    mut rx: mpsc::Receiver<(u32, Instruction, bool)>,
    workers: Vec<WorkerSender<Result<Instruction, Status>>>,
    inter_worker_interval: u64,
    inter_probe_interval: u64,
    number_of_probes: u8,
) {
    // Loop over the tasks in the channel
    while let Some((worker_id, instruction, multiple)) = rx.recv().await {
        let nprobes = if multiple { number_of_probes } else { 1 };

        if worker_id == BREAK_SIGNAL {
            break;
        } else if worker_id == ALL_WORKERS_END {
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
        } else if worker_id == ALL_WORKERS {
            // To all workers with an interval (used for --unicast, anycast, --responsive follow-up probes)
            let mut probing_index = 0;

            for sender in &workers {
                if *sender.status == Probing {
                    let sender_c = sender.clone();
                    let task_c = instruction.clone();
                    spawn(async move {
                        // Wait inter-client probing interval
                        tokio::time::sleep(Duration::from_secs(
                            probing_index * inter_worker_interval,
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
