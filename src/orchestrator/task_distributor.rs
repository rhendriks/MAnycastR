use crate::custom_module::manycastr::Instruction;
use crate::orchestrator::worker::WorkerSender;
use crate::orchestrator::worker::WorkerStatus::Probing;
use crate::orchestrator::{ALL_WORKERS_DIRECT, ALL_WORKERS_INTERVAL, BREAK_SIGNAL};
use log::{info, warn};
use std::time::Duration;
use tokio::spawn;
use tokio::sync::mpsc;
use tonic::Status;

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
        println!(
            "[Orchestrator] Sending task to worker ID {worker_id} ({} probe(s))",
            nprobes
        );

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
