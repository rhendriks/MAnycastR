use crate::custom_module::manycastr::{Address, ReplyBatch};
use crate::orchestrator::worker::WorkerStatus::{Disconnected, Idle, Listening, Probing};
use crate::orchestrator::{CliHandle, OngoingMeasurement};
use futures_core::Stream;
use log::{info, warn};
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;

#[derive(Debug, Clone, Copy)]
pub enum WorkerStatus {
    Idle,         // Connected but not participating in a measurement
    Probing,      // Probing for a measurement
    Listening,    // Only listening for probe replies for a measurement
    Disconnected, // Disconnected
}

impl fmt::Display for WorkerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Idle => "IDLE",
            Probing => "PROBING",
            Listening => "LISTENING",
            Disconnected => "DISCONNECTED",
        };
        write!(f, "{s}")
    }
}

impl PartialEq for WorkerStatus {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Idle, Idle)
                | (Probing, Probing)
                | (Listening, Listening)
                | (Disconnected, Disconnected)
        )
    }
}

impl PartialEq<WorkerStatus> for Mutex<WorkerStatus> {
    fn eq(&self, other: &WorkerStatus) -> bool {
        let status = self.lock().unwrap();
        *status == *other
    }
}

/// Special Receiver struct that notices when the worker disconnects.
/// When a worker drops we update the active worker counter such that the orchestrator knows this worker is not participating in any measurements.
/// Furthermore, we send a message to the CLI if it is currently performing a measurement, to let it know this worker is finished.
pub struct WorkerReceiver<T> {
    /// The inner receiver that connects to the worker
    pub(crate) inner: mpsc::Receiver<T>,
    /// Shared counter of the number of active workers in the current measurement (None if no measurement is active)
    pub(crate) ongoing_measurement: Arc<RwLock<Option<OngoingMeasurement>>>,
    /// Sender that connects to the CLI
    pub(crate) cli_sender: CliHandle,
    /// The hostname of the worker
    pub(crate) hostname: String,
    /// Worker ID
    pub(crate) worker_id: u32,
    /// The status of the worker, used to determine if it is connected or not
    pub(crate) status: Arc<Mutex<WorkerStatus>>,
}

impl<T> Stream for WorkerReceiver<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.inner.poll_recv(cx)
    }
}

impl<T> Drop for WorkerReceiver<T> {
    fn drop(&mut self) {
        warn!("[Orchestrator] Worker {} lost connection", self.hostname);

        let mut should_notify_cli = false;
        let worker_id = self.worker_id;

        {
            let status = *self.status.lock().unwrap();
            let is_participating = status == Probing || status == Listening;

            // If this worker is participating, update the active_workers counter
            if is_participating {
                let mut measurement_lock = self.ongoing_measurement.write().unwrap();

                if let Some(ref mut measurement) = *measurement_lock {
                    // Remove from probing list if they were a prober
                    measurement.probing_workers.retain(|&id| id != worker_id);

                    // Decrement the participating workers counter
                    if measurement.workers_count <= 1 {
                        // This was the last worker
                        info!(
                            "[Orchestrator] Last active worker ({}) dropped. Measurement is over.",
                            self.hostname
                        );
                        *measurement_lock = None; // Reset the state
                        should_notify_cli = true;
                    } else {
                        measurement.workers_count -= 1;
                    }
                }
            }
        }

        // Set the status to Disconnected
        *self.status.lock().unwrap() = Disconnected;

        // Notify the CLI if the measurement is finished now
        if should_notify_cli {
            if let Some(cli_tx_lock) = self.cli_sender.lock().unwrap().as_ref() {
                if let Err(e) = cli_tx_lock.try_send(Ok(ReplyBatch::default())) {
                    warn!(
                        "[Orchestrator] Failed to send measurement finished signal to CLI: {}",
                        e
                    );
                }
            }
        }
    }
}

/// Special Sender struct for workers that sends tasks after a delay (based on the Worker interval).
#[derive(Clone)]
pub struct WorkerSender<T> {
    /// Inner sender that connects to the orker
    pub(crate) inner: Sender<T>,
    /// Unique Worker ID
    pub(crate) worker_id: u32,
    /// Worker hostname
    pub(crate) hostname: String,
    /// Status of the Worker (e.g., Listening, Probing, Idle, Connected)
    pub(crate) status: Arc<Mutex<WorkerStatus>>,
    /// Unicast IPv4 address of the Worker (None if unavailable)
    pub(crate) unicast_v4: Option<Address>,
    /// Unicast IPv6 address of the Worker (None if unavailable)
    pub(crate) unicast_v6: Option<Address>,
}
impl<T> WorkerSender<T> {
    /// Checks if the sender is closed
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Sends a task after the specified interval
    pub async fn send(&self, task: T) -> Result<(), mpsc::error::SendError<T>> {
        match self.inner.send(task).await {
            Ok(_) => Ok(()),
            Err(e) => {
                self.cleanup();
                Err(e)
            }
        }
    }

    pub(crate) fn cleanup(&self) {
        // If the worker is disconnected, we set the status to DISCONNECTED
        let mut status = self.status.lock().unwrap();
        *status = Disconnected;

        info!("[Orchestrator] Worker {} dropped", self.hostname);
    }

    pub fn is_participating(&self) -> bool {
        let status = self.status.lock().unwrap();
        *status == Probing || *status == Listening
    }

    pub fn get_status(&self) -> String {
        self.status.lock().unwrap().clone().to_string()
    }

    /// The worker finished its measurement
    pub fn finished(&self) {
        let mut status = self.status.lock().unwrap();
        // Set the status to Idle if it is not Disconnected
        if *status != Disconnected {
            *status = Idle;
        }
    }
}
impl<T> fmt::Debug for WorkerSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WorkerSender {{ worker_id: {}, hostname: {}, status: {} }}",
            self.worker_id,
            self.hostname,
            self.get_status()
        )
    }
}
