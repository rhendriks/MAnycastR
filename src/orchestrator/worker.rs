use crate::custom_module::manycastr::{Address, ReplyBatch};
use crate::orchestrator::worker::WorkerStatus::{Disconnected, Idle, Listening, Probing};
use crate::orchestrator::CliHandle;
use futures_core::Stream;
use log::{info, warn};
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
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
///
/// When a worker drops we update the active worker counter such that the orchestrator knows this worker is not participating in any measurements.
/// Furthermore, we send a message to the CLI if it is currently performing a measurement, to let it know this worker is finished.
pub struct WorkerReceiver<T> {
    /// The inner receiver that connects to the worker
    pub(crate) inner: mpsc::Receiver<T>,
    /// Shared counter of the number of active workers in the current measurement (None if no measurement is active)
    pub(crate) active_workers: Arc<Mutex<Option<u32>>>,
    /// Sender that connects to the CLI
    pub(crate) cli_sender: CliHandle,
    /// The hostname of the worker
    pub(crate) hostname: String,
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

        // If this worker is participating, update the active_workers counter
        if (*self.status.lock().unwrap() == Probing || *self.status.lock().unwrap() == Listening)
            && self.active_workers.lock().unwrap().is_some()
        {
            let mut active_workers = self.active_workers.lock().unwrap();
            let count = active_workers.unwrap();
            if count == 1 {
                // Measurement is over, no more active workers
                info!("[Orchestrator] Last active worker dropped, measurement is over... Notifying CLI");
                *active_workers = None;

                match self
                    .cli_sender
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap()
                    .try_send(Ok(ReplyBatch::default()))
                {
                    Ok(_) => (),
                    Err(_) => {
                        warn!("[Orchestrator] Failed to send measurement finished signal to CLI")
                    }
                }
            } else {
                *active_workers = Some(count - 1);
            }
        }

        // Set the status to Disconnected
        let mut status = self.status.lock().unwrap();
        *status = Disconnected;
    }
}

/// Special Sender struct for workers that sends tasks after a delay (based on the Worker interval).
///
/// # Fields
///
/// * inner - the inner sender that connects to the worker
/// * worker_id - the unique ID of the worker
/// * hostname - the hostname of the worker
/// * status - the status of the worker, used to determine if it is connected or not
/// * unicast_v4 - the unicast IPv4 address of the worker, if available
/// * unicast_v6 - the unicast IPv6 address of the worker, if available
#[derive(Clone)]
pub struct WorkerSender<T> {
    pub(crate) inner: Sender<T>,
    pub(crate) worker_id: u32,
    pub(crate) hostname: String,
    pub(crate) status: Arc<Mutex<WorkerStatus>>,
    pub(crate) unicast_v4: Option<Address>,
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

    pub fn is_probing(&self) -> bool {
        *self.status.lock().unwrap() == Probing
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
