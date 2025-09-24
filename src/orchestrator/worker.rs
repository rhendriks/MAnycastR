use std::collections::HashMap;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use futures_core::Stream;
use log::{info, warn};
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use crate::custom_module::manycastr::{Address, TaskResult};
use crate::orchestrator::CliHandle;
use crate::orchestrator::worker::WorkerStatus::{Idle, Probing, Listening, Disconnected};

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
/// When a worker drops we update the open_measurements such that the orchestrator knows this worker is not participating in any measurements.
/// Furthermore, we send a message to the CLI if it is currently performing a measurement, to let it know this worker is finished.
///
/// Finally, remove this worker from the worker list.
///
/// # Fields
///
/// * 'inner' - the receiver that connects to the worker
/// * 'open_measurements' - a list of the current open measurements
/// * 'cli_sender' - the sender that connects to the CLI
/// * 'hostname' - the hostname of the worker
/// * 'status' - the status of the worker, used to determine if it is connected or not
pub struct WorkerReceiver<T> {
    pub(crate) inner: mpsc::Receiver<T>,
    pub(crate) open_measurements: Arc<Mutex<HashMap<u32, u32>>>,
    pub(crate) cli_sender: CliHandle,
    pub(crate) hostname: String,
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

        // Handle the open measurements that involve this worker
        let mut open_measurements = self.open_measurements.lock().unwrap();
        if !open_measurements.is_empty() {
            for (m_id, remaining) in open_measurements.clone().iter() {
                // If this measurement is already finished
                if remaining == &0 {
                    continue;
                }
                // If this is the last worker for this open measurement
                if remaining == &1 {
                    // The orchestrator no longer has to wait for this measurement
                    open_measurements.remove(m_id);

                    warn!("[Orchestrator] The last worker for a measurement dropped, sending measurement finished signal to CLI");
                    match self
                        .cli_sender
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap()
                        .try_send(Ok(TaskResult::default()))
                    {
                        Ok(_) => (),
                        Err(_) => warn!(
                            "[Orchestrator] Failed to send measurement finished signal to CLI"
                        ),
                    }
                } else {
                    // One less worker for this measurement
                    *open_measurements.get_mut(m_id).unwrap() -= 1;
                }
            }
        }

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

        info!(
            "[Orchestrator] Worker {} dropped",
            self.hostname
        );
    }

    pub fn is_probing(&self) -> bool {
        *self.status.lock().unwrap() == Probing
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