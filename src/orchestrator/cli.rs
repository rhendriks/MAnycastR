use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use futures_core::Stream;
use log::warn;
use tokio::sync::mpsc;

/// Special Receiver struct that notices when the CLI disconnects.
///
/// When a CLI disconnects we cancel all open measurements. We set this orchestrator as available for receiving a new measurement.
///
/// Furthermore, if a measurement is active, we send a termination message to all workers to quit the current measurement.
///
/// # Fields
///
/// * 'inner' - the receiver that connects to the CLI
/// * 'm_active' - a boolean value that is set to true when there is an active measurement
/// * 'm_id' - a list of the current open measurements, and the number of workers that are currently working on it
/// * 'open_measurements' - a mapping of measurement IDs to the number of workers that are currently working on it
pub struct CLIReceiver<T> {
    pub(crate) inner: mpsc::Receiver<T>,
    pub(crate) m_active: Arc<Mutex<bool>>,
    pub(crate) m_id: u32,
    pub(crate) open_measurements: Arc<Mutex<HashMap<u32, u32>>>,
}

impl<T> Stream for CLIReceiver<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.inner.poll_recv(cx)
    }
}

impl<T> Drop for CLIReceiver<T> {
    fn drop(&mut self) {
        let mut is_active = self.m_active.lock().unwrap();

        // If there is an active measurement we need to cancel it and notify the workers
        if *is_active {
            warn!("[Orchestrator] CLI dropped during an active measurement, terminating measurement");
        }
        *is_active = false; // No longer an active measurement

        // Remove the current measurement
        let mut open_measurements = self.open_measurements.lock().unwrap();
        open_measurements.remove(&self.m_id);
    }
}