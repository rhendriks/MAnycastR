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
/// * 'active_workers' - a shared counter of the number of active workers in the current measurement (None if no measurement is active)
/// * 'm_id' - a list of the current open measurements, and the number of workers that are currently working on it
pub struct CLIReceiver<T> {
    pub(crate) inner: mpsc::Receiver<T>,
    pub(crate) active_workers: Arc<Mutex<Option<u32>>>,
}

impl<T> Stream for CLIReceiver<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.inner.poll_recv(cx)
    }
}

impl<T> Drop for CLIReceiver<T> {
    fn drop(&mut self) {
        let mut active_workers = self.active_workers.lock().unwrap();

        // If there is an active measurement we need to cancel it and notify the workers
        if active_workers.is_some() {
            warn!("[Orchestrator] CLI dropped during an active measurement, terminating measurement");
            *active_workers = None; // No longer an active measurement
        }
    }
}