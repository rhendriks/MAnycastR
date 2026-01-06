use crate::orchestrator::OngoingMeasurement;
use futures_core::Stream;
use log::warn;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tokio::sync::mpsc;

/// Special Receiver struct that notices when the CLI disconnects.
/// When a CLI disconnects we cancel all open measurements. We set this orchestrator as available for receiving a new measurement.
/// Furthermore, if a measurement is active, we send a termination message to all workers to quit the current measurement.
pub struct CLIReceiver<T> {
    /// Receiver that connects to the CLI
    pub(crate) inner: mpsc::Receiver<T>,
    /// Shared measurement data for the current ongoing measurement, None if no measurement is ongoing
    pub(crate) ongoing_measurement: Arc<RwLock<Option<OngoingMeasurement>>>,
}

impl<T> Stream for CLIReceiver<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.inner.poll_recv(cx)
    }
}

impl<T> Drop for CLIReceiver<T> {
    fn drop(&mut self) {
        let mut measurement_lock = self.ongoing_measurement.write().unwrap();

        // If there is an active measurement we need to cancel it and notify the workers
        if measurement_lock.is_some() {
            warn!(
                "[Orchestrator] CLI dropped during an active measurement, terminating measurement"
            );
            *measurement_lock = None; // No longer an active measurement
        }
    }
}
