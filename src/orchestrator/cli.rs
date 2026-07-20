use crate::custom_module::manycastr::WorkerStatus::Disconnected;
use crate::custom_module::manycastr::{End, Instruction, instruction};
use crate::orchestrator::{MeasurementHandle, WorkerRegistry};
use futures_core::Stream;
use log::warn;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;

/// Special Receiver struct that notices when the CLI disconnects.
/// When a CLI disconnects we cancel the measurement it was performing (if still active):
/// the measurement state is cleared and all participating workers are sent an abort
/// instruction, making the orchestrator and workers available for a new measurement.
pub struct CLIReceiver<T> {
    /// Receiver that connects to the CLI
    pub(crate) inner: mpsc::Receiver<T>,
    /// All per-measurement state. `None` when idle.
    pub(crate) measurement: MeasurementHandle,
    /// Registry of connected workers (for aborting the measurement on the workers)
    pub(crate) workers: WorkerRegistry,
    /// ID of the measurement this CLI stream belongs to
    pub(crate) m_id: u32,
}

impl<T> Stream for CLIReceiver<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        self.inner.poll_recv(cx)
    }
}

impl<T> Drop for CLIReceiver<T> {
    fn drop(&mut self) {
        // Clear the measurement state, but only if our measurement is still the active one
        let participant_ids: Vec<u32> = {
            let mut lock = self.measurement.write().unwrap();
            match lock.as_ref() {
                Some(state) if state.m_id == self.m_id => {
                    warn!(
                        "[Orchestrator] CLI dropped during an active measurement, terminating measurement"
                    );
                    let ids = state.participants.keys().copied().collect();
                    *lock = None; // No longer an active measurement
                    ids
                }
                // Our measurement already finished (or was replaced by a new one)
                _ => return,
            }
        };

        // Abort the measurement on all participating workers
        let abort = Instruction {
            instruction_type: Some(instruction::InstructionType::End(End { code: 1 })),
        };
        let senders: Vec<_> = self.workers.lock().unwrap().clone();
        for sender in senders {
            if !participant_ids.contains(&sender.worker_id) || sender.get_status() == Disconnected {
                continue;
            }
            if sender.try_send(Ok(abort.clone())).is_err() {
                warn!(
                    "[Orchestrator] Could not send abort instruction to worker {}",
                    sender.hostname
                );
            }
            sender.finished();
        }
    }
}
