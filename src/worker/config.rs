use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use tonic::transport::Channel;
use crate::custom_module::manycastr::controller_client::ControllerClient;
use crate::custom_module::manycastr::instruction::InstructionType;

/// The worker that is run at the anycast sites and performs measurements as instructed by the orchestrator.
///
/// The worker is responsible for establishing a connection with the orchestrator, receiving tasks, and performing measurements.
#[derive(Clone)]
pub struct Worker {
    /// gRPC client to communicate with the orchestrator
    pub(crate) grpc_client: ControllerClient<Channel>,
    /// Hostname of the worker
    pub(crate) hostname: String,
    /// Indicates if the worker is currently active in a measurement
    pub(crate) is_active: Arc<Mutex<bool>>,
    /// ID of the current measurement TODO combine with is_active?
    pub(crate) current_m_id: Arc<Mutex<u32>>,
    /// Instructions sender to the outbound probing thread
    pub(crate) outbound_tx: Option<tokio::sync::mpsc::Sender<InstructionType>>,
    /// Atomic boolean to signal the inbound thread to immediately stop listening for packets
    pub(crate) abort_s: Arc<AtomicBool>,
}