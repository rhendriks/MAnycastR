use crate::custom_module::manycastr::controller_client::ControllerClient;
use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::{Address, Origin};
use local_ip_address::{local_ip, local_ipv6};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tonic::transport::Channel;

/// The worker that is run at the anycast PoPs and performs measurements as instructed by the orchestrator.
/// The worker is responsible for establishing a connection with the orchestrator, receiving tasks, and performing measurements.
#[derive(Clone)]
pub struct Worker {
    /// gRPC client to communicate with the orchestrator
    pub(crate) grpc_client: ControllerClient<Channel>,
    /// Hostname of the worker
    pub(crate) hostname: String,
    /// ID of the current measurement (None indicates no active measurement ongoing)
    pub(crate) current_m_id: Arc<Mutex<Option<u32>>>,
    /// Instructions sender to the outbound probing threads
    pub(crate) outbound_txs: Vec<tokio::sync::mpsc::Sender<InstructionType>>,
    /// Atomic boolean to signal the inbound thread to immediately stop listening for packets
    pub(crate) abort_inbound: Arc<AtomicBool>,
}

/// Takes a list of origins, replaces any unspecified unicast addresses with the local addresses,
/// and returns the modified list of origins.
///
/// # Arguments
/// * `origins` - A vector of Origin structs to be modified.
/// * `is_ipv6` - A boolean indicating whether to use the local IPv6 address (true) or IPv4 address (false).
///
/// # Returns
/// * A vector of Origin structs with unspecified unicast addresses replaced by local addresses.
pub fn set_unicast_origins(origins: Vec<Origin>, is_ipv6: bool) -> Vec<Origin> {
    let src_addr = if is_ipv6 {
        local_ipv6().ok().map(Address::from)
    } else {
        local_ip().ok().map(Address::from)
    };

    origins
        .into_iter()
        .map(|mut o| {
            if o.src.is_some_and(|s| s.is_unicast()) {
                o.src = src_addr;
            }
            o
        })
        .collect()
}
