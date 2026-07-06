use crate::custom_module::manycastr::controller_client::ControllerClient;
use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::{Address, Origin};
use local_ip_address::{local_ip, local_ipv6};
use log::warn;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tonic::transport::Channel;

/// The worker that is run at the anycast PoPs and performs measurements as instructed by the orchestrator.
/// The worker is responsible for establishing a connection with the orchestrator, receiving tasks, and performing measurements.
pub struct Worker {
    /// gRPC client to communicate with the orchestrator
    pub(crate) grpc_client: ControllerClient<Channel>,
    /// Hostname of the worker
    pub(crate) hostname: String,
    /// ID of the current measurement (None indicates no active measurement ongoing)
    pub(crate) current_m_id: Arc<Mutex<Option<u32>>>,
    /// Instructions senders to the outbound probing threads, paired with their origin ID
    pub(crate) outbound_txs: Vec<(u32, tokio::sync::mpsc::Sender<InstructionType>)>,
    /// Join handles of the outbound probing threads, awaited on graceful end before closing inbound
    pub(crate) outbound_handles: Vec<std::thread::JoinHandle<()>>,
    /// Atomic boolean to signal the inbound thread to immediately stop listening for packets
    pub(crate) abort_inbound: Arc<AtomicBool>,
}

/// Takes a list of origins, replaces any unicast placeholder addresses with the local
/// address of the placeholder's IP version, and returns the modified list of origins.
///
/// Drops unicast origins when no local unicast address of that version can be found.
///
/// # Arguments
/// * `origins` - A vector of Origin structs to be modified.
///
/// # Returns
/// * A vector of Origin structs with unicast placeholders replaced by local addresses.
pub fn set_unicast_origins(origins: Vec<Origin>) -> Vec<Origin> {
    // Resolve the local addresses once (a version is looked up only when an origin needs it)
    let mut local_v4: Option<Option<Address>> = None;
    let mut local_v6: Option<Option<Address>> = None;

    origins
        .into_iter()
        .filter_map(|mut o| {
            if o.is_unicast() {
                let is_ipv6 = o.src.expect("no src").is_v6();
                let src_addr = if is_ipv6 {
                    *local_v6.get_or_insert_with(|| local_ipv6().ok().map(Address::from))
                } else {
                    *local_v4.get_or_insert_with(|| local_ip().ok().map(Address::from))
                };
                match src_addr {
                    Some(addr) => o.src = Some(addr),
                    None => {
                        warn!(
                            "[Worker] No local {} address available; skipping unicast origin {}",
                            if is_ipv6 { "IPv6" } else { "IPv4" },
                            o.origin_id
                        );
                        return None;
                    }
                }
            }
            Some(o)
        })
        .collect()
}
