mod probe;
mod record_route;
mod trace;

use log::{info, warn};
use std::num::NonZeroU32;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use tokio::sync::mpsc::Receiver;

use crate::custom_module;
use custom_module::manycastr::Origin;

use pnet::datalink::DataLinkSender;

use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::task::TaskType;
use crate::custom_module::Separated;
use crate::net::packet::get_ethernet_header;
use crate::worker::outbound::probe::send_probe;
use crate::worker::outbound::record_route::send_record_route_probe;
use crate::worker::outbound::trace::send_trace;
use ratelimit_meter::{DirectRateLimiter, LeakyBucket};

const DISCOVERY_WORKER_ID_OFFSET: u32 = u16::MAX as u32;

/// Configuration for the outbound/sending thread
pub struct OutboundConfig {
    /// The unique ID of this specific worker.
    pub worker_id: u16,
    /// A list of source addresses and port values (`Origin`) to send probes from.
    pub tx_origins: Vec<Origin>,
    /// Shared signal to forcefully shut down the worker (e.g., when the CLI disconnects).
    pub abort_outbound: Arc<AtomicBool>,
    /// Indicates if this is a latency measurement.
    pub is_latency: bool,
    /// The unique ID of the measurement.
    pub m_id: u32,
    /// The type of probe to send (e.g., 1 for ICMP, 2 for DNS/A, 3 for TCP).
    pub m_type: u8,
    /// The domain name to query in DNS measurement probes.
    pub qname: String,
    /// An informational URL to be embedded in the probe's payload (e.g., an opt-out link).
    pub info_url: String,
    /// The name of the network interface to send packets from (e.g., "eth0").
    pub if_name: String,
    /// The target rate for sending probes, measured in packets per second (pps).
    pub probing_rate: u32,
    /// Vector of origins to find the matching origin ID for traceroute tasks
    pub origin_map: Option<Vec<Origin>>,
    /// Indicates if the measurement is IPv6 (true) or IPv4 (false).
    pub is_ipv6: bool,
}

/// Starts the outbound worker thread that awaits tasks and sends probes.
///
/// # Arguments
/// * `config` - configuration for the outbound worker thread
/// * `outbound_rx` - on this channel we receive future tasks that are part of the current measurement
/// * `socket_tx` - the sender object to send packets
pub fn outbound(
    config: OutboundConfig,
    mut outbound_rx: Receiver<InstructionType>,
    mut socket_tx: Box<dyn DataLinkSender>,
) {
    thread::Builder::new()
        .name("outbound".to_string())
        .spawn(move || {
            let mut sent = 0u32;
            let mut sent_discovery = 0u32;
            let mut traces_sent = 0u32;
            let mut failed = 0u32;

            // Calculate probing rate (multiple origins multiply the probing rate)
            let total_rate = config.probing_rate * config.tx_origins.len() as u32;
            // Rate limiter bucket
            let mut limiter =
                DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(total_rate).unwrap());

            let ethernet_header = get_ethernet_header(config.is_ipv6, &config.if_name);

            while let Some(instruction) = outbound_rx.blocking_recv() {
                if config
                    .abort_outbound
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    // Forcefully abort the thread (discard any instructions left in the channel)
                    warn!("[Worker outbound] Abort signal received, stopping.");
                    break;
                }

                match instruction {
                    // Measurement finished
                    InstructionType::End(_) => break,
                    // Probe tasks to send
                    InstructionType::Tasks(payload) => {
                        for task in payload.tasks.iter() {
                            match &task.task_type {
                                Some(TaskType::Probe(task)) => {
                                    let (s, f) = send_probe(
                                        &config,
                                        &ethernet_header,
                                        &task.dst.unwrap(),
                                        &mut socket_tx,
                                        &mut limiter,
                                        false, // Not a discovery probe
                                    );
                                    sent += s;
                                    failed += f;
                                }
                                Some(TaskType::Discovery(task)) => {
                                    let (s, f) = send_probe(
                                        &config,
                                        &ethernet_header,
                                        &task.dst.unwrap(),
                                        &mut socket_tx,
                                        &mut limiter,
                                        true, // This is a discovery probe
                                    );
                                    sent_discovery += s;
                                    failed += f;
                                }
                                Some(TaskType::Trace(trace)) => {
                                    let (s, f) = send_trace(
                                        &ethernet_header,
                                        config.worker_id as u32,
                                        config.m_id,
                                        &config.info_url,
                                        trace,
                                        &mut socket_tx,
                                        config.origin_map.as_ref().expect("Missing origin_map"),
                                    );
                                    traces_sent += s;
                                    failed += f;
                                }
                                Some(TaskType::Record(task)) => {
                                    let (s, f) = send_record_route_probe(
                                        &ethernet_header,
                                        &config,
                                        &task.dst.unwrap(),
                                        &mut socket_tx,
                                        &mut limiter,
                                    );
                                    sent += s;
                                    failed += f;
                                }
                                _ => continue, // Invalid task type
                            };
                        }
                    }
                    _ => continue, // Invalid measurement
                };
            }
            info!(
                "[Worker outbound] Finished. Sent: {} ({} discovery), Traces: {}, Failed: {}",
                sent.with_separator(),
                sent_discovery.with_separator(),
                traces_sent.with_separator(),
                failed.with_separator()
            );
        })
        .expect("Failed to spawn outbound thread");
}
