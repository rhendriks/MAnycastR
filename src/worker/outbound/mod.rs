mod probe;
mod record_route;
mod trace;

use log::{info, warn};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use tokio::sync::mpsc::Receiver;

use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::task::TaskType;
use crate::custom_module::manycastr::{Address, ProtocolType};
use crate::custom_module::Separated;
use crate::worker::outbound::probe::send_probe;
use crate::worker::outbound::record_route::send_record_route_probe;
use crate::worker::outbound::trace::send_trace;
use ratelimit_meter::{DirectRateLimiter, LeakyBucket};
use socket2::{SockAddr, Socket};

const DISCOVERY_WORKER_ID_OFFSET: u32 = u16::MAX as u32;

/// Configuration for the outbound/sending thread
pub struct OutboundConfig {
    /// The unique ID of this specific worker.
    pub worker_id: u16,
    /// Shared signal to forcefully shut down the worker (e.g., when the CLI disconnects).
    pub abort_outbound: Arc<AtomicBool>,
    /// The unique ID of the measurement.
    pub m_id: u32,
    /// Protocol type used
    pub p_type: ProtocolType,
    /// Optional domain name to query in DNS measurement probes.
    pub qname: Option<String>,
    /// Optional URL to be embedded in the probe's payload (e.g., an opt-out link).
    pub info_url: Option<String>,
    /// The target rate for sending probes, measured in packets per second (pps).
    pub probing_rate: u32,
    /// Whether to add the Record Route option to IPv4 probes
    pub is_record: bool,
    /// Source address to use
    pub src: Address,
    /// Source port to use
    pub sport: u16,
    /// Destination port to use
    pub dport: u16,
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
    socket: Arc<Socket>,
) {
    thread::Builder::new()
        .name("outbound".to_string())
        .spawn(move || {
            let mut sent = 0u32;
            let mut sent_discovery = 0u32;
            let mut traces_sent = 0u32;
            let mut failed = 0u32;

            // Calculate probing rate (multiple origins multiply the probing rate)
            let total_rate = config.probing_rate;
            // Rate limiter bucket
            let mut limiter =
                DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(total_rate).unwrap());

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
                                    let (s, f) = if !config.is_record {
                                        send_probe(
                                            &config,
                                            &task.dst.unwrap(),
                                            &socket,
                                            &mut limiter,
                                            false, // Not a discovery probe
                                        )
                                    } else {
                                        send_record_route_probe(
                                            &config,
                                            &task.dst.unwrap(),
                                            &socket,
                                            &mut limiter,
                                        )
                                    };
                                    sent += s;
                                    failed += f;
                                }
                                Some(TaskType::Discovery(task)) => {
                                    let (s, f) = send_probe(
                                        &config,
                                        &task.dst.unwrap(),
                                        &socket,
                                        &mut limiter,
                                        true, // This is a discovery probe
                                    );
                                    sent_discovery += s;
                                    failed += f;
                                }
                                Some(TaskType::Trace(trace)) => {
                                    let (s, f) = send_trace(
                                        config.worker_id as u32,
                                        config.m_id,
                                        config.info_url.clone(),
                                        trace,
                                        &socket,
                                        &config.src,
                                    );
                                    traces_sent += s;
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

/// Send a packet (vector of bytes) using the socket
/// IPv4: Send IPv4 header (optional Record Route option) and IP payload
/// IPv6: Send only payload (kernel writes IPv6 header)
///
/// # Arguments
/// * `socket` - attached socket to send probes from
/// * `packet_buffer` - Packet to send (as bytes)
/// * `dst` - Destination address to send the packet to
pub fn send_packet(
    socket: &Socket,
    packet_buffer: &Vec<u8>,
    dst: &Address,
) -> Result<(), std::io::Error> {
    if packet_buffer.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Empty packet",
        ));
    }

    let ip: IpAddr = dst
        .try_into()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let dest_addr = SockAddr::from(SocketAddr::new(ip, 0));

    socket.send_to(packet_buffer, &dest_addr)?;

    Ok(())
}
