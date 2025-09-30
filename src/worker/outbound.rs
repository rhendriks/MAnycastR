use log::{error, info, warn};
use std::num::NonZeroU32;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use tokio::sync::mpsc::{error::TryRecvError, Receiver};

use crate::custom_module;
use custom_module::manycastr::Origin;

use pnet::datalink::DataLinkSender;

use crate::custom_module::manycastr::instruction::InstructionType;
use crate::custom_module::manycastr::task::TaskType;
use crate::custom_module::manycastr::{Address, Trace};
use crate::custom_module::Separated;
use crate::net::packet::{
    create_dns, create_icmp, create_record_route_icmp, create_tcp, get_ethernet_header,
    ProbePayload,
};
use ratelimit_meter::{DirectRateLimiter, LeakyBucket};

const DISCOVERY_WORKER_ID_OFFSET: u32 = u16::MAX as u32;

/// Configuration for an outbound packet sending worker.
///
/// This struct holds all the parameters needed to initialize and run a worker
/// that generates and sends measurement probes (e.g., ICMP, DNS, TCP)
/// at a specified rate.
pub struct OutboundConfig {
    /// The unique ID of this specific worker.
    pub worker_id: u16,
    /// A list of source addresses and port values (`Origin`) to send probes from.
    pub tx_origins: Vec<Origin>,
    /// A shared signal that can be used to forcefully shut down the worker.
    ///
    /// E.g., when the CLI has abruptly disconnected.
    pub abort_s: Arc<AtomicBool>,
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
///
/// * 'config' - configuration for the outbound worker thread
///
/// * 'outbound_rx' - on this channel we receive future tasks that are part of the current measurement
///
/// * 'socket_tx' - the sender object to send packets
pub fn outbound(
    config: OutboundConfig,
    mut outbound_rx: Receiver<InstructionType>,
    mut socket_tx: Box<dyn DataLinkSender>,
) {
    thread::Builder::new()
        .name("outbound".to_string())
        .spawn(move || {
            let mut sent: u32 = 0;
            let mut sent_discovery = 0;
            let mut traces_sent: u32 = 0;
            let mut failed: u32 = 0;
            // Rate limit the number of packets sent per second, each origin has the same rate (i.e., sending with 2 origins will double the rate)
            let mut limiter = DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(config.probing_rate * config.tx_origins.len() as u32).unwrap());

            let ethernet_header = get_ethernet_header(config.is_ipv6, &config.if_name);
            'outer: loop {
                if config.abort_s.load(std::sync::atomic::Ordering::SeqCst) {
                    // If the finish_rx is set to true, break the loop (abort)
                    warn!("[Worker outbound] ABORTING");
                    break;
                }
                let instruction;
                // Receive tasks from the outbound channel
                loop {
                    match outbound_rx.try_recv() {
                        Ok(t) => {
                            instruction = t;
                            break;
                        }
                        Err(e) => {
                            if e == TryRecvError::Disconnected {
                                info!("[Worker outbound] Channel disconnected");
                                break 'outer;
                            }
                            // wait some time and try again
                            sleep(Duration::from_millis(100));
                        }
                    };
                }
                match instruction {
                    InstructionType::End(_) => {
                        // An End task means the measurement has finished
                        break;
                    }
                    InstructionType::Tasks(tasks) => {
                        for task in tasks.tasks.iter() {
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
                                },
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
                                },
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
            info!("[Worker outbound] Outbound thread finished - packets sent : {} (including {} discovery probes), packets failed to send: {}", sent.with_separator(), sent_discovery.with_separator(), failed.with_separator());
            if traces_sent > 0 {
                info!("[Worker outbound] Traceroute probes sent: {}", traces_sent.with_separator());
            }
        })
        .expect("Failed to spawn outbound thread");
}

/// Sends probes to the specified destination using the provided measurement configuration.
/// This function constructs the appropriate packet based on the measurement type
/// and sends it through the provided socket.
/// # Arguments
///
/// * 'config' - The outbound configuration containing worker details and settings.
/// * 'ethernet_header' - The Ethernet header to prepend to the packet.
/// * 'dst' - The destination address to which the probes will be sent.
/// * 'socket_tx' - The socket sender to use for sending the packet.
/// * 'limiter' - A rate limiter to control the sending rate of packets.
/// * 'is_discovery' - A boolean indicating whether the probes are for discovery purposes.
/// # Returns
/// A tuple containing the number of successfully sent packets and the number of failed sends.
pub fn send_probe(
    config: &OutboundConfig,
    ethernet_header: &[u8],
    dst: &Address,
    socket_tx: &mut Box<dyn DataLinkSender>,
    limiter: &mut DirectRateLimiter<LeakyBucket>,
    is_discovery: bool, // Whether we are sending a discovery probe
) -> (u32, u32) {
    let origins = &config.tx_origins;
    let worker_id = if is_discovery {
        config.worker_id as u32 + DISCOVERY_WORKER_ID_OFFSET // Use a different worker ID range for discovery probes
    } else {
        config.worker_id as u32
    };
    let m_type = config.m_type;
    let is_symmetric = config.is_latency; // For TCP, use the is_latency flag
    let m_id = config.m_id;
    let info_url = &config.info_url;
    let mut sent = 0;
    let mut failed = 0;
    let qname = &config.qname;
    for origin in origins {
        let mut packet = ethernet_header.to_owned();
        match m_type {
            1 => {
                let payload_fields = ProbePayload {
                    worker_id,
                    m_id,
                    info_url,
                };
                // ICMP
                packet.extend_from_slice(&create_icmp(
                    &origin.src.unwrap(),
                    dst,
                    origin.dport as u16, // ICMP identifier
                    2,                   // ICMP sequence number
                    payload_fields,
                    255,
                ));
            }
            2 | 4 => {
                // DNS A record or CHAOS
                packet.extend_from_slice(&create_dns(origin, dst, worker_id, m_type, qname));
            }
            3 => {
                // TCP
                packet.extend_from_slice(&create_tcp(
                    origin,
                    dst,
                    worker_id,
                    is_symmetric, // is_symmetric
                    info_url,
                ));
            }
            255 => {
                panic!("Invalid measurement type)") // TODO all
            }
            _ => panic!("Invalid measurement type"), // Invalid measurement
        }

        while limiter.check().is_err() {
            // Rate limit to avoid bursts
            sleep(Duration::from_millis(1));
        }

        match socket_tx.send_to(&packet, None) {
            Some(Ok(())) => sent += 1,
            Some(Err(e)) => {
                warn!("[Worker outbound] Failed to send ICMP packet: {e}");
                failed += 1;
            }
            None => error!("[Worker outbound] Failed to send packet: No Tx interface"),
        }
    }

    (sent, failed)
}

/// Sends a traceroute probe based on the provided trace task and configuration.
/// Only ICMP traceroute is currently implemented.
/// # Arguments
/// * 'ethernet_header' - The Ethernet header to prepend to the packet.
/// * 'config' - The outbound configuration containing worker details and settings.
/// * 'trace_task' - The traceroute task containing destination and TTL information.
/// * 'socket_tx' - The socket sender to use for sending the packet.
/// * 'sent' - A mutable reference to a counter for successfully sent packets.
/// * 'failed' - A mutable reference to a counter for failed packet sends.
/// * 'origins' - A vector of origins to find the matching origin ID for traceroute tasks.
pub fn send_trace(
    ethernet_header: &[u8],
    worker_id: u32,
    m_id: u32,
    info_url: &str,
    trace_task: &Trace,
    socket_tx: &mut Box<dyn DataLinkSender>,
    origins: &[Origin],
) -> (u32, u32) {
    let target = &trace_task.dst.unwrap(); // Single target for traceroute tasks
    let origin_id = trace_task.origin_id;
    // Get the matching origin for this trace task
    let tx_origin = origins.iter().find(|o| o.origin_id == origin_id);
    if tx_origin.is_none() {
        warn!(
            "[Worker outbound] No matching origin found for trace task with origin ID {}",
            origin_id
        );
        return (0, 1);
    }
    let tx_origin = tx_origin.unwrap();

    let mut packet = ethernet_header.to_owned();

    // Encode TTL and first 8 bits of measurement ID in the ICMP sequence number
    let sequence_number: u16 = ((trace_task.ttl as u16) << 8) | ((m_id & 0xFF) as u16);

    let payload_fields = ProbePayload {
        worker_id,
        m_id,
        info_url,
    };

    // Create the appropriate traceroute packet based on the trace_type
    packet.extend_from_slice(&create_icmp(
        tx_origin.src.as_ref().unwrap(),
        target,
        worker_id as u16, // encoding worker ID in ICMP identifier
        sequence_number,  // encoding TTL and first 8 bits of m_id in ICMP sequence number
        payload_fields,
        trace_task.ttl as u8,
    ));
    match socket_tx.send_to(&packet, None) {
        Some(Ok(())) => return (1, 0),
        Some(Err(e)) => {
            warn!("[Worker outbound] Failed to send traceroute packet: {e}");
        }
        None => error!("[Worker outbound] Failed to send packet: No Tx interface"),
    }
    (0, 1)
}

/// Send a Record Route ICMP probe to the specified destination.
///
/// # Arguments
/// * 'ethernet_header' - The Ethernet header to prepend to the packet.
/// * 'config' - The outbound configuration containing worker details and settings.
/// * 'dst' - The destination address to which the probe will be sent.
/// * 'socket_tx' - The socket sender to use for sending the packet.
/// * 'limiter' - A rate limiter to control the sending rate of packets.
/// # Returns
/// A tuple containing the number of successfully sent packets and the number of failed sends.
pub fn send_record_route_probe(
    ethernet_header: &[u8],
    config: &OutboundConfig,
    dst: &Address,
    socket_tx: &mut Box<dyn DataLinkSender>,
    limiter: &mut DirectRateLimiter<LeakyBucket>,
) -> (u32, u32) {
    let mut sent = 0;
    let mut failed = 0;

    let worker_id = config.worker_id as u32;
    let m_id = config.m_id;
    let info_url = &config.info_url;
    let origins = config.origin_map.as_ref().expect("Missing origin_map");

    for origin in origins {
        let mut packet = ethernet_header.to_owned();
        let payload_fields = ProbePayload {
            worker_id,
            m_id,
            info_url,
        };

        packet.extend_from_slice(&create_record_route_icmp(
            origin.src.as_ref().unwrap(),
            dst,
            origin.dport as u16, // encoding worker ID in ICMP identifier
            2,                   // sequence number set to 1 for reverse traceroute
            payload_fields,
            64, // TTL set to 64 for reverse traceroute
        ));

        while limiter.check().is_err() {
            // Rate limit to avoid bursts
            sleep(Duration::from_millis(1));
        }

        match socket_tx.send_to(&packet, None) {
            Some(Ok(())) => sent += 1,
            Some(Err(e)) => {
                warn!("[Worker outbound] Failed to send reverse traceroute packet: {e}");
                failed += 1;
            }
            None => error!("[Worker outbound] Failed to send packet: No Tx interface"),
        }
    }
    (sent, failed)
}
