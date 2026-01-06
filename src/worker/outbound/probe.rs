use crate::custom_module::manycastr::Address;
use crate::net::packet::{create_dns, create_icmp, create_tcp, ProbePayload};
use crate::worker::outbound::{OutboundConfig, DISCOVERY_WORKER_ID_OFFSET};
use log::{error, warn};
use pnet::datalink::DataLinkSender;
use ratelimit_meter::{DirectRateLimiter, LeakyBucket, NonConformance};
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::A_ID;
use crate::CHAOS_ID;
use crate::ICMP_ID;
use crate::TCP_ID;

/// Sends probes to the specified destination using the provided measurement configuration.
/// This function constructs the appropriate packet based on the measurement type
/// and sends it through the provided socket.
/// # Arguments
///
/// * `config` - The outbound configuration containing worker details and settings.
/// * `ethernet_header` - The Ethernet header to prepend to the packet.
/// * `dst` - The destination address to which the probes will be sent.
/// * `socket_tx` - Raw socket to send packets.
/// * `limiter` - A rate limit bucket to control the sending rate of packets.
/// * `is_discovery` - A boolean indicating whether the probes are for discovery purposes.
///
/// # Returns
/// A tuple containing the number of successfully sent packets and the number of failed sends.
pub fn send_probe(
    config: &OutboundConfig,
    ethernet_header: &[u8],
    dst: &Address,
    socket_tx: &mut Box<dyn DataLinkSender>,
    limiter: &mut DirectRateLimiter<LeakyBucket>,
    is_discovery: bool,
) -> (u32, u32) {
    let worker_id = if is_discovery {
        config.worker_id as u32 + DISCOVERY_WORKER_ID_OFFSET // Use a different worker ID range for discovery probes
    } else {
        config.worker_id as u32
    };

    let mut sent = 0;
    let mut failed = 0;

    // Payload to encode in outgoing probes
    let icmp_payload = ProbePayload {
        worker_id,
        m_id: config.m_id,
        trace_ttl: None,
        info_url: &config.info_url,
    };

    // Write packets to send to a one-time allocated buffer
    let mut packet_buffer = Vec::with_capacity(256);

    for origin in &config.tx_origins {
        // Rate limit
        if let Err(not_until) = limiter.check() {
            let wait_time = not_until.wait_time_from(Instant::now());
            if wait_time > Duration::ZERO {
                sleep(wait_time);
            }
        }

        // Write new packet to buffer
        packet_buffer.clear();
        packet_buffer.extend_from_slice(ethernet_header);

        match config.m_type {
            ICMP_ID => {
                packet_buffer.extend_from_slice(&create_icmp(
                    &origin.src.unwrap(),
                    dst,
                    origin.dport as u16, // ICMP identifier
                    2, // ICMP seq
                    &icmp_payload,
                    255,
                ));
            }
            A_ID | CHAOS_ID => {
                packet_buffer.extend_from_slice(&create_dns(origin, dst, worker_id, config.m_type, &config.qname));
            }
            TCP_ID => {
                packet_buffer.extend_from_slice(&create_tcp(origin, dst, worker_id, config.is_latency, &config.info_url));
            }
            255 => {
                panic!("Invalid measurement type)") // TODO all, any
            }
            _ => panic!("Invalid measurement type"), // Invalid measurement
        }

        match socket_tx.send_to(&packet_buffer, None) {
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
