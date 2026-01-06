use crate::custom_module::manycastr::Address;
use crate::net::packet::{create_record_route_icmp, ProbePayload};
use crate::worker::outbound::OutboundConfig;
use log::{error, warn};
use pnet::datalink::DataLinkSender;
use ratelimit_meter::{DirectRateLimiter, LeakyBucket, NonConformance};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Send a Record Route ICMP probe to the specified destination.
///
/// # Arguments
/// * `ethernet_header` - The Ethernet header to prepend to the packet.
/// * `config` - The outbound configuration containing worker details and settings.
/// * `dst` - The destination address to which the probe will be sent.
/// * `socket_tx` - The socket sender to use for sending the packet.
/// * `limiter` - A rate limiter to control the sending rate of packets.
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

    // Payload to encode in outgoing probes
    let icmp_payload = ProbePayload {
        worker_id: config.worker_id as u32,
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

        packet_buffer.extend_from_slice(&create_record_route_icmp(
            origin.src.as_ref().unwrap(),
            dst,
            origin.dport as u16,
            2,
            &icmp_payload,
            255,
        ));

        match socket_tx.send_to(&packet_buffer, None) {
            Some(Ok(())) => sent += 1,
            Some(Err(e)) => {
                warn!("[Worker outbound] Failed to send Record Route packet: {e}");
                failed += 1;
            }
            None => error!("[Worker outbound] Failed to send packet: No Tx interface"),
        }
    }
    (sent, failed)
}
