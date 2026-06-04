use crate::custom_module::manycastr::Address;
use crate::net::packet::{create_record_route_icmp, ProbePayload};
use crate::worker::outbound::{send_packet, OutboundConfig};
use log::warn;
use ratelimit_meter::{DirectRateLimiter, LeakyBucket, NonConformance};
use socket2::Socket;
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Send a Record Route ICMP probe to the specified destination.
///
/// # Arguments
/// * `config` - The outbound configuration containing worker details and settings.
/// * `dst` - The destination address to which the probe will be sent.
/// * `socket` - The socket sender to use for sending the packet.
/// * `limiter` - A rate limiter to control the sending rate of packets.
/// # Returns
/// A tuple containing the number of successfully sent packets and the number of failed sends.
pub fn send_record_route_probe(
    config: &OutboundConfig,
    dst: &Address,
    socket: &Socket,
    limiter: &mut DirectRateLimiter<LeakyBucket>,
    packet_buffer: &mut Vec<u8>,
) -> (u32, u32) {
    let mut sent = 0;
    let mut failed = 0;

    let icmp_payload = ProbePayload {
        worker_id: config.worker_id as u32,
        m_id: config.m_id,
        trace_ttl: None,
        info_url: config.info_url.as_deref(),
    };

    // Rate limit
    if let Err(not_until) = limiter.check() {
        let wait_time = not_until.wait_time_from(Instant::now());
        if wait_time > Duration::ZERO {
            sleep(wait_time);
        }
    }

    packet_buffer.clear();

    packet_buffer.extend_from_slice(&create_record_route_icmp(
        &config.src,
        dst,
        config.dport,
        2,
        &icmp_payload,
        255,
    ));

    match send_packet(socket, packet_buffer, dst, 0) {
        Ok(()) => sent += 1,
        Err(e) => {
            warn!("[Worker outbound] Failed to send ICMP packet: {e}");
            failed += 1;
        }
    }
    (sent, failed)
}
