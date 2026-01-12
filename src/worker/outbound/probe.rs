use crate::custom_module::manycastr::{Address, ProtocolType};
use crate::net::packet::{create_dns, create_icmp, create_tcp, ProbePayload};
use crate::worker::outbound::{send_packet, OutboundConfig, DISCOVERY_WORKER_ID_OFFSET};
use log::warn;
use ratelimit_meter::{DirectRateLimiter, LeakyBucket, NonConformance};
use socket2::Socket;
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Sends probes to the specified destination using the provided measurement configuration.
/// This function constructs the appropriate packet based on the measurement type
/// and sends it through the provided socket.
/// # Arguments
///
/// * `config` - The outbound configuration containing worker details and settings.
/// * `dst` - The destination address to which the probes will be sent.
/// * `socket_tx` - Raw socket to send packets.
/// * `limiter` - A rate limit bucket to control the sending rate of packets.
/// * `is_discovery` - A boolean indicating whether the probes are for discovery purposes.
///
/// # Returns
/// A tuple containing the number of successfully sent packets and the number of failed sends.
pub fn send_probe(
    config: &OutboundConfig,
    dst: &Address,
    socket_tx: &Socket,
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
        info_url: config.info_url.clone(),
    };

    // Write packets to send to a one-time allocated buffer
    let mut packet_buffer = Vec::with_capacity(256);

    // Rate limit TODO rate limit is not shared amongst multiple origins (will violate probing rate)
    if let Err(not_until) = limiter.check() {
        let wait_time = not_until.wait_time_from(Instant::now());
        if wait_time > Duration::ZERO {
            sleep(wait_time);
        }
    }

    // Write new packet to buffer
    packet_buffer.clear();

    match config.p_type {
        ProtocolType::Icmp => {
            packet_buffer.extend_from_slice(&create_icmp(
                &config.src,
                dst,
                config.dport, // ICMP identifier
                2, // ICMP seq
                &icmp_payload,
                255,
            ));
        }
        ProtocolType::ADns | ProtocolType::ChaosDns => {
            packet_buffer.extend_from_slice(&create_dns(
                &config.src,
                dst,
                config.sport,
                worker_id,
                config.p_type == ProtocolType::ChaosDns,
                config.qname.clone().expect("qname missing"),
            ));
        }
        ProtocolType::Tcp => {
            packet_buffer.extend_from_slice(&create_tcp(
                &config.src,
                dst,
                config.sport,
                config.dport,
                worker_id,
                is_discovery,
                config.info_url.clone(),
            ));
        }
    }

    println!("sending packet with length {}", packet_buffer.len());

    match send_packet(socket_tx, &packet_buffer, dst) {
        Ok(()) => sent += 1,
        Err(e) => {
            warn!("[Worker outbound] Failed to send ICMP packet: {e}");
            failed += 1;
        }
    }

    (sent, failed)
}
