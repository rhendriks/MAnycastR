use crate::custom_module::manycastr::{Address, ProtocolType};
use crate::net::packet::{DnsProbeId, ProbePayload, create_dns, create_icmp, create_tcp};
use crate::worker::outbound::{DISCOVERY_WORKER_ID_OFFSET, OutboundConfig, send_packet};
use log::warn;
use ratelimit_meter::{DirectRateLimiter, LeakyBucket, NonConformance};
use socket2::Socket;
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Sends probes to the specified destination using the provided measurement configuration.
/// This function constructs the appropriate packet based on the measurement type
/// and sends it through the provided socket.
///
/// # Arguments
/// * `config` - The outbound configuration containing worker details and settings.
/// * `dst` - The destination address to which the probes will be sent.
/// * `session_id` - 16-bit session ID encoded in the probe (ICMP/DNS-A only)
/// * `socket` - Raw socket to send packets.
/// * `limiter` - A rate limit bucket to control the sending rate of packets.
/// * `is_discovery` - A boolean indicating whether the probes are for discovery purposes.
///
/// # Returns
/// A tuple containing the number of successfully sent packets and the number of failed sends.
pub fn send_probe(
    config: &OutboundConfig,
    dst: &Address,
    session_id: u32,
    socket: &Socket,
    limiter: &mut DirectRateLimiter<LeakyBucket>,
    is_discovery: bool,
    packet_buffer: &mut Vec<u8>,
) -> (u32, u32) {
    let worker_id = if is_discovery {
        config.worker_id as u32 + DISCOVERY_WORKER_ID_OFFSET // Use a different worker ID range for discovery probes
    } else {
        config.worker_id as u32
    };

    let mut sent = 0;
    let mut failed = 0;

    let probe_id = crate::probe_id(config.m_id, session_id);
    let icmp_payload = ProbePayload {
        worker_id,
        probe_id,
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

    match config.p_type {
        ProtocolType::Icmp => {
            packet_buffer.extend_from_slice(&create_icmp(
                &config.src,
                dst,
                config.dport, // ICMP identifier
                2,            // ICMP seq
                &icmp_payload,
                255,
            ));
        }
        ProtocolType::ADns | ProtocolType::ChaosDns => {
            let dns_id = DnsProbeId {
                worker_id,
                probe_id,
            };
            packet_buffer.extend_from_slice(&create_dns(
                &config.src,
                dst,
                config.sport,
                &dns_id,
                config.p_type == ProtocolType::ChaosDns,
                config.qname.as_deref().expect("qname missing"),
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
                config.info_url.as_deref(),
            ));
        }
    }

    match send_packet(socket, packet_buffer, dst) {
        Ok(()) => sent += 1,
        Err(e) => {
            warn!(
                "[Worker outbound] Failed to send {} packet: {e}",
                config.p_type
            );
            failed += 1;
        }
    }

    (sent, failed)
}
