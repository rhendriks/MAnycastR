use crate::custom_module::manycastr::Address;
use crate::net::packet::{create_dns, create_icmp, create_tcp, ProbePayload};
use crate::worker::outbound::{OutboundConfig, DISCOVERY_WORKER_ID_OFFSET};
use log::{error, warn};
use pnet::datalink::DataLinkSender;
use ratelimit_meter::{DirectRateLimiter, LeakyBucket};
use std::thread::sleep;
use std::time::Duration;

use crate::A_ID;
use crate::CHAOS_ID;
use crate::ICMP_ID;
use crate::TCP_ID;

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
///
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
    let is_latency = config.is_latency; // For TCP, use the is_latency flag
    let m_id = config.m_id;
    let info_url = &config.info_url;
    let mut sent = 0;
    let mut failed = 0;
    let qname = &config.qname;
    for origin in origins {
        let mut packet = ethernet_header.to_owned();
        match m_type {
            ICMP_ID => {
                let payload_fields = ProbePayload {
                    worker_id,
                    m_id,
                    trace_ttl: None, // not a traceroute task
                    info_url,
                };
                packet.extend_from_slice(&create_icmp(
                    &origin.src.unwrap(),
                    dst,
                    origin.dport as u16, // ICMP identifier
                    2,                   // ICMP seq
                    payload_fields,
                    255,
                ));
            }
            A_ID | CHAOS_ID => {
                packet.extend_from_slice(&create_dns(origin, dst, worker_id, m_type, qname));
            }
            TCP_ID => {
                packet.extend_from_slice(&create_tcp(origin, dst, worker_id, is_latency, info_url));
            }
            255 => {
                panic!("Invalid measurement type)") // TODO all, any
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
