use std::thread::sleep;
use std::time::Duration;
use log::{error, warn};
use pnet::datalink::DataLinkSender;
use ratelimit_meter::{DirectRateLimiter, LeakyBucket};
use crate::custom_module::manycastr::Address;
use crate::net::packet::{create_record_route_icmp, ProbePayload};
use crate::worker::outbound::OutboundConfig;

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
            origin.dport as u16,
            2,
            payload_fields,
            255,
        ));

        while limiter.check().is_err() {
            // Rate limit to avoid bursts
            sleep(Duration::from_millis(1));
        }

        match socket_tx.send_to(&packet, None) {
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