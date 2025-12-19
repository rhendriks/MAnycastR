use std::time::{SystemTime, UNIX_EPOCH};
use crate::custom_module::manycastr::{Address, Origin, ProbeDiscovery, ProbeMeasurement};
use crate::custom_module::manycastr::result::ResultData;
use crate::net::{parse_record_route_option, IPv4Packet, PacketPayload};
use crate::worker::config::get_origin_id;

/// Parse ICMP Record Route packets (including v4/v6 headers) into a Reply result with trace information.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse (excluding the Ethernet header)
/// * `m_id` - the ID of the current measurement
/// * `worker_map` - mapping of origin to origin ID
/// * `is_ipv6` - whether the packet is IPv6 (true) or IPv4 (false)
/// # Returns
/// * `Option<Reply>` - the received RR reply (None if it is not a valid RR packet)
pub fn parse_record_route(
    packet_bytes: &[u8],
    m_id: u32,
    worker_map: &Vec<Origin>,
    is_ipv6: bool,
) -> Option<ResultData> {
    // Check for Record Route option and minimum length
    if (is_ipv6 && (packet_bytes.len() < 66 || packet_bytes[40] != 7)) // TODO fix ipv6 filter
        || (!is_ipv6 && (packet_bytes.len() < 52 || packet_bytes[20] != 7))
    {
        return None;
    }

    if is_ipv6 {
        panic!("IPv6 Record Route not implemented") // TODO
    }

    // Parse IP header
    let ip_header = IPv4Packet::from(packet_bytes);

    // Get options (if any)
    let recorded_hops = if let Some(ip_option) = ip_header.options {
        parse_record_route_option(&ip_option)
    } else {
        return None; // No options, cannot be a RR packet
    };

    // Parse ICMP header
    let PacketPayload::Icmp { value: icmp_packet } = ip_header.payload else {
        return None;
    };

    // Make sure that this packet belongs to this measurement
    let pkt_measurement_id: [u8; 4] = icmp_packet.payload[0..4].try_into().ok()?; // TODO move to initial if statement
    if u32::from_be_bytes(pkt_measurement_id) != m_id {
        return None;
    }

    let tx_time = u64::from_be_bytes(icmp_packet.payload[4..12].try_into().unwrap());
    let tx_id = u32::from_be_bytes(icmp_packet.payload[12..16].try_into().unwrap());
    let probe_src = Address::from(u32::from_be_bytes(
        icmp_packet.payload[16..20].try_into().unwrap(),
    ));
    let probe_dst = Address::from(u32::from_be_bytes(
        icmp_packet.payload[20..24].try_into().unwrap(),
    ));
    if (probe_src.get_v4() != ip_header.dst) || (probe_dst.get_v4() != ip_header.src) {
        return None; // spoofed reply
    }

    let origin_id = get_origin_id(Address::from(ip_header.dst), 0, 0, worker_map);
    let rx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    Some(ResultData::Measurement(ProbeMeasurement {
        src: Some(Address::from(ip_header.src)),
        ttl: ip_header.ttl as u32,
        origin_id,
        rx_time,
        tx_time: Some(tx_time),
        tx_id,
        chaos: None,
        recorded_hops,
    }))
}