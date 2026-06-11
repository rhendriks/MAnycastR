use crate::custom_module::manycastr::{Address, Reply};
use crate::net::{IPv4Packet, PacketPayload, parse_record_route_option};
use crate::worker::inbound::ping::parse_icmp_inner;

/// Parse ICMP Record Route packets (including v4/v6 headers) into a Reply result with trace information.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse (excluding the Ethernet header)
/// * `m_id` - the ID of the current measurement
/// * `src` - source address of the received packet (target address)
/// * `ttl` - TTL value of the received packet
///
/// # Returns
/// * `Option<Reply>` - the received RR reply (None if it is not a valid RR packet)
pub fn parse_record_route(packet_bytes: &[u8], m_id: u32, src: Address, ttl: u32) -> Option<Reply> {
    // Check for Record Route option and minimum length
    if packet_bytes.len() < 52 || packet_bytes[20] != 7 {
        return None;
    }

    // Parse IP header
    let ipv4_header = IPv4Packet::from(packet_bytes);

    // Get options (if any)
    let recorded_hops = if let Some(ip_option) = &ipv4_header.options {
        parse_record_route_option(ip_option)
    } else {
        return None; // No options, cannot be a RR packet
    };

    // Parse ICMP header
    let PacketPayload::Icmp { value: icmp_packet } = &ipv4_header.payload else {
        return None;
    };

    parse_icmp_inner(icmp_packet, m_id, recorded_hops, false, src, ttl, 0)
}
