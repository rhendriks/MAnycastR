use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{Address, DiscoveryReply, MeasurementReply, Reply};
use crate::net::{DNSAnswer, DNSRecord, TXTRecord, UDPPacket};
use crate::DNS_IDENTIFIER;

/// Parse DNS packets into a Reply result.
/// Filters out spoofed packets and only parses DNS replies valid for the current measurement.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse
/// * `is_chaos` - whether this is a chaos reply (True) or an A record reply (False)
/// * `src` - source address for this packet
/// * `ttl` - TTL value of this packet
/// * `sport` - Source port used for outgoing packets (destination port of replies)
///
/// # Returns
/// * `Option<Reply>` - the received DNS reply (None if invalid)
pub fn parse_dns(
    packet_bytes: &[u8],
    is_chaos: bool,
    src: Address,
    ttl: u32,
    sport: u16,
    rx_time: u64,
) -> Option<Reply> {
    // DNS header offset
    let dns_offset = if src.is_v6() { 8 } else { 28 };

    // Verify 6 leftmost bits of transaction ID
    let first_tx_byte = packet_bytes[dns_offset];
    let dns_identifier = first_tx_byte >> 2; // Shift right by 2 to isolate the top 6 bits

    if dns_identifier != DNS_IDENTIFIER {
        return None;
    }

    let udp_packet = if src.is_v6() {
        UDPPacket::from(packet_bytes)
    } else {
        UDPPacket::from(&packet_bytes[20..]) // skip IPv4 header
    };

    // The UDP responses will be from DNS services, the body length has to be large enough to contain a DNS A reply
    if (!is_chaos & (udp_packet.body.len() < 66)) | (is_chaos & (udp_packet.body.len() < 10)) {
        return None;
    }

    // Verify port
    if udp_packet.dport != sport {
        return None;
    }

    let reply_dport = udp_packet.dport;

    let (tx_time, tx_id, chaos, is_discovery) = if !is_chaos {
        let dns_result = parse_dns_a_record(udp_packet.body.as_slice(), src.is_v6())?;

        if (dns_result.probe_sport != reply_dport) | (dns_result.probe_dst != src) {
            return None; // spoofed reply
        }

        (
            dns_result.tx_time,
            dns_result.tx_id,
            None,
            dns_result.is_discovery,
        )
    } else {
        let (tx_time, tx_worker_id, chaos) = parse_chaos(udp_packet.body.as_slice())?;
        (tx_time, tx_worker_id, Some(chaos), false)
    };

    if is_discovery {
        Some(Reply {
            reply_data: Some(ReplyData::Discovery(DiscoveryReply { src: Some(src) })),
        })
    } else {
        Some(Reply {
            reply_data: Some(ReplyData::Measurement(MeasurementReply {
                src: Some(src),
                ttl,
                rx_time,
                tx_time,
                tx_id,
                chaos,
                recorded_hops: None,
            })),
        })
    }
}

struct DnsResult {
    tx_time: u64,
    tx_id: u32,
    probe_sport: u16,
    probe_dst: Address,
    is_discovery: bool,
}

/// Attempts to parse the DNS A record from a DNS payload body.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse
///
/// # Returns
/// * `Option<DnsResult>` - the DNS result containing the DNS A record with the source port and source and destination addresses and whether it is a discovery packet
///
/// # Remarks
/// The function returns None if the packet is too short to contain a DNS A record.
fn parse_dns_a_record(packet_bytes: &[u8], is_ipv6: bool) -> Option<DnsResult> {
    let record = DNSRecord::from(packet_bytes);
    let domain = record.domain; // example: '1679305276037913215.3226971181.16843009.0.4000.google.com'
    let parts: Vec<&str> = domain.split('.').collect();
    // Our domains have at least 5 parts
    if parts.len() < 5 {
        return None;
    }

    let tx_time = parts[0].parse::<u64>().ok()?;
    let probe_dst = if is_ipv6 {
        Address::from(parts[2].parse::<u128>().ok()?)
    } else {
        Address::from(parts[2].parse::<u32>().ok()?)
    };
    let mut tx_id = parts[3].parse::<u32>().ok()?;
    let probe_sport = parts[4].parse::<u16>().ok()?;

    let is_discovery = if tx_id > u16::MAX as u32 {
        tx_id -= u16::MAX as u32;
        true
    } else {
        false
    };

    Some(DnsResult {
        tx_time,
        tx_id,
        probe_sport,
        probe_dst,
        is_discovery,
    })
}

/// Attempts to parse the DNS Chaos record from a UDP payload body.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse
///
/// # Returns
/// * `Option<UdpPayload>` - the UDP payload containing the DNS Chaos record
///
/// # Remarks
/// The function returns None if the packet is too short to contain a DNS Chaos record.
fn parse_chaos(packet_bytes: &[u8]) -> Option<(u64, u32, String)> {
    let record = DNSRecord::from(packet_bytes);

    // 10 rightmost bits have the sender worker ID encoded
    let tx_worker_id = (record.transaction_id & 0x03FF) as u32;

    if record.answer == 0 {
        return Some((0u64, tx_worker_id, "Not implemented".to_string()));
    }

    let chaos_data = TXTRecord::from(DNSAnswer::from(record.body.as_slice()).data.as_slice()).txt;

    Some((0u64, tx_worker_id, chaos_data))
}
