use crate::custom_module::manycastr::reply::ReplyData;
use crate::custom_module::manycastr::{Address, DiscoveryReply, MeasurementReply, Reply};
use crate::dns_identifier;
use crate::net::{DNSAnswer, DNSRecord, TXTRecord};

/// Per-measurement context needed to validate incoming DNS replies.
pub struct DnsContext {
    pub is_chaos: bool,
    pub sport: u16,
    pub is_dgram: bool,
    pub m_id: u32,
}

/// Parse DNS packets into a Reply result.
/// Filters out spoofed packets and only parses DNS replies valid for the current measurement.
///
/// # Arguments
/// * `packet_bytes` - the bytes of the packet to parse
/// * `src` - source address for this packet
/// * `ttl` - TTL value of this packet
/// * `rx_time` - kernel receive timestamp (microseconds since epoch)
/// * `ctx` - per-measurement DNS context (sport, m_id, is_chaos, is_dgram)
///
/// # Returns
/// * `Option<Reply>` - the received DNS reply (None if invalid)
pub fn parse_dns(
    packet_bytes: &[u8],
    src: Address,
    ttl: u32,
    rx_time: u64,
    ctx: &DnsContext,
) -> Option<Reply> {
    let DnsContext {
        is_chaos,
        sport,
        is_dgram,
        m_id,
    } = *ctx;

    // Obtain the DNS message and the reply's destination port (our source port).
    let (dns_msg, reply_dport): (&[u8], u16) = if is_dgram {
        // SOCK_DGRAM, kernel strips the IP and UDP headers
        (packet_bytes, sport)
    } else {
        // Raw socket: IPv4 includes the IP header (skip 20 bytes); IPv6 does not.
        let udp_bytes = if src.is_v6() {
            packet_bytes
        } else {
            packet_bytes.get(20..)?
        };
        if udp_bytes.len() < 8 {
            return None;
        }
        let dport = u16::from_be_bytes([udp_bytes[2], udp_bytes[3]]);
        (&udp_bytes[8..], dport)
    };

    // Verify our destination port (i.e. the probe's source port)
    if reply_dport != sport {
        return None;
    }

    // Verify 6-bit measurement identifier in the DNS transaction ID
    if dns_msg.is_empty() || (dns_msg[0] >> 2) != dns_identifier(m_id) {
        return None;
    }

    // The body length has to be large enough to contain a DNS A / TXT reply
    if (!is_chaos & (dns_msg.len() < 66)) | (is_chaos & (dns_msg.len() < 10)) {
        return None;
    }

    let (tx_time, tx_id, chaos, is_discovery) = if !is_chaos {
        let dns_result = parse_dns_a_record(dns_msg, src.is_v6(), m_id)?;

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
        let (tx_time, tx_worker_id, chaos) = parse_chaos(dns_msg)?;
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
/// * `is_ipv6` - whether this is an IPv6 measurement
/// * `m_id` - measurement ID to validate against the QNAME-encoded value
///
/// # Returns
/// * `Option<DnsResult>` - the DNS result containing the DNS A record with the source port and source and destination addresses and whether it is a discovery packet
///
/// # Remarks
/// The function returns None if the packet is too short to contain a DNS A record,
/// or if the measurement ID encoded in the QNAME does not match the current measurement.
fn parse_dns_a_record(packet_bytes: &[u8], is_ipv6: bool, m_id: u32) -> Option<DnsResult> {
    let record = DNSRecord::from(packet_bytes);
    let domain = record.domain; // example: '1679305276037913215.3226971181.16843009.0.4000.123456.google.com'
    let parts: Vec<&str> = domain.split('.').collect();
    // Our domains have at least 6 parts (tx_time, src, dst, tx_id, sport, m_id, domain...)
    if parts.len() < 6 {
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
    let pkt_m_id = parts[5].parse::<u32>().ok()?;

    // Verify measurement ID matches
    if pkt_m_id != m_id {
        return None;
    }

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
