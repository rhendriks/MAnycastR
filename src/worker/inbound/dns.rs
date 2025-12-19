use std::time::{SystemTime, UNIX_EPOCH};
use crate::{A_ID, CHAOS_ID};
use crate::custom_module::manycastr::{Address, Origin, ProbeDiscovery, ProbeMeasurement, Result};
use crate::custom_module::manycastr::result::ResultData;
use crate::net::{DNSAnswer, DNSRecord, IPPacket, IPv4Packet, IPv6Packet, PacketPayload, TXTRecord};
use crate::worker::config::get_origin_id;

/// Parse DNS packets into a Reply result.
///
/// Filters out spoofed packets and only parses DNS replies valid for the current measurement.
///
/// # Arguments
///
/// * 'packet_bytes' - the bytes of the packet to parse
///
/// * 'measurement_type' - the type of measurement being performed
///
/// * 'origin_map' - mapping of origin to origin ID
///
/// # Returns
///
/// * `Option<Result>` - the received DNS reply (None if invalid)
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a UDP header.
pub fn parse_dns(
    packet_bytes: &[u8],
    measurement_type: u8,
    origin_map: &Vec<Origin>,
    is_ipv6: bool,
) -> Option<Result> {
    // DNSv6 48 length (IPv6 header (40) + UDP header (8)) + check next protocol is UDP TODO incorporate minimum payload size
    // DNSv4 28 minimum (IPv4 header (20) + UDP header (8)) + check next protocol is UDP TODO incorporate minimum payload size
    if (is_ipv6 && (packet_bytes.len() < 48 || packet_bytes[6] != 17))
        || (!is_ipv6 && (packet_bytes.len() < 28 || packet_bytes[9] != 17))
    {
        return None;
    }

    let ip_header = if is_ipv6 {
        IPPacket::V6(IPv6Packet::from(packet_bytes))
    } else {
        IPPacket::V4(IPv4Packet::from(packet_bytes))
    };

    let PacketPayload::Udp { value: udp_packet } = ip_header.payload() else {
        return None;
    };

    // The UDP responses will be from DNS services, with src port 53 and our possible src ports as dest port, furthermore the body length has to be large enough to contain a DNS A reply
    // TODO use 'get_domain_length'
    if ((measurement_type == A_ID) & (udp_packet.body.len() < 66))
        | ((measurement_type == CHAOS_ID) & (udp_packet.body.len() < 10))
    {
        return None;
    }

    let reply_sport = udp_packet.sport;
    let reply_dport = udp_packet.dport;
    let rx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    let (tx_time, tx_id, chaos, is_discovery) = if measurement_type == A_ID {
        let dns_result = parse_dns_a_record(udp_packet.body.as_slice(), is_ipv6)?;

        if (dns_result.probe_sport != reply_dport)
            | (dns_result.probe_dst != ip_header.src())
            | (dns_result.probe_src != ip_header.dst())
        {
            return None; // spoofed reply
        }

        (
            dns_result.tx_time,
            dns_result.tx_id,
            None,
            dns_result.is_discovery,
        )
    } else if measurement_type == CHAOS_ID {
        // TODO is_discovery for CHAOS
        let (tx_time, tx_worker_id, chaos) = parse_chaos(udp_packet.body.as_slice())?;
        (tx_time, tx_worker_id, Some(chaos), false)
    } else {
        panic!("Invalid measurement type");
    };

    let origin_id = get_origin_id(ip_header.dst(), reply_sport, reply_dport, origin_map)?;

    if is_discovery {
        Some(Result {
            result_data: Some(ResultData::Discovery(ProbeDiscovery {
                src: Some(ip_header.src()),
                origin_id,
            }))
        })
    } else {
        Some(Result {
            result_data:         Some(ResultData::Measurement(ProbeMeasurement {
                src: Some(ip_header.src()),
                ttl: ip_header.ttl() as u32,
                origin_id,
                rx_time,
                tx_time,
                tx_id,
                chaos,
                recorded_hops: None,
            }))
        })
    }
}

struct DnsResult {
    tx_time: u64,
    tx_id: u32,
    probe_sport: u16,
    probe_src: Address,
    probe_dst: Address,
    is_discovery: bool,
}

/// Attempts to parse the DNS A record from a DNS payload body.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// # Returns
///
/// * `Option<DnsResult>` - the DNS result containing the DNS A record with the source port and source and destination addresses and whether it is a discovery packet
///
/// # Remarks
///
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
    let probe_src = if is_ipv6 {
        Address::from(parts[1].parse::<u128>().ok()?)
    } else {
        Address::from(parts[1].parse::<u32>().ok()?)
    };
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
        probe_src,
        probe_dst,
        is_discovery,
    })
}

/// Attempts to parse the DNS Chaos record from a UDP payload body.
///
/// # Arguments
///
/// * `packet_bytes` - the bytes of the packet to parse
///
/// # Returns
///
/// * `Option<UdpPayload>` - the UDP payload containing the DNS Chaos record
///
/// # Remarks
///
/// The function returns None if the packet is too short to contain a DNS Chaos record.
fn parse_chaos(packet_bytes: &[u8]) -> Option<(u64, u32, String)> {
    let record = DNSRecord::from(packet_bytes);

    // 8 right most bits are the sender worker_id
    let tx_worker_id = ((record.transaction_id >> 8) & 0xFF) as u32;

    if record.answer == 0 {
        return Some((0u64, tx_worker_id, "Not implemented".to_string()));
    }

    let chaos_data = TXTRecord::from(DNSAnswer::from(record.body.as_slice()).data.as_slice()).txt;

    Some((0u64, tx_worker_id, chaos_data))
}