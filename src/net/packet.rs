use crate::custom_module::manycastr::{Address, Origin};
use crate::net::{ICMPPacket, TCPPacket, UDPPacket};
use std::time::{SystemTime, UNIX_EPOCH};

/// ICMP arguments to encode in the payload.
#[derive(Debug)]
pub struct ProbePayload {
    /// Sender worker ID
    pub worker_id: u32,
    /// Unique measurement ID (to verify reply)
    pub m_id: u32,
    /// Optional TTL value of the IP header (for traceroute)
    pub trace_ttl: Option<u8>,
    /// Optional URL (e.g., opt-out information)
    pub info_url: Option<String>,
}

/// Creates a ping packet to send.
///
/// # Arguments
/// * `src` - the source address for the ping packet
/// * `dst` - the destination address for the ping packet
/// * `identifier` - the identifier to use in the ICMP header
/// * `seq` - the sequence number to use in the ICMP header
/// * `payload` - information to encode in the payload
/// * `ttl` - the time-to-live (TTL) value to set in the IP header
///
/// # Returns
/// A ping packet (including the IP header) as a byte vector.
pub fn create_icmp(
    src: &Address,
    dst: &Address,
    identifier: u16,
    seq: u16,
    payload: &ProbePayload,
    ttl: u8,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    // Create the ping payload bytes
    let mut payload_bytes: Vec<u8> = Vec::new();
    payload_bytes.extend_from_slice(&payload.m_id.to_be_bytes()); // Bytes 0 - 3
    payload_bytes.extend_from_slice(&tx_time.to_be_bytes()); // Bytes 4 - 11
    payload_bytes.extend_from_slice(&payload.worker_id.to_be_bytes()); // Bytes 12 - 15

    // Add addresses to payload (used for spoofing detection)
    payload_bytes.extend_from_slice(&src.to_be_bytes()); // Bytes 16 - 33 (v6) or 16 - 19 (v4)
    payload_bytes.extend_from_slice(&dst.to_be_bytes()); // Bytes 34 - 51 (v6) or 20 - 23 (v4)

    // Optional, add trace TTL (traceroute measurements)
    if let Some(trace_ttl) = payload.trace_ttl {
        payload_bytes.extend_from_slice(&trace_ttl.to_be_bytes()); // Byte 52 (v6) or 24 (v4)
    }

    // Add info URL to payload
    if let Some(info_url) = &payload.info_url {
        payload_bytes.extend_from_slice(info_url.as_bytes());
    }

    ICMPPacket::echo_request(identifier, seq, payload_bytes, src, dst, ttl)
}

/// Create a Record Route ICMP packet to send.
/// # Arguments
/// * `src` - the source address for the ping packet
/// * `dst` - the destination address for the ping packet
/// * `identifier` - the identifier to use in the ICMP header
/// * `seq` - the sequence number to use in the ICMP header
/// * `payload` - payload data
/// * `ttl` - the time-to-live (TTL) value to set in the IP header
/// # Returns
/// A reverse traceroute ICMP packet (including the IP header) as a byte vector.
pub fn create_record_route_icmp(
    src: &Address,
    dst: &Address,
    identifier: u16,
    seq: u16,
    payload: &ProbePayload,
    ttl: u8,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    // Create the ping payload bytes
    let mut payload_bytes: Vec<u8> = Vec::new();
    payload_bytes.extend_from_slice(&payload.m_id.to_be_bytes()); // Bytes 0 - 3
    payload_bytes.extend_from_slice(&tx_time.to_be_bytes()); // Bytes 4 - 11
    payload_bytes.extend_from_slice(&payload.worker_id.to_be_bytes()); // Bytes 12 - 15

    // Add addresses to payload (used for spoofing detection)
    payload_bytes.extend_from_slice(&src.to_be_bytes()); // Bytes 16 - 33 (v6) or 16 - 19 (v4)
    payload_bytes.extend_from_slice(&dst.to_be_bytes()); // Bytes 34 - 51 (v6) or 20 - 23 (v4)

    // Add info URL to payload
    if let Some(info_url) = &payload.info_url {
        payload_bytes.extend_from_slice(info_url.as_bytes());
    }

    ICMPPacket::record_route_icmpv4(identifier, seq, payload_bytes, src.into(), dst.into(), ttl)
}

/// Creates a DNS packet.
///
/// # Arguments
/// * `origin` - the source address and port values we use for our probes
/// * `worker_id` - the unique worker ID of this worker
/// * `dst` - the destination address for the DNS packet
/// * `is_chaos` - whether this is a CHAOS measurement
/// * `qname` - the DNS record to request
///
/// # Returns
/// A DNS packet (including the IP header) as a byte vector.
pub fn create_dns(
    origin: &Origin,
    dst: &Address,
    worker_id: u32,
    is_chaos: bool,
    qname: String,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let src = &origin.src.expect("None IP address");
    let sport = origin.sport as u16;

    if !is_chaos {
        UDPPacket::dns_request(src, dst, sport, qname, tx_time, worker_id, 255)
    } else {
        UDPPacket::chaos_request(src, dst, sport, worker_id, qname)
    }
}

/// Creates a TCP packet.
///
/// # Arguments
/// * `origin` - the source address and port values we use for our probes
/// * `dst` - the destination address for the TCP packet
/// * `worker_id` - the unique worker ID of this worker
/// * `is_discovery` - whether this is a measurement (False) or discovery (True) probe
/// * `info_url` - Optional URL to encode in packet payload (e.g., opt-out URL)
///
/// # Returns
/// A TCP packet (including the IP header) as a byte vector.
pub fn create_tcp(
    origin: &Origin,
    dst: &Address,
    worker_id: u32,
    is_discovery: bool,
    info_url: Option<String>,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32;

    let timestamp_21b = tx_time & 0x1FFFFF;
    let worker_10b = worker_id & 0x3FF;

    let discovery_bit = if is_discovery { 1u32 << 31 } else { 0 };
    let ack = discovery_bit | (worker_10b << 21) | timestamp_21b;

    TCPPacket::tcp_syn_ack(
        &origin.src.unwrap(),
        dst,
        origin.sport as u16,
        origin.dport as u16,
        ack,
        255,
        info_url,
    )
}
