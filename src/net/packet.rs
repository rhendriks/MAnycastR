use crate::custom_module::manycastr::Address;
use crate::net::{
    ICMPPacket, PacketPayload, PseudoHeader, TCPPacket, UDPPacket, build_ip_packet,
    calculate_checksum,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// ICMP arguments to encode in the payload.
#[derive(Debug)]
pub struct ProbePayload<'a> {
    /// Sender worker ID
    pub worker_id: u32,
    /// Unique measurement ID (to verify reply)
    pub m_id: u32,
    /// Optional TTL value of the IP header (for traceroute)
    pub trace_ttl: Option<u8>,
    /// Optional URL (e.g., opt-out information)
    pub info_url: Option<&'a str>,
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
/// * `is_dgram` - datagram socket (true) or raw socket (false)
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
    is_dgram: bool,
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

    ICMPPacket::echo_request(identifier, seq, payload_bytes, src, dst, ttl, is_dgram)
}

pub struct DnsProbeId {
    pub worker_id: u32,
    pub m_id: u32,
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
/// DNS probe identity (worker + measurement).
pub fn create_dns(
    src: &Address,
    dst: &Address,
    sport: u16,
    id: &DnsProbeId,
    is_chaos: bool,
    qname: &str,
    is_dgram: bool,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    if !is_chaos {
        UDPPacket::dns_request(src, dst, sport, qname, tx_time, id, is_dgram)
    } else {
        UDPPacket::chaos_request(src, dst, sport, id, qname, is_dgram)
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
    src: &Address,
    dst: &Address,
    sport: u16,
    dport: u16,
    worker_id: u32,
    is_discovery: bool,
    info_url: Option<&str>,
) -> Vec<u8> {
    let tx_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u32;

    let timestamp_21b = tx_time & 0x1FFFFF;
    let worker_10b = worker_id & 0x3FF;

    let discovery_bit = if is_discovery { 1u32 << 31 } else { 0 };
    let ack = discovery_bit | (worker_10b << 21) | timestamp_21b;

    TCPPacket::tcp_syn_ack(src, dst, sport, dport, ack, 255, info_url)
}

/// Identity of a UDP/DNS trace probe, encoded in the QNAME so the **destination
/// DNS server's** reply can be matched back to the trace session.
pub struct TraceDnsId<'a> {
    /// Sending worker id
    pub tx_id: u32,
    /// Measurement ID
    pub m_id: u32,
    /// Full microsecond send time (for the destination-hop RTT)
    pub tx_micros: u64,
    /// Time-to-live / hop limit of the probe (recovered as hop_count)
    pub ttl: u8,
    /// The DNS name to query (e.g. `example.org`)
    pub qname: &'a str,
}

/// Creates a UDP (Paris) traceroute probe packet with a DNS payload
///
/// When the probe reaches its destination DNS server, the server replies to the DNS query,
/// resulting in the traceroute being terminated (destination reached).
///
/// Encoding scheme:
/// - IPv4 IP identification (16b) / IPv6 flow label (16b of 20b):
///   `(worker_hi_2 << 14) | timestamp_14b`
/// - UDP checksum (16b): `(ttl << 8) | worker_lo_8`
///
/// # Arguments
/// * `src` / `dst` - source / destination address
/// * `sport` / `dport` - configured ports (constant across probes for Paris)
/// * `identifier` - IP identification / flow label (worker_hi + timestamp)
/// * `desired_checksum` - value forced into the UDP checksum (ttl + worker_lo)
/// * `id` - probe identity encoded in the QNAME (worker, measurement, send time, TTL)
pub fn create_udp_trace(
    src: &Address,
    dst: &Address,
    sport: u16,
    dport: u16,
    identifier: u16,
    desired_checksum: u16,
    id: &TraceDnsId,
) -> Vec<u8> {
    let ttl = id.ttl;

    // Create a valid DNS query with traceroute encodings and the desired UDP checksum
    let mut body = crate::net::udp::dns_a_trace_body(src, dst, sport, id);
    let corr_off = body.len(); // correction word appended after the DNS message
    body.extend_from_slice(&[0u8, 0u8]);

    let udp_length = (8 + body.len()) as u16;

    // Compute the actual checksum with the correction placeholder as 0x0000
    let tmp_udp = UDPPacket {
        sport,
        dport,
        length: udp_length,
        checksum: 0,
        body: body.clone(),
    };
    let udp_bytes: Vec<u8> = (&tmp_udp).into();
    let pseudo_header = PseudoHeader::new(src, dst, 17, udp_length as u32);
    let actual_checksum = calculate_checksum(&udp_bytes, &pseudo_header);

    let correction = checksum_correction(actual_checksum, desired_checksum);
    let (b0, b1) = if corr_off.is_multiple_of(2) {
        ((correction >> 8) as u8, (correction & 0xFF) as u8)
    } else {
        ((correction & 0xFF) as u8, (correction >> 8) as u8)
    };
    body[corr_off] = b0;
    body[corr_off + 1] = b1;

    let udp_packet = UDPPacket {
        sport,
        dport,
        length: udp_length,
        checksum: desired_checksum,
        body,
    };

    build_ip_packet(
        src,
        dst,
        ttl,
        identifier,
        PacketPayload::Udp { value: udp_packet },
    )
}

/// Compute a 2-byte correction word that, when placed in the payload (replacing
/// the zero placeholder), forces the UDP checksum to `desired`.
fn checksum_correction(actual: u16, desired: u16) -> u16 {
    let c: u32 = (!desired as u32) + (actual as u32);
    let mut c = (c & 0xFFFF) + (c >> 16);
    c = (c & 0xFFFF) + (c >> 16); // handle second carry
    c as u16
}

/// Creates a TCP (Paris) traceroute probe packet.
///
/// Encodes the following information in the seq and ack fields.
/// - Bits 31-22: worker_id (10 bits, up to 1024 workers)
/// - Bits 21-14: TTL (8 bits)
/// - Bits 13-0:  timestamp in milliseconds (14 bits)
///
/// # Arguments
/// * `src` - source address
/// * `dst` - destination address
/// * `sport` - configured source port
/// * `dport` - configured destination port
/// * `seq` - encoded identity (worker_id + ttl + timestamp); written to both seq and ack
/// * `ttl` - time-to-live / hop limit
/// * `info_url` - optional URL encoded in payload
pub fn create_tcp_trace(
    src: &Address,
    dst: &Address,
    sport: u16,
    dport: u16,
    seq: u32,
    ttl: u8,
    info_url: Option<&str>,
) -> Vec<u8> {
    let body: Vec<u8> = if let Some(url) = info_url {
        url.bytes().collect()
    } else {
        vec![]
    };

    let mut tcp_packet = TCPPacket {
        sport,
        dport,
        seq,
        ack: seq, // same identity in ack: the destination RST echoes ack (RST.seq = ack + 1)
        offset: 0b01010000, // Data offset 5 (20 bytes)
        flags: 0b00010010, // SYN + ACK (unsolicited → elicits RST from the target)
        checksum: 0,
        pointer: 0,
        body,
        window_size: 65535,
    };

    let tcp_bytes: Vec<u8> = (&tcp_packet).into();
    let pseudo_header = PseudoHeader::new(src, dst, 6, tcp_bytes.len() as u32);
    tcp_packet.checksum = calculate_checksum(&tcp_bytes, &pseudo_header);

    build_ip_packet(
        src,
        dst,
        ttl,
        15037,
        PacketPayload::Tcp { value: tcp_packet },
    )
}
