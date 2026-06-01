use log::info;
use std::mem::MaybeUninit;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{sleep, Builder};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

use crate::custom_module::manycastr::{ProtocolType, Reply, ReplyBatch};
use crate::custom_module::Separated;
use crate::worker::inbound::dns::parse_dns;
use crate::worker::inbound::ping::parse_icmp;
use crate::worker::inbound::record_route::parse_record_route;
use crate::worker::inbound::tcp::parse_tcp;
use crate::worker::inbound::trace::parse_trace;
use socket2::{MaybeUninitSlice, MsgHdrMut, SockAddr, Socket};

mod dns;
mod ping;
mod record_route;
mod tcp;
mod trace;

/// Configuration for an inbound packet listening worker.
///
/// This struct holds all the parameters needed to initialize and run a worker
/// that listens for and processes incoming measurement packets.
pub struct InboundConfig {
    /// The unique ID of the measurement.
    pub m_id: u32,
    /// The unique ID of this specific worker.
    pub worker_id: u16,
    /// Protocol used
    pub p_type: ProtocolType,
    /// A shared signal that can be used to gracefully shut down the worker.
    pub abort_s: Arc<AtomicBool>,
    /// Indicates if the measurement involves traceroute.
    pub is_traceroute: bool,
    /// Indicates if the measurement is a Record Route measurement.
    pub is_record: bool,
    /// Whether the socket is DGRAM (unprivileged ICMP, no IP header in packets)
    pub is_dgram: bool,
    /// Origin ID associated with the Socket
    pub origin_id: u32,
    /// Source port used
    pub sport: u16,
    /// Source address used
    pub src: String,
}

/// Listen for incoming packets
/// Creates two threads, one that listens on the socket and another that forwards results to the orchestrator and shuts down the receiving socket when appropriate.
/// Makes sure that the received packets are valid and belong to the current measurement.
///
/// # Arguments
/// * `config` - configuration for the inbound worker thread
/// * `tx` - sender to put task results in
/// * `socket` - the socket to listen on
///
/// # Panics
/// If the measurement type is invalid
pub fn inbound(config: InboundConfig, tx: UnboundedSender<ReplyBatch>, socket: Arc<Socket>) {
    info!(
        "[Worker inbound] Started listener (for Origin {})",
        config.origin_id
    );
    let (reply_tx, reply_rx) = std::sync::mpsc::channel::<Reply>();
    let rx_f_c = config.abort_s.clone();
    let is_dgram = config.is_dgram;
    Builder::new()
        .name("listener_thread".to_string())
        .spawn(move || {
            let mut received: u32 = 0;
            loop {
                let (packet, ttl, src) = match get_packet(&socket, is_dgram) {
                    Ok(result) => result,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if rx_f_c.load(Ordering::Relaxed) {
                            break;
                        }
                        continue;
                    }
                    Err(e) => panic!("Socket error: {}", e),
                };

                let result = match (config.is_traceroute, config.is_record, config.p_type) {
                    (true, _, _) => parse_trace(packet, config.m_id, src.into(), ttl),

                    (_, true, _) => parse_record_route(packet, config.m_id, src.into(), ttl),

                    (_, _, ProtocolType::Icmp) => {
                        parse_icmp(packet, config.m_id, false, src.into(), ttl, is_dgram)
                    }

                    (_, _, ProtocolType::ADns) | (_, _, ProtocolType::ChaosDns) => parse_dns(
                        packet,
                        config.p_type == ProtocolType::ChaosDns,
                        src.into(),
                        ttl,
                        config.sport,
                    ),

                    (_, _, ProtocolType::Tcp) => parse_tcp(packet, src.into(), ttl, config.sport),
                };

                if let Some(reply) = result {
                    received += 1;
                    let _ = reply_tx.send(reply);
                }
            }

            if config.p_type == ProtocolType::Icmp {
                info!(
                    "[Worker inbound] Stopped ICMP ping listener {} (received {} packets)",
                    config.src,
                    received.with_separator(),
                )
            } else {
                info!(
                    "[Worker inbound] Stopped {} listener {}:{} (received {} packets)",
                    config.p_type,
                    config.src,
                    config.sport,
                    received.with_separator(),
                );
            }
        })
        .expect("Failed to spawn listener_thread");

    Builder::new()
        .name("result_sender_thread".to_string())
        .spawn(move || {
            handle_results(&tx, config.abort_s, config.worker_id, reply_rx, config.origin_id);
        })
        .expect("Failed to spawn result_sender_thread");
}

struct ControlBuffer([MaybeUninit<u8>; 128]);

/// Get a packet from a socket with the TTL and src address
/// TODO replace with eBPF code
fn get_packet(socket: &Socket, is_dgram: bool) -> Result<(&[u8], u32, SocketAddr), std::io::Error> {
    let mut buf = [MaybeUninit::<u8>::uninit(); 2048];
    let mut source_storage: SockAddr = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0).into();

    let mut control_storage = ControlBuffer([MaybeUninit::uninit(); 128]);
    let control_buf_bytes = &mut control_storage.0;

    let recv_result = {
        let mut iov_buf = [MaybeUninitSlice::new(&mut buf)];
        let mut msg = MsgHdrMut::new()
            .with_addr(&mut source_storage)
            .with_buffers(&mut iov_buf)
            .with_control(control_buf_bytes);

        socket.recvmsg(&mut msg, 0).map(|n| (n, msg.control_len()))
    };

    match recv_result {
        Ok((bytes_read, control_len)) => {
            let source = source_storage
                .as_socket()
                .ok_or_else(|| std::io::Error::other("invalid source address"))?;

            // SAFETY: recvmsg initialized `bytes_read` and `control_len` bytes respectively
            let (packet_data, ancillary_data) = unsafe { // TODO remove unsafe
                let p = std::slice::from_raw_parts(buf.as_ptr() as *const u8, bytes_read);
                let c = std::slice::from_raw_parts(
                    control_storage.0.as_ptr() as *const u8,
                    control_len,
                );
                (p, c)
            };

            // TODO find better approach for obtaining hop_limit/ttl
            let hop_limit = if source.is_ipv6() {
                // IPv6 header is never included
                parse_hop_limit(ancillary_data).unwrap_or(0)
            } else if is_dgram {
                // dgram does not return the IP header
                parse_ttl_v4(ancillary_data).unwrap_or(0)
            } else {
                // IPv4 header included in raw socket mode, get the TTL at byte 8
                packet_data[8] as u32
            };
            Ok((packet_data, hop_limit, source))
        }
        Err(e) => Err(e),
    }
}

/// Retrieve IPv4 TTL from the ancillary data buffer (IP_RECVTTL cmsg).
/// Used in DGRAM mode where the IPv4 header is not included in the packet data.
fn parse_ttl_v4(data: &[u8]) -> Option<u32> {
    let mut pos = 0;
    while pos + 16 <= data.len() {
        let cmsg_len = usize::from_ne_bytes(data[pos..pos + 8].try_into().ok()?);
        let level = i32::from_ne_bytes(data[pos + 8..pos + 12].try_into().ok()?);
        let type_ = i32::from_ne_bytes(data[pos + 12..pos + 16].try_into().ok()?);

        if level == libc::IPPROTO_IP && type_ == libc::IP_TTL && pos + 17 <= data.len() {
            return Some(data[pos + 16] as u32);
        }

        if cmsg_len == 0 {
            break;
        }
        pos += (cmsg_len + 7) & !7;
    }
    None
}

/// Retrieve IPv6 hop limit from the ancillary_data buffer bytes
fn parse_hop_limit(data: &[u8]) -> Option<u32> {
    let mut pos = 0;
    while pos + 16 <= data.len() {
        // cmsghdr on 64-bit: [0..8] len, [8..12] level, [12..16] type
        let cmsg_len = usize::from_ne_bytes(data[pos..pos + 8].try_into().ok()?);
        let level = i32::from_ne_bytes(data[pos + 8..pos + 12].try_into().ok()?);
        let type_ = i32::from_ne_bytes(data[pos + 12..pos + 16].try_into().ok()?);

        // IPv6 Hop Limit: Level 41 (IPPROTO_IPV6), Type 52 (IPV6_HOPLIMIT)
        if (level == 41) && (type_ == 52) && (pos + 17 <= data.len()) {
            return Some(data[pos + 16] as u32);
        }

        if cmsg_len == 0 {
            break;
        }
        pos += (cmsg_len + 7) & !7; // Align to 8-byte boundary
    }
    None
}

/// Forward results to the Worker handler
///
/// # Arguments
/// * `tx` - sender to put task results in
/// * `rx_f` - channel that is used to signal the end of the measurement
/// * `worker_id` - the unique worker ID of this worker
/// * `reply_rx` - channel receiver for replies from the listener thread
/// * `origin_id` - origin ID associated with this inbound handler
fn handle_results(
    tx: &UnboundedSender<ReplyBatch>,
    rx_f: Arc<AtomicBool>,
    worker_id: u16,
    reply_rx: std::sync::mpsc::Receiver<Reply>,
    origin_id: u32,
) {
    loop {
        sleep(Duration::from_secs(1));

        let mut rq = Vec::new(); // TODO assess using a capacity for each replybatch
        while let Ok(reply) = reply_rx.try_recv() {
            rq.push(reply);
        }

        if !rq.is_empty() {
            tx.send(ReplyBatch {
                rx_id: worker_id as u32,
                results: rq,
                origin_id,
            })
            .expect("Failed to send TaskResult to worker handler");
        }

        if rx_f.load(Ordering::SeqCst) {
            tx.send(ReplyBatch::default())
                .expect("Failed to send 'finished' signal to orchestrator");
            break;
        }
    }
}
