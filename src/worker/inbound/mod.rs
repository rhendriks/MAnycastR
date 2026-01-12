use log::info;
use std::mem;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, Builder};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

use crate::custom_module::manycastr::{Origin, ProtocolType, Reply, ReplyBatch};
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
    /// A map of valid source addresses and port values (`Origin`) to verify incoming packets against.
    pub origin_map: Vec<Origin>,
    /// A shared signal that can be used to gracefully shut down the worker.
    pub abort_s: Arc<AtomicBool>,
    /// Indicates if the measurement involves traceroute.
    pub is_traceroute: bool,
    /// Indicates if the measurement is using IPv6 (true) or IPv4 (false).
    pub is_ipv6: bool,
    /// Indicates if the measurement is a Record Route measurement.
    pub is_record: bool,
}

/// Listen for incoming packets
/// Creates two threads, one that listens on the socket and another that forwards results to the orchestrator and shuts down the receiving socket when appropriate.
/// Makes sure that the received packets are valid and belong to the current measurement.
///
/// # Arguments
/// * `config` - configuration for the inbound worker thread
/// * `tx` - sender to put task results in
/// * `socket_rx` - the socket to listen on
///
/// # Panics
/// If the measurement type is invalid
pub fn inbound(config: InboundConfig, tx: UnboundedSender<ReplyBatch>, socket: Arc<Socket>) {
    info!("[Worker inbound] Started listener");
    // Result queue to store incoming pings, and take them out when sending the TaskResults to the orchestrator
    let rq = Arc::new(Mutex::new(Vec::new()));
    let rq_c = rq.clone();
    let rx_f_c = config.abort_s.clone();
    Builder::new()
        .name("listener_thread".to_string())
        .spawn(move || {
            // Listen for incoming packets
            let mut received: u32 = 0;
            loop {
                // Check if we should exit
                if rx_f_c.load(Ordering::Relaxed) {
                    break;
                }
                let (packet, ttl, src) = get_packet(&socket).expect("receiving failed");
                println!("Received packet: {:?} with length {}", packet, packet.len());

                let packet: &[u8] = packet.as_ref();
                let result = match (config.is_traceroute, config.is_record, config.p_type) {
                    (true, _, _) => {
                        parse_trace(packet, config.m_id, &config.origin_map, config.is_ipv6)
                    }

                    (_, true, _) => parse_record_route(packet, config.m_id, &config.origin_map),

                    (_, _, ProtocolType::Icmp) => parse_icmp(
                        packet,
                        config.m_id,
                        &config.origin_map,
                        config.is_ipv6,
                        false,
                    ),

                    (_, _, ProtocolType::ADns) | (_, _, ProtocolType::ChaosDns) => parse_dns(
                        packet,
                        config.p_type == ProtocolType::ChaosDns,
                        &config.origin_map,
                        config.is_ipv6,
                    ),

                    (_, _, ProtocolType::Tcp) => {
                        parse_tcp(packet, &config.origin_map, config.is_ipv6)
                    }
                };

                // Invalid packets have value None
                if result.is_none() {
                    continue;
                }

                // Put result in transmission queue
                {
                    received += 1;
                    let mut buffer = rq_c.lock().unwrap();
                    buffer.push(result.unwrap())
                }
            }

            info!(
                "[Worker inbound] Stopped pnet listener (received {} packets)",
                received.with_separator()
            );
        })
        .expect("Failed to spawn listener_thread");

    // Thread for sending the received replies to the orchestrator as TaskResult
    Builder::new()
        .name("result_sender_thread".to_string())
        .spawn(move || {
            handle_results(&tx, config.abort_s, config.worker_id, rq);
        })
        .expect("Failed to spawn result_sender_thread");
}

/// Get a packet from the socket
///
/// # Returns
/// (Packet bytes, TTL/hop count, Source Address)
/// Get a packet from the socket for socket2 0.6.1
// In 0.6.1, these types are located in the root or specific sub-modules.
// Note: 'Cmsg' was renamed to 'ControlMessage' in some 0.6.x iterations,
// but most commonly it is Cmsg in the root.

/// Get a packet and TTL from the socket in socket2 0.6.1
fn get_packet(socket: &Socket) -> Result<(Vec<u8>, Option<u32>, SocketAddr), std::io::Error> {
    let mut buf = [0u8; 2048];

    // Safety: 0.6.1 requires MaybeUninitSlice.
    // This cast is safe as u8 and MaybeUninit<u8> share the same layout.
    let uninit_buf = unsafe {
        std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut MaybeUninit<u8>, buf.len())
    };
    let mut iov_buf = [MaybeUninitSlice::new(uninit_buf)];

    // Control buffer for ancillary data (TTL/Hop Limit)
    let mut control_buf = [MaybeUninit::<u8>::uninit(); 128];

    // Storage for the source address
    let mut source_storage: SockAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0).into();

    loop {
        // Construct the message header using the Builder Pattern (with_...)
        let mut msg = MsgHdrMut::new()
            .with_addr(&mut source_storage)
            .with_buffers(&mut iov_buf)
            .with_control(&mut control_buf);

        // socket2 0.6.1 uses the libc name 'recvmsg'
        match socket.recvmsg(&mut msg, 0) {
            Ok(bytes_read) => {
                let packet_data = buf[..bytes_read].to_vec();
                let source = source_storage.as_socket().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "Invalid source address")
                })?;

                let mut ttl: Option<u32> = None;

                // --- TTL EXTRACTION ---
                if source.is_ipv4() {
                    // Because you used set_header_included(true), the TTL is at index 8
                    // of the IPv4 header, which is included in your packet_data.
                    if packet_data.len() > 8 {
                        ttl = Some(packet_data[8] as u32);
                    }
                } else {
                    // IPv6: socket2 0.6.1 does not provide a safe ControlMessage iterator.
                    // To get the Hop Limit here, you would typically use the `nix` crate
                    // to parse the `control_buf`, OR parse the cmsghdr bytes manually.
                    // For now, we acknowledge IPv6 TTL requires an external parser like nix.
                }

                return Ok((packet_data, ttl, source));
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                return Err(e);
            }
        }
    }
}
/// * `tx` - sender to put task results in
/// * `rx_f` - channel that is used to signal the end of the measurement
/// * `worker_id` - the unique worker ID of this worker
/// * `rq_sender` - contains a vector of all received replies as Reply results
fn handle_results(
    tx: &UnboundedSender<ReplyBatch>,
    rx_f: Arc<AtomicBool>,
    worker_id: u16,
    rq_sender: Arc<Mutex<Vec<Reply>>>,
) {
    loop {
        // Every second, forward the ping results to the orchestrator
        sleep(Duration::from_secs(1));

        // Get the current result queue, and replace it with an empty one
        let rq = {
            let mut guard = rq_sender.lock().unwrap();
            mem::take(&mut *guard)
        };

        // Send the result to the worker handler
        if !rq.is_empty() {
            tx.send(ReplyBatch {
                rx_id: worker_id as u32,
                results: rq,
            })
            .expect("Failed to send TaskResult to worker handler");
        }

        // Exit the thread if worker sends us the signal it's finished
        if rx_f.load(Ordering::SeqCst) {
            // Send default value to let the orchestrator know we are finished
            tx.send(ReplyBatch::default())
                .expect("Failed to send 'finished' signal to orchestrator");
            break;
        }
    }
}
