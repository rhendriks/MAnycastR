use log::info;
use std::mem;
use std::mem::MaybeUninit;
use std::net::{Ipv6Addr, SocketAddr};
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
                println!("Received packet: {:?} with length {} and ttl {:?} and src {:?}", packet, packet.len(), ttl, src);

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
/// (Packet bytes, hop count, Source Address)
/// Get a packet from the socket for socket2 0.6.1
fn get_packet(socket: &Socket) -> Result<(Vec<u8>, Option<u8>, SocketAddr), std::io::Error> {
    let mut buf = [0u8; 2048];

    let uninit_buf = unsafe {
        std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut MaybeUninit<u8>, buf.len())
    };
    let mut iov_buf = [MaybeUninitSlice::new(uninit_buf)];

    let mut control_buf = [MaybeUninit::<u8>::uninit(); 128];

    // Storage for the source address
    let mut source_storage: SockAddr = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0).into();

    loop {
        let mut msg = MsgHdrMut::new()
            .with_addr(&mut source_storage)
            .with_buffers(&mut iov_buf)
            .with_control(&mut control_buf);

        match socket.recvmsg(&mut msg, 0) {
            Ok(bytes_read) => {
                let packet_data = buf[..bytes_read].to_vec();
                let source = source_storage.as_socket().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "Invalid source address")
                })?;

                let ttl: Option<u8> = None; // TODO

                return Ok((packet_data, ttl, source));
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    sleep(Duration::from_millis(1));
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
