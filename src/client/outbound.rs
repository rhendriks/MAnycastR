// TODO socket2 can be converted into socket/stream for UDP/TCP
// This type can be freely converted into the network primitives provided by the standard library, such as TcpStream or UdpSocket, using the From trait, see the example below.

use ratelimit_meter::{DirectRateLimiter, LeakyBucket};
use std::num::NonZeroU32;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::net::{ICMP4Packet, TCPPacket, UDPPacket};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::oneshot::Receiver;
use socket2::Socket;

use crate::client::verfploeter::PingPayload;

// Perform a ping measurement/task
pub fn perform_ping(dest_addresses: Vec<u32>, socket: Arc<Socket>, mut rx_f: Receiver<()>, task_id: u32, client_id: u8, source_addr: u32) {
    println!("[Client outbound] Started pinging thread");
    thread::spawn({
        move || {
            // Rate limiter
            let mut lb = DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(5000).unwrap());

            // Loop over the destination addresses
            for dest_addr in dest_addresses {


                let transmit_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;

                // Create ping payload
                let payload = PingPayload {
                    transmit_time,
                    source_address: source_addr,
                    destination_address: dest_addr,
                    sender_client_id: client_id as u32,
                };

                let mut bytes: Vec<u8> = Vec::new();
                bytes.extend_from_slice(&task_id.to_be_bytes()); // Bytes 0 - 3
                bytes.extend_from_slice(&payload.transmit_time.to_be_bytes()); // Bytes 4 - 11
                bytes.extend_from_slice(&payload.source_address.to_be_bytes()); // Bytes 12 - 15
                bytes.extend_from_slice(&payload.destination_address.to_be_bytes()); // Bytes 16 - 19
                bytes.extend_from_slice(&payload.sender_client_id.to_be_bytes()); // Bytes 20 - 23

                let bind_addr_dest = format!("{}:0", Ipv4Addr::from(dest_addr).to_string());

                let icmp = ICMP4Packet::echo_request(1, 2, bytes);

                // Rate limiting
                while let Err(_) = lb.check() {
                    thread::sleep(Duration::from_millis(1));
                }

                // Send out packet
                if let Err(e) = socket.send_to(
                    &icmp,
                    &bind_addr_dest
                        .to_string()
                        .parse::<SocketAddr>()
                        .unwrap()
                        .into(),
                ) {
                    error!("Failed to send packet to socket: {:?}", e);
                } else {
                    // println!("[Client outbound] Packet sent!");
                }
            }
            debug!("finished ping");

            // All packets have been sent for this task, give the listener 10 seconds for the replies
            thread::sleep(Duration::from_secs(10));
            // Now close down the listener
            rx_f.close();
        }
    });
    println!("[Client outbound] Outbound thread finished");
}

// Perform a UDP measurement/task
pub fn perform_udp(dest_addresses: Vec<u32>, socket: Arc<Socket>, mut rx_f: Receiver<()>, client_id: u8, source_address: u32, source_port: u16) {
    println!("[Client outbound] Started UDP probing thread");
    thread::spawn({
        move || {
            // Rate limiter
            let mut lb = DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(5000).unwrap());

            // Loop over the destination addresses
            for dest_addr in dest_addresses {

                let transmit_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;

                let bind_addr_dest = format!("{}:0", Ipv4Addr::from(dest_addr).to_string()); // TODO port

                let udp = UDPPacket::dns_request(source_address, dest_addr, source_port as u16, Vec::new(), "google.com", transmit_time, client_id);

                // Rate limiting
                while let Err(_) = lb.check() {
                    thread::sleep(Duration::from_millis(1));
                }

                // Send out packet
                if let Err(e) = socket.send_to(
                    &udp,
                    &bind_addr_dest
                        .to_string()
                        .parse::<SocketAddr>()
                        .unwrap()
                        .into(),
                ) {
                    error!("Failed to send UDP packet to socket: {:?}", e);
                } else {
                    // println!("[Client outbound] Packet sent!");
                }
            }
            debug!("finished udp probing");

            // All packets have been sent for this task, give the listener 10 seconds for the replies
            thread::sleep(Duration::from_secs(10));
            // Now close down the listener
            rx_f.close();
        }
    });
    println!("[Client outbound] UDP Outbound thread finished");
}

// Perform a TCP measurement/task
pub fn perform_tcp(dest_addresses: Vec<u32>, socket: Arc<Socket>, mut rx_f: Receiver<()>, task_id: u32, client_id: u8, source_addr: u32, destination_port: u16, source_port: u16) {
    println!("[Client outbound] Started TCP probing thread using source address {:?}", source_addr);
    thread::spawn({
        move || {
            // Rate limiter
            let mut lb = DirectRateLimiter::<LeakyBucket>::per_second(NonZeroU32::new(5000).unwrap());

            // Loop over the destination addresses
            for dest_addr in dest_addresses {


                // TODO can I still store the transmit time information somehow?
                // let transmit_time = SystemTime::now()
                //     .duration_since(UNIX_EPOCH)
                //     .unwrap()
                //     .as_nanos() as u64;

                // let mut bytes: Vec<u8> = Vec::new();
                // bytes.extend_from_slice(&payload.task_id.to_be_bytes()); // Bytes 0 - 3
                // bytes.extend_from_slice(&payload.transmit_time.to_be_bytes()); // Bytes 4 - 11
                // bytes.extend_from_slice(&payload.source_address.to_be_bytes()); // Bytes 12 - 15
                // bytes.extend_from_slice(&payload.destination_address.to_be_bytes()); // Bytes 16 - 19
                // bytes.extend_from_slice(&payload.sender_client_id.to_be_bytes()); // Bytes 20 - 23

                let bind_addr_dest = format!("{}:0", Ipv4Addr::from(dest_addr).to_string()); // TODO port

                // TODO randomize port/seq/ack to avoid being blocked by firewalls
                let seq = task_id; // information in seq gets lost
                let ack = client_id as u32 + 300; // ack information gets returned as seq

                let tcp = TCPPacket::tcp_syn_ack(source_addr, dest_addr, source_port as u16, destination_port as u16, seq, ack, Vec::new()); // TODO what needs to be in the TCP body?

                // Rate limiting
                while let Err(_) = lb.check() {
                    thread::sleep(Duration::from_millis(1));
                }

                // Send out packet
                if let Err(e) = socket.send_to(
                    &tcp,
                    &bind_addr_dest
                        .to_string()
                        .parse::<SocketAddr>()
                        .unwrap()
                        .into(),
                ) {
                    error!("Failed to send TCP packet to socket: {:?}", e);
                } else {
                    // println!("[Client outbound] Packet sent!");
                }
            }
            debug!("finished TCP probing");

            // All packets have been sent for this task, give the listener 10 seconds for the replies
            thread::sleep(Duration::from_secs(10));
            // Now close down the listener
            rx_f.close();
        }
    });
    println!("[Client outbound] TCP Outbound thread finished");
}