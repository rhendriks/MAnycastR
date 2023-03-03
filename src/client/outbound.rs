use super::Task;

// TODO socket2 can be converted into socket/stream for UDP/TCP
// This type can be freely converted into the network primitives provided by the standard library, such as TcpStream or UdpSocket, using the From trait, see the example below.


// Ratelimiter dependencies
use ratelimit_meter::{DirectRateLimiter, LeakyBucket};
use std::num::NonZeroU32;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Ping dependencies
use crate::net::{ICMP4Packet, IPv4Packet};
use std::net::{Ipv4Addr, Shutdown, SocketAddr};
use std::sync::Arc;
use tokio::sync::oneshot::Receiver;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::oneshot::Sender;

use crate::client;
use crate::client::verfploeter::PingPayload;
use crate::client::verfploeter::task::Data;

// TODO info_url
// TODO lock thread such that only one task is active at a time

// Perform a ping measurement/task
pub fn perform_ping(dest_addresses: Vec<u32>, socket: Arc<Socket>, mut rx_f: Receiver<()>) {
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
                let mut payload = PingPayload {
                    task_id: 1111,
                    transmit_time,
                    source_address: 3333,
                    destination_address: 4444,
                };

                let mut bytes: Vec<u8> = Vec::new();
                bytes.extend_from_slice(&payload.task_id.to_be_bytes()); // Bytes 0 - 3
                bytes.extend_from_slice(&payload.transmit_time.to_be_bytes()); // Bytes 4 - 11
                bytes.extend_from_slice(&payload.source_address.to_be_bytes()); // Bytes 12 - 15
                bytes.extend_from_slice(&payload.destination_address.to_be_bytes()); // Bytes 16 - 19

                let bind_addr_dest = format!("{}:0", Ipv4Addr::from(dest_addr).to_string());

                let icmp = ICMP4Packet::echo_request(1, 2, bytes);

                // Rate limiting
                while let Err(_) = lb.check() { // TODO needed?
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