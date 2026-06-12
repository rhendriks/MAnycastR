//! Live feed support: reading NDJSON targets from stdin for feed-based measurements.

use crate::custom_module::manycastr::{Address, CliMessage, TargetBatch, cli_message};
use futures_core::Stream;
use log::warn;
use std::io::BufRead;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;

/// Size of the bounded stdin-to-gRPC feed channel (blocks stdin when full).
pub const FEED_CHANNEL_SIZE: usize = 1024;

/// Wraps the feed receiver as a `Stream` so it can be used as a gRPC streaming request.
pub struct FeedStream {
    pub(crate) inner: mpsc::Receiver<CliMessage>,
}

/// Implement `Stream` to enable for async message feeding (rate-limited stream at Orc).
impl Stream for FeedStream {
    type Item = CliMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.poll_recv(cx)
    }
}

/// Read NDJSON target lines from stdin and forward them to the live feed.
///
/// Each line is a JSON object with a `dst` field (e.g., `{"dst":"1.1.1.1"}`).
/// Blocks when the feed channel is full (rate-limiting set by Orchestrator).
/// Runs on a dedicated thread; dropping the sender (at EOF) signals the end of the feed.
pub fn read_stdin_feed(feed_tx: mpsc::Sender<CliMessage>, is_ipv6: bool) {
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            break;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let Some(addr) = parse_feed_line(line) else {
            warn!("[CLI] Skipping invalid feed line: {line}");
            continue;
        };

        if addr.is_v6() != is_ipv6 { // TODO support mixed IPv4/IPv6
            warn!(
                "[CLI] Skipping target {addr}: IP version does not match the measurement ({})",
                if is_ipv6 { "IPv6" } else { "IPv4" }
            );
            continue;
        }

        let msg = CliMessage {
            message: Some(cli_message::Message::Targets(TargetBatch {
                targets: vec![addr],
            })),
        };
        if feed_tx.blocking_send(msg).is_err() {
            break; // Feed closed (measurement ended)
        }
    }
}

/// Parse a single NDJSON feed line into a target address (e.g., `{"dst":"1.1.1.1"}`).
fn parse_feed_line(line: &str) -> Option<Address> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let dst = value.get("dst")?.as_str()?;
    dst.parse::<Address>().ok()
}
