//! Live feed support: reading NDJSON targets from stdin for feed-based measurements.

use crate::custom_module::manycastr::{Address, CliMessage, LiveTarget, TargetBatch, cli_message};
use crate::{ALL_ORIGINS, ALL_WORKERS, ANY_ORIGIN, ANY_WORKER};
use bimap::BiHashMap;
use futures_core::Stream;
use log::warn;
use std::collections::HashSet;
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

/// Read target lines from stdin and forward them to the live feed.
///
/// Each line is a JSON object (e.g., `{"dst":"1.1.1.1","worker":"ams01","origin":2}`),
/// or a bare address (e.g., `1.1.1.1`).
/// The optional `worker` field selects the probing worker: a worker ID,
/// a hostname, `"all"` (probe from all workers), or `"any"` (round-robin, default).
/// The optional `origin` field selects the origin to send from: an origin ID,
/// or `"all"` (all configured origins, default).
/// Blocks when the feed channel is full (rate-limiting set by Orchestrator).
/// Runs on a dedicated thread; dropping the sender (at EOF) signals the end of the feed.
pub fn read_stdin_feed(
    feed_tx: mpsc::Sender<CliMessage>,
    is_ipv6: bool,
    worker_map: BiHashMap<u32, String>,
    origin_ids: HashSet<u32>,
) {
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            break;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let Some(target) = parse_feed_line(line, &worker_map, &origin_ids) else {
            warn!("[CLI] Skipping invalid feed line: {line}");
            continue;
        };

        let addr = target.dst.expect("parsed target always has a dst");
        if addr.is_v6() != is_ipv6 {
            // TODO support mixed IPv4/IPv6
            warn!(
                "[CLI] Skipping target {addr}: IP version does not match the measurement ({})",
                if is_ipv6 { "IPv6" } else { "IPv4" }
            );
            continue;
        }

        let msg = CliMessage {
            message: Some(cli_message::Message::Targets(TargetBatch {
                targets: vec![target],
            })),
        };
        if feed_tx.blocking_send(msg).is_err() {
            break; // Feed closed (measurement ended)
        }
    }
}

/// Parse a single feed line into a live target: an NDJSON object
/// (e.g., `{"dst":"1.1.1.1","worker":"ams01","origin":2}`) or a bare address (e.g., `1.1.1.1`).
fn parse_feed_line(
    line: &str,
    worker_map: &BiHashMap<u32, String>,
    origin_ids: &HashSet<u32>,
) -> Option<LiveTarget> {
    // Bare address shorthand (interactive use): any worker (round-robin), any origin
    if !line.starts_with('{') {
        return Some(LiveTarget {
            dst: Some(line.parse::<Address>().ok()?),
            worker_id: ANY_WORKER,
            origin_id: ANY_ORIGIN,
        });
    }

    // NDJSON object (producers/scripts)
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let dst = value.get("dst")?.as_str()?.parse::<Address>().ok()?;
    let worker_id = match value.get("worker") {
        None => ANY_WORKER,
        Some(worker) => parse_worker(worker, worker_map)?,
    };
    let origin_id = match value.get("origin") {
        None => ANY_ORIGIN,
        Some(origin) => parse_origin(origin, origin_ids)?,
    };

    Some(LiveTarget {
        dst: Some(dst),
        worker_id,
        origin_id,
    })
}

/// Resolve a feed line's `origin` value to an origin ID:
/// an origin ID (number or numeric string) of a configured origin, `"all"`,
/// or `"any"` (try origins in order; stop on the first responsive one).
fn parse_origin(origin: &serde_json::Value, origin_ids: &HashSet<u32>) -> Option<u32> {
    let id = match origin {
        // Origin ID as JSON number (e.g., "origin":2)
        serde_json::Value::Number(n) => u32::try_from(n.as_u64()?).ok()?,
        serde_json::Value::String(s) if s == "all" => return Some(ALL_ORIGINS),
        serde_json::Value::String(s) if s == "any" => return Some(ANY_ORIGIN),
        // Origin ID as numeric string (e.g., "origin":"2")
        serde_json::Value::String(s) => match s.parse::<u32>() {
            Ok(id) => id,
            Err(_) => {
                warn!("[CLI] '{s}' is not a valid origin ID.");
                return None;
            }
        },
        _ => return None,
    };

    if origin_ids.contains(&id) {
        return Some(id);
    }
    warn!("[CLI] Origin ID '{id}' is not a configured origin.");
    None
}

/// Resolve a feed line's `worker` value to a worker ID: TODO reuse for hitlist-based -x worker parsing
/// a worker ID (number or numeric string), a hostname, `"all"`, or `"any"`.
fn parse_worker(worker: &serde_json::Value, worker_map: &BiHashMap<u32, String>) -> Option<u32> {
    // Worker ID as JSON number (e.g., "worker":1)
    if let Some(id) = worker.as_u64() {
        let id = u32::try_from(id).ok()?;
        if worker_map.contains_left(&id) {
            return Some(id);
        }
        warn!("[CLI] Worker ID '{id}' is not a known worker.");
        return None;
    }

    let worker = worker.as_str()?;
    match worker {
        "any" => Some(ANY_WORKER),
        "all" => Some(ALL_WORKERS),
        _ => {
            // Worker ID as numeric string (e.g., "worker":"1")
            if let Ok(id) = worker.parse::<u32>() {
                if worker_map.contains_left(&id) {
                    return Some(id);
                }
                warn!("[CLI] Worker ID '{id}' is not a known worker.");
                return None;
            }
            // Hostname
            if let Some(&id) = worker_map.get_by_right(worker) {
                return Some(id);
            }
            warn!("[CLI] '{worker}' is not a valid worker ID or known hostname.");
            None
        }
    }
}
