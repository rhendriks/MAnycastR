//! Live feed support: reading NDJSON targets from stdin for feed-based measurements.

use crate::cli::config::resolve_workers;
use crate::custom_module::manycastr::{Address, CliMessage, LiveTarget, TargetBatch, cli_message};
use crate::{ALL_ORIGINS, ALL_WORKERS, ANY_ORIGIN, ANY_WORKER};
use bimap::BiHashMap;
use futures_core::Stream;
use log::warn;
use std::collections::HashMap;
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
/// The optional `worker` field selects the probing worker: a worker ID, a hostname, a glob
/// (e.g. `us-*` — probes the target from every matched worker), `"all"` (probe from all
/// workers), or `"any"` (round-robin, default).
/// The optional `origin` field selects the origin to send from: an origin ID,
/// `"all"` (all configured origins), or `"any"` (first responsive, default).
/// The optional `nprobes` field sets how many measurement probes are sent to
/// the target (default 1), spaced by the measurement's probe interval.
/// Blocks when the feed channel is full (rate-limiting set by Orchestrator).
/// Runs on a dedicated thread; dropping the sender (at EOF) signals the end of the feed.
pub fn read_stdin_feed(
    feed_tx: mpsc::Sender<CliMessage>,
    worker_map: BiHashMap<u32, String>,
    origins: HashMap<u32, bool>, // origin ID -> is_v6
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

        let targets = parse_feed_line(line, &worker_map, &origins);
        if targets.is_empty() {
            warn!("[CLI] Skipping invalid feed line: {line}");
            continue;
        }

        let addr = targets[0].dst.expect("parsed target always has a dst");
        // Skip IPv4/IPv6 targets when no origin with the same IP version exists
        if !origins.values().any(|&is_v6| is_v6 == addr.is_v6()) {
            warn!(
                "[CLI] Skipping target {addr}: no {} origin is configured",
                if addr.is_v6() { "IPv6" } else { "IPv4" }
            );
            continue;
        }

        let msg = CliMessage {
            message: Some(cli_message::Message::Targets(TargetBatch { targets })),
        };
        if feed_tx.blocking_send(msg).is_err() {
            break; // Feed closed (measurement ended)
        }
    }
}

/// Parse a single feed line into live target(s): an NDJSON object
/// (e.g., `{"dst":"1.1.1.1","worker":"ams01","origin":2}`) or a bare address (e.g., `1.1.1.1`).
///
/// Returns one target per selected worker.
/// An empty result means the line was invalid or matched no worker.
fn parse_feed_line(
    line: &str,
    worker_map: &BiHashMap<u32, String>,
    origins: &HashMap<u32, bool>,
) -> Vec<LiveTarget> {
    // Parse a bare address (with default configs)
    if !line.starts_with('{') {
        let Ok(dst) = line.parse::<Address>() else {
            return Vec::new();
        };
        return vec![LiveTarget {
            dst: Some(dst),
            worker_id: ANY_WORKER,
            origin_id: ANY_ORIGIN,
            nprobes: 1,
        }];
    }

    // parse NDJSON format
    parse_feed_object(line, worker_map, origins).unwrap_or_default()
}

/// Parse an NDJSON feed object into one target per selected worker.
/// Returns `None` on a malformed object, an unknown worker/origin, or an invalid nprobes.
fn parse_feed_object(
    line: &str,
    worker_map: &BiHashMap<u32, String>,
    origins: &HashMap<u32, bool>,
) -> Option<Vec<LiveTarget>> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let dst = value.get("dst")?.as_str()?.parse::<Address>().ok()?;
    let worker_ids = match value.get("worker") {
        None => vec![ANY_WORKER],
        Some(worker) => parse_worker(worker, worker_map)?,
    };
    let origin_id = match value.get("origin") {
        None => ANY_ORIGIN,
        Some(origin) => parse_origin(origin, origins, dst.is_v6())?,
    };
    let nprobes = match value.get("nprobes") {
        None => 1,
        Some(nprobes) => parse_nprobes(nprobes)?,
    };

    Some(
        worker_ids
            .into_iter()
            .map(|worker_id| LiveTarget {
                dst: Some(dst),
                worker_id,
                origin_id,
                nprobes,
            })
            .collect(),
    )
}

/// Parse `nprobes`, that specifies the number of probes to send to this target.
fn parse_nprobes(nprobes: &serde_json::Value) -> Option<u32> {
    let n = match nprobes {
        // Probe count as JSON number (e.g., "nprobes":3)
        serde_json::Value::Number(n) => n.as_u64()?,
        // Probe count as numeric string (e.g., "nprobes":"3")
        serde_json::Value::String(s) => s.parse::<u64>().ok()?,
        _ => return None,
    };

    if (1..=u8::MAX as u64).contains(&n) {
        Some(n as u32)
    } else {
        warn!("[CLI] '{n}' is not a valid nprobes value (1-255).");
        None
    }
}

/// Resolve a feed line's `origin` value to an origin ID:
/// an origin ID (number or numeric string) of a configured origin, `"all"`,
/// or `"any"` (try origins in order; stop on the first responsive one).
/// A specific origin must match the target's IP version.
fn parse_origin(
    origin: &serde_json::Value,
    origins: &HashMap<u32, bool>,
    dst_is_v6: bool,
) -> Option<u32> {
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

    // IP version of origin must match the target address
    match origins.get(&id) {
        Some(&is_v6) if is_v6 == dst_is_v6 => Some(id),
        Some(&is_v6) => {
            warn!(
                "[CLI] Origin {id} is {} but the target is {}.",
                if is_v6 { "IPv6" } else { "IPv4" },
                if dst_is_v6 { "IPv6" } else { "IPv4" }
            );
            None
        }
        None => {
            warn!("[CLI] Origin ID '{id}' is not a configured origin.");
            None
        }
    }
}

/// Resolve a feed line's `worker` value to the worker selection(s):
/// `"any"` (round-robin) or `"all"` (broadcast) sentinels, or a worker ID, hostname, or glob
/// (e.g. `us-*`) resolved via [`resolve_workers`] — a glob yields one entry per matched worker.
/// Returns `None` (skip the line) on an unknown worker or a glob that matched nothing.
fn parse_worker(
    worker: &serde_json::Value,
    worker_map: &BiHashMap<u32, String>,
) -> Option<Vec<u32>> {
    // Worker ID as JSON number (e.g., "worker":1)
    if let Some(id) = worker.as_u64() {
        let id = u32::try_from(id).ok()?;
        if worker_map.contains_left(&id) {
            return Some(vec![id]);
        }
        warn!("[CLI] Worker ID '{id}' is not a known worker.");
        return None;
    }

    let worker = worker.as_str()?;
    match worker {
        "any" => Some(vec![ANY_WORKER]),
        "all" => Some(vec![ALL_WORKERS]),
        // Worker ID, hostname, or glob
        _ => {
            let ids = resolve_workers(worker, worker_map);
            if ids.is_empty() {
                warn!("[CLI] '{worker}' did not match any known worker ID or hostname.");
                return None;
            }
            Some(ids)
        }
    }
}
