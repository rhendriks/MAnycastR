//! Live feed support: reading NDJSON targets from stdin for feed-based measurements.

use crate::cli::config::resolve_workers;
use crate::custom_module::manycastr::{Address, CliMessage, LiveTarget, TargetBatch, cli_message};
use crate::{ALL_ORIGINS, ALL_WORKERS, ANY_ORIGIN};
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
/// The optional `worker` field selects the probing worker(s): a worker ID, a hostname, a glob
/// (e.g. `us-*` — probes the target from every matched worker, spaced by the worker interval),
/// `"all"` (probe from all workers), or `"any"` (round-robin, default).
/// The optional `origin` field selects the origin to send from: an origin ID,
/// `"all"` (all configured origins), or `"any"` (first responsive, default).
/// The optional `nprobes` field sets how many measurement probes are sent to
/// the target (default 1), spaced by the measurement's probe interval.
/// The optional `ttl` field (feed-trace only) sets the probe TTL (default 255)
/// Blocks when the feed channel is full (rate-limiting set by Orchestrator).
/// Runs on a dedicated thread; dropping the sender (at EOF) signals the end of the feed.
pub fn read_stdin_feed(
    feed_tx: mpsc::Sender<CliMessage>,
    worker_map: BiHashMap<u32, String>,
    origins: HashMap<u32, bool>, // origin ID -> is_v6
    is_trace: bool,              // feed-trace measurement (enables the per-target `ttl` field)
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

        let Some(target) = parse_feed_line(line, &worker_map, &origins, is_trace) else {
            warn!("[CLI] Skipping invalid feed line: {line}");
            continue;
        };

        let addr = target.dst.expect("parsed target always has a dst");
        // Skip IPv4/IPv6 targets when no origin with the same IP version exists
        if !origins.values().any(|&is_v6| is_v6 == addr.is_v6()) {
            warn!(
                "[CLI] Skipping target {addr}: no {} origin is configured",
                if addr.is_v6() { "IPv6" } else { "IPv4" }
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
///
/// Returns `None` when the line was invalid or matched no worker.
fn parse_feed_line(
    line: &str,
    worker_map: &BiHashMap<u32, String>,
    origins: &HashMap<u32, bool>,
    is_trace: bool,
) -> Option<LiveTarget> {
    // Parse a bare address (with default configs)
    if !line.starts_with('{') {
        let dst = line.parse::<Address>().ok()?;
        return Some(LiveTarget {
            dst: Some(dst),
            worker_ids: Vec::new(), // any worker (round-robin)
            origin_id: ANY_ORIGIN,
            nprobes: 1, // TODO use unset value of 0 (defaulting to 1)
            ttl: 0, // unset (default 255 for feed-trace)
        });
    }

    // parse NDJSON format
    parse_feed_object(line, worker_map, origins, is_trace)
}

/// Parse an NDJSON feed object into a live target carrying its worker selection.
/// Returns `None` on a malformed object, an unknown worker/origin, or an invalid nprobes/ttl.
fn parse_feed_object(
    line: &str,
    worker_map: &BiHashMap<u32, String>,
    origins: &HashMap<u32, bool>,
    is_trace: bool,
) -> Option<LiveTarget> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let dst = value.get("dst")?.as_str()?.parse::<Address>().ok()?;
    let worker_ids = match value.get("worker") {
        None => Vec::new(), // any worker (round-robin)
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
    let ttl = match value.get("ttl") {
        None => 0, // unset (default 255 for feed-trace)
        Some(_) if !is_trace => {
            warn!("[CLI] The 'ttl' field requires a feed-trace measurement (-m feed-trace).");
            return None;
        }
        Some(ttl) => parse_ttl(ttl)?,
    };

    Some(LiveTarget {
        dst: Some(dst),
        worker_ids,
        origin_id,
        nprobes,
        ttl,
    })
}

/// Parse `ttl`, the probe TTL used for this target (feed-trace only, 1-255).
fn parse_ttl(ttl: &serde_json::Value) -> Option<u32> {
    let n = match ttl {
        // TTL as JSON number (e.g., "ttl":12)
        serde_json::Value::Number(n) => n.as_u64()?,
        // TTL as numeric string (e.g., "ttl":"12")
        serde_json::Value::String(s) => s.parse::<u64>().ok()?,
        _ => return None,
    };

    if (1..=u8::MAX as u64).contains(&n) {
        Some(n as u32)
    } else {
        warn!("[CLI] '{n}' is not a valid ttl value (1-255).");
        None
    }
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

/// Resolve a feed line's `worker` value to the target's `worker_ids`:
/// `"any"` (round-robin, empty list) or `"all"` (broadcast, `[ALL_WORKERS]`) sentinels,
/// or a worker ID, hostname, or glob (e.g. `us-*`) resolved via [`resolve_workers`] —
/// a glob yields every matched worker (probed staggered by the worker interval).
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
        "any" => Some(Vec::new()),
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
