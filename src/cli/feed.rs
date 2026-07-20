//! Live feed support: reading NDJSON targets from stdin for feed-based measurements.

use crate::cli::config::resolve_workers;
use crate::custom_module::manycastr::{
    Address, CliMessage, Configuration, LiveTarget, ProtocolType, TargetBatch, cli_message,
};
use crate::{ALL_ORIGINS, ALL_WORKERS};
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

/// Per-origin properties the feed parser needs to validate targets.
pub struct FeedOrigin {
    /// IP version of the origin's source address
    pub is_v6: bool,
    /// Protocol the origin probes with
    pub p_type: ProtocolType,
}

impl FeedOrigin {
    /// TCP and DNS CHAOS do not support session IDs.
    fn supports_sessions(&self) -> bool {
        matches!(self.p_type, ProtocolType::Icmp | ProtocolType::ADns)
    }
}

/// The configured origins available to feed targets, and the default origins for each IP version.
pub struct FeedOrigins {
    /// Origin ID -> IP version and protocol, to match feed targets with compatible origins
    by_id: HashMap<u32, FeedOrigin>,
    /// First configured IPv4 origin (default for IPv4 targets without an `origin` field)
    default_v4: Option<u32>,
    /// First configured IPv6 origin (default for IPv6 targets without an `origin` field)
    default_v6: Option<u32>,
}

impl FeedOrigins {
    /// Collect the unique origins of a measurement.
    /// Set the first origin of each IP version as that version's default.
    pub fn new(configurations: &[Configuration]) -> Self {
        let mut by_id = HashMap::new();
        let mut default_v4 = None;
        let mut default_v6 = None;
        for origin in configurations.iter().filter_map(|c| c.origin) {
            by_id.entry(origin.origin_id).or_insert(FeedOrigin {
                is_v6: origin.is_v6(),
                p_type: origin.p_type(),
            });
            let default = if origin.is_v6() {
                &mut default_v6
            } else {
                &mut default_v4
            };
            default.get_or_insert(origin.origin_id);
        }
        Self {
            by_id,
            default_v4,
            default_v6,
        }
    }

    /// The default origin for a target of the given IP version.
    /// Returns `None` if no origin of that version is configured.
    fn default_for(&self, is_v6: bool) -> Option<u32> {
        let default = if is_v6 {
            self.default_v6
        } else {
            self.default_v4
        };
        if default.is_none() {
            warn!(
                "[CLI] No {} origin is configured.",
                if is_v6 { "IPv6" } else { "IPv4" }
            );
        }
        default
    }

    /// Whether an origin of the given IP version is configured.
    fn has_version(&self, is_v6: bool) -> bool {
        self.by_id.values().any(|origin| origin.is_v6 == is_v6)
    }
}

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
/// The optional `origin` field selects the origin to send from: an origin ID, or
/// `"all"` (all configured origins). Defaults to the first configured origin of
/// the target's IP version.
/// The optional `nprobes` field sets how many measurement probes are sent to
/// the target (default 1), spaced by the measurement's probe interval.
/// The optional `ttl` field (feed-trace only) sets the probe TTL (default 255)
/// The optional `session` field (`--sessions` only) tags the target with a
/// session; replies carry it back for attribution (ICMP/DNS-A only).
/// Blocks when the feed channel is full (rate-limiting set by Orchestrator).
/// Runs on a dedicated thread; dropping the sender (at EOF) signals the end of the feed.
pub fn read_stdin_feed(
    feed_tx: mpsc::Sender<CliMessage>,
    worker_map: BiHashMap<u32, String>,
    origins: FeedOrigins,
    is_trace: bool,    // feed-trace measurement (enables the per-target `ttl` field)
    is_sessions: bool, // feed sessions enabled (--sessions; enables the per-target `session` field)
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

        let Some(target) = parse_feed_line(line, &worker_map, &origins, is_trace, is_sessions)
        else {
            warn!("[CLI] Skipping invalid feed line: {line}");
            continue;
        };

        let addr = target.dst.expect("parsed target always has a dst");
        // Skip origin:all targets when no origin with the same IP version exists
        if !origins.has_version(addr.is_v6()) {
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
    origins: &FeedOrigins,
    is_trace: bool,
    is_sessions: bool,
) -> Option<LiveTarget> {
    // Parse a bare address (with default configs)
    if !line.starts_with('{') {
        let dst = line.parse::<Address>().ok()?;
        return Some(LiveTarget {
            dst: Some(dst),
            worker_ids: Vec::new(), // any worker (round-robin)
            origin_id: origins.default_for(dst.is_v6())?,
            nprobes: 1,    // TODO use unset value of 0 (defaulting to 1)
            ttl: 0,        // unset (default 255 for feed-trace)
            session_id: 0, // no session
        });
    }

    // parse NDJSON format
    parse_feed_object(line, worker_map, origins, is_trace, is_sessions)
}

/// Parse an NDJSON feed object into a live target carrying its worker selection.
/// Returns `None` on a malformed object, an unknown worker/origin, or an invalid nprobes/ttl.
fn parse_feed_object(
    line: &str,
    worker_map: &BiHashMap<u32, String>,
    origins: &FeedOrigins,
    is_trace: bool,
    is_sessions: bool,
) -> Option<LiveTarget> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let dst = value.get("dst")?.as_str()?.parse::<Address>().ok()?;
    let worker_ids = match value.get("worker") {
        None => Vec::new(), // any worker (round-robin)
        Some(worker) => parse_worker(worker, worker_map)?,
    };
    let origin_id = match value.get("origin") {
        None => origins.default_for(dst.is_v6())?,
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
    let session_id = match value.get("session") {
        None => 0, // no session
        Some(_) if !is_sessions => {
            warn!("[CLI] Ignoring 'session': sessions are not enabled (start with --sessions).");
            0
        }
        Some(session) => parse_session(session, origin_id, origins, dst.is_v6())?,
    };

    Some(LiveTarget {
        dst: Some(dst),
        worker_ids,
        origin_id,
        nprobes,
        ttl,
        session_id,
    })
}

/// Parse `session`, a 16-bit session ID (0-65535) tagging this target; replies echo it
/// back so they can be attributed to the submitting session.
/// When set to 0, the target is not attributed to any session (replies are reported with session 0).
///
/// Warns when setting a session for TCP/CHAOS probes (does not support session encoding).
fn parse_session(
    session: &serde_json::Value,
    origin_id: u32,
    origins: &FeedOrigins,
    dst_is_v6: bool,
) -> Option<u32> {
    let n = match session {
        // Session as JSON number (e.g., "session":7)
        serde_json::Value::Number(n) => n.as_u64()?,
        // Session as numeric string (e.g., "session":"7")
        serde_json::Value::String(s) => s.parse::<u64>().ok()?,
        _ => return None,
    };

    if n > u16::MAX as u64 {
        warn!("[CLI] '{n}' is not a valid session value (0-65535).");
        return None;
    }
    if n == 0 {
        return Some(0); // Explicit "no session"
    }

    // Warn when using CHAOS/TCP that cannot encode sessions in probes
    let unattributable = match origin_id {
        ALL_ORIGINS => origins
            .by_id
            .values()
            .any(|origin| origin.is_v6 == dst_is_v6 && !origin.supports_sessions()),
        id => origins
            .by_id
            .get(&id)
            .is_some_and(|o| !o.supports_sessions()),
    };
    if unattributable {
        warn!(
            "[CLI] Session {n}: TCP/CHAOS replies cannot echo the session ID; their rows will report session 0."
        );
    }

    Some(n as u32)
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
/// an origin ID (number or numeric string) of a configured origin, or `"all"`.
/// A specific origin must match the target's IP version.
fn parse_origin(origin: &serde_json::Value, origins: &FeedOrigins, dst_is_v6: bool) -> Option<u32> {
    let id = match origin {
        // Origin ID as JSON number (e.g., "origin":2)
        serde_json::Value::Number(n) => u32::try_from(n.as_u64()?).ok()?,
        serde_json::Value::String(s) if s == "all" => return Some(ALL_ORIGINS),
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
    match origins.by_id.get(&id) {
        Some(origin) if origin.is_v6 == dst_is_v6 => Some(id),
        Some(origin) => {
            warn!(
                "[CLI] Origin {id} is {} but the target is {}.",
                if origin.is_v6 { "IPv6" } else { "IPv4" },
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
