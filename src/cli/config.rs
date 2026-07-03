use crate::ALL_WORKERS;
use crate::custom_module::manycastr::{Address, Configuration, Origin, ProtocolType};
use bimap::BiHashMap;
use flate2::read::GzDecoder;
use log::info;
use rand::prelude::SliceRandom;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;

/// Resolve a worker selector token to the matching worker IDs.
///
/// A token is one of:
/// * a numeric worker ID (e.g. `1`) — matched exactly,
/// * an exact hostname (e.g. `ams01`),
/// * a glob with `*` wildcards (e.g. `us-*`) — matched against hostnames.
///
/// Returns every matching worker ID (empty if none match)
pub fn resolve_workers(token: &str, worker_map: &BiHashMap<u32, String>) -> Vec<u32> {
    // Numeric worker ID
    if let Ok(id) = token.parse::<u32>() {
        return if worker_map.contains_left(&id) {
            vec![id]
        } else {
            Vec::new()
        };
    }

    // Hostname glob
    if token.contains('*') {
        return worker_map
            .iter()
            .filter(|(_, hostname)| glob_match(token, hostname))
            .map(|(id, _)| *id)
            .collect();
    }

    // Exact hostname
    worker_map
        .get_by_right(token)
        .map(|&id| vec![id])
        .unwrap_or_default()
}

/// IP versions present in a set of addresses (hitlist targets or origin sources).
#[derive(Clone, Copy, Default, PartialEq)]
pub struct IpVersions {
    pub has_v4: bool,
    pub has_v6: bool,
}

impl IpVersions {
    /// Collect the IP versions used by the (resolved) origin source addresses.
    pub fn from_origins(configurations: &[Configuration]) -> Self {
        let mut versions = IpVersions::default();
        for src in configurations.iter().filter_map(|c| c.origin?.src) {
            if src.is_v6() {
                versions.has_v6 = true;
            } else {
                versions.has_v4 = true;
            }
        }
        versions
    }

    /// Collect the IP versions present in a list of target addresses.
    pub fn from_targets(targets: &[Address]) -> Self {
        let mut versions = IpVersions::default();
        for addr in targets {
            if addr.is_v6() {
                versions.has_v6 = true;
            } else {
                versions.has_v4 = true;
            }
        }
        versions
    }

    /// Human-readable label, e.g. "IPv4" or "IPv4+IPv6".
    pub fn label(&self) -> &'static str {
        match (self.has_v4, self.has_v6) {
            (true, true) => "IPv4+IPv6",
            (false, true) => "IPv6",
            _ => "IPv4",
        }
    }
}

/// Parse an origin source address token: an anycast IP address, or one of the
/// unicast keywords `unicastv4`/`unicastv6`.
///
/// # Panics
/// * If the token is not a valid address or unicast keyword.
pub fn parse_src_address(token: &str) -> Address {
    if token.eq_ignore_ascii_case("unicastv4") {
        Address::unicast_v4()
    } else if token.eq_ignore_ascii_case("unicastv6") {
        Address::unicast_v6()
    } else if token.eq_ignore_ascii_case("unicast") {
        panic!("'unicast' must specify an IP version: use 'unicastv4' or 'unicastv6'");
    } else {
        Address::from(token)
    }
}

/// Match `text` against a `*`-wildcard `pattern`
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text; // no wildcard
    }

    let mut pos = 0;
    // Anchor the start (unless the pattern begins with '*')
    if !parts[0].is_empty() {
        if !text.starts_with(parts[0]) {
            return false;
        }
        pos = parts[0].len();
    }
    // Each interior segment must appear, in order, after the previous match
    for part in &parts[1..parts.len() - 1] {
        match text[pos..].find(part) {
            Some(i) => pos += i + part.len(),
            None => return false,
        }
    }
    // Anchor the end (unless the pattern ends with '*')
    let last = parts[parts.len() - 1];
    text.len() >= pos + last.len() && text[pos..].ends_with(last)
}

/// Get the hitlist from a file.
///
/// # Arguments
/// * `hitlist_path` - path to the hitlist file
/// * `is_shuffle` - boolean whether the hitlist should be shuffled or not
///
/// # Returns
/// * A tuple containing a vector of addresses and the IP versions present.
///
/// # Panics
/// * If the hitlist file cannot be opened.
/// * If the hitlist is empty.
pub fn get_hitlist(hitlist_path: &str, is_shuffle: bool) -> (Vec<Address>, IpVersions) {
    let file =
        File::open(hitlist_path).unwrap_or_else(|_| panic!("Unable to open file {hitlist_path}"));

    // Create reader based on file extension
    let reader: Box<dyn BufRead> = if hitlist_path.ends_with(".gz") {
        let decoder = GzDecoder::new(file);
        Box::new(BufReader::new(decoder))
    } else {
        Box::new(BufReader::new(file))
    };

    let ips: Vec<Address> = reader // Create a vector of addresses from the file
        .lines()
        .map_while(Result::ok) // Handle potential errors
        .filter(|l| !l.trim().is_empty()) // Skip empty lines
        .map(Address::from)
        .collect();

    finalize_hitlist(ips, is_shuffle)
}

/// Build a hitlist from a comma-separated list of target addresses (e.g. from the
/// `--target` CLI flag), as an alternative to a hitlist file. The targets are
/// treated exactly like a hitlist containing those addresses.
///
/// # Arguments
/// * `targets` - comma-separated address list, e.g. "1.1.1.1" or "1.1.1.1,8.8.8.8"
/// * `is_shuffle` - whether the resulting hitlist should be shuffled
///
/// # Returns
/// * A tuple of the parsed addresses and the IP versions present.
pub fn get_targets(targets: &str, is_shuffle: bool) -> (Vec<Address>, IpVersions) {
    let ips: Vec<Address> = targets
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(Address::from)
        .collect();

    finalize_hitlist(ips, is_shuffle)
}

/// Validate that a parsed hitlist is non-empty, collect the IP versions it uses,
/// and optionally shuffle it. Shared by [`get_hitlist`] (file) and
/// [`get_targets`] (inline `--target` list).
///
/// # Panics
/// * If the hitlist is empty.
fn finalize_hitlist(mut ips: Vec<Address>, is_shuffle: bool) -> (Vec<Address>, IpVersions) {
    if ips.is_empty() {
        panic!("No target addresses provided (empty hitlist / target list)");
    }

    let versions = IpVersions::from_targets(&ips);

    // Shuffle the hitlist, if desired
    if is_shuffle {
        ips.as_mut_slice().shuffle(&mut rand::rng());
    }
    (ips, versions)
}

/// Parse the worker configurations from a file.
///
/// # Arguments
/// * `conf_file` - path to the configuration file
/// * `worker_map` - a BiHashMap mapping worker IDs to hostnames
///
/// # Returns
/// * A vector of Configuration objects parsed from the file
///
/// # Panics
/// * If the configuration file cannot be opened.
/// * If the configuration file contains invalid formats.
/// * If no valid configurations are found in the file.
pub fn parse_configurations(
    conf_file: &str,
    worker_map: &BiHashMap<u32, String>,
) -> Vec<Configuration> {
    info!("[CLI] Using configuration file: {conf_file}");
    let file = File::open(conf_file)
        .unwrap_or_else(|_| panic!("Unable to open configuration file {conf_file}"));
    let buf_reader = BufReader::new(file);
    let mut origin_id = 0;
    let mut configurations: Vec<Configuration> = Vec::new();

    for line in buf_reader.lines() {
        let line = line.expect("Unable to read configuration line");
        let line = line.trim();
        // Skip comments and empty lines
        if line.is_empty() || line.starts_with("#") {
            continue;
        }

        // Worker, src_addr, src_port, dst_port, protocol
        let parts: Vec<&str> = line.split(",").map(|s| s.trim()).collect();
        if parts.len() != 5 {
            panic!("Invalid configuration format: {line}");
        }

        // Get the workers for this configuration line
        let worker_ids = if parts[0] == "ALL" {
            vec![ALL_WORKERS]
        } else {
            let ids = resolve_workers(parts[0], worker_map);
            if ids.is_empty() {
                panic!(
                    "'{}' did not match any known worker ID or hostname.",
                    parts[0]
                );
            }
            ids
        };

        // Parse the source address
        let src = parse_src_address(parts[1]);

        // Parse to u16 first, must fit in header
        let sport = u16::from_str(parts[2]).expect("Unable to parse src port") as u32;
        let dport = u16::from_str(parts[3]).expect("Unable to parse dst port") as u32;
        let p_type = ProtocolType::from_str(parts[4]).expect("Unable to parse protocol type");
        // Each line is one origin, shared by every worker the selector matched
        origin_id += 1;

        for worker_id in worker_ids {
            configurations.push(Configuration {
                worker_id,
                origin: Some(Origin {
                    src: Some(src),
                    sport,
                    dport,
                    origin_id,
                    p_type: p_type as i32,
                }),
            });
        }
    }
    if configurations.is_empty() {
        panic!("No valid configurations found in file {conf_file}");
    }

    configurations
}
