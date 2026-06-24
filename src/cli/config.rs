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
/// * `configurations` - list of configurations to check the source address type
/// * `is_shuffle` - boolean whether the hitlist should be shuffled or not
///
/// # Returns
/// * A tuple containing a vector of addresses and a boolean indicating whether the addresses are IPv6 or IPv4.
///
/// # Panics
/// * If the hitlist file cannot be opened.
/// * If the anycast source address type (v4 or v6) does not match the hitlist addresses.
/// * If the hitlist addresses are of mixed types (v4 and v6).
pub fn get_hitlist(
    hitlist_path: &str,
    configurations: &[Configuration],
    is_shuffle: bool,
) -> (Vec<Address>, bool) {
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

    finalize_hitlist(ips, configurations, is_shuffle)
}

/// Build a hitlist from a comma-separated list of target addresses (e.g. from the
/// `--target` CLI flag), as an alternative to a hitlist file. The targets are
/// treated exactly like a hitlist containing those addresses.
///
/// # Arguments
/// * `targets` - comma-separated address list, e.g. "1.1.1.1" or "1.1.1.1,8.8.8.8"
/// * `configurations` - list of configurations to check the source address type
/// * `is_shuffle` - whether the resulting hitlist should be shuffled
///
/// # Returns
/// * A tuple of the parsed addresses and whether they are IPv6.
pub fn get_targets(
    targets: &str,
    configurations: &[Configuration],
    is_shuffle: bool,
) -> (Vec<Address>, bool) {
    let ips: Vec<Address> = targets
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(Address::from)
        .collect();

    finalize_hitlist(ips, configurations, is_shuffle)
}

/// Validate a parsed hitlist (non-empty, single IP version, matching source
/// address type) and optionally shuffle it. Shared by [`get_hitlist`] (file) and
/// [`get_targets`] (inline `--target` list).
///
/// # Panics
/// * If the hitlist is empty.
/// * If the addresses are of mixed types (v4 and v6).
/// * If the anycast source address type does not match the hitlist addresses.
fn finalize_hitlist(
    mut ips: Vec<Address>,
    configurations: &[Configuration],
    is_shuffle: bool,
) -> (Vec<Address>, bool) {
    if ips.is_empty() {
        panic!("No target addresses provided (empty hitlist / target list)");
    }

    let hitlist_is_v6 = ips[0].is_v6();
    // Panic if the ips in the hitlist are not all the same type
    if ips.iter().any(|ip| ip.is_v6() != hitlist_is_v6) {
        panic!("Hitlist addresses are not all of the same type! (mixed IPv4 & IPv6)");
    }

    // Make sure the anycast address is the same type as the hitlist addresses
    if let Some(src_addr) = configurations.first().and_then(|c| c.origin?.src) {
        let address_is_unicast = src_addr.is_unicast();

        if !address_is_unicast && (src_addr.is_v6() != hitlist_is_v6) {
            panic!(
                "Anycast source ({}) does not match hitlist type ({})",
                if src_addr.is_v6() { "v6" } else { "v4" },
                if hitlist_is_v6 { "v6" } else { "v4" }
            );
        }
    }

    // Shuffle the hitlist, if desired
    if is_shuffle {
        ips.as_mut_slice().shuffle(&mut rand::rng());
    }
    (ips, hitlist_is_v6)
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
/// * If the configuration file contains mixed IPv4 and IPv6 addresses.
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
    let mut is_ipv6: Option<bool> = None;
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

        let src = Address::from(parts[1]);
        if let Some(v6) = is_ipv6 {
            if v6 != src.is_v6() {
                panic!("Configuration file contains mixed IPv4 and IPv6 addresses!");
            }
        } else {
            is_ipv6 = Some(src.is_v6());
        }

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
