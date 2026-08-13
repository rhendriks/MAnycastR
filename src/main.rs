//! # MAnycastR
//!
//! MAnycastR (Measure Anycast Routing) performs synchronized Internet measurements from a
//! distributed set of anycast Points of Presence (PoPs): catchment mapping, anycast and unicast
//! latency, anycast traceroute, and anycast censuses. IPv4 and IPv6 are both supported, over
//! ICMP, UDP (DNS), and TCP.
//!
//! These pages document the internals. For installation, usage, measurement types, and output
//! formats, see the
//! [README](https://github.com/rhendriks/MAnycastR#readme), or run `manycastr cli start --help`.
//!
//! # The components
//!
//! A deployment consists of three components, each a subcommand of the `manycastr` binary:
//!
//! * [Orchestrator](orchestrator) - a central controller orchestrating measurements
//! * [CLI](cli) - command-line interface scheduling measurements at the Orchestrator and collecting results
//! * [Worker](worker) - deployed on anycast PoPs, performing measurements
//!
//! The CLI sends a measurement definition to the Orchestrator, which instructs the Workers to
//! start the measurement. Workers send probes and receive replies, streaming results back to the
//! Orchestrator, which aggregates them (creating follow-up tasks where the measurement type calls
//! for it) and forwards them to the CLI, which writes the output file.
//!
//! Supporting modules: [net] (packet construction and parsing), [tls] (transport security for the
//! inter-component gRPC connections), and [custom_module] (generated gRPC types).
use clap::builder::{ArgPredicate, PossibleValuesParser};
use clap::{ArgAction, ArgGroup, ArgMatches, Command, arg, value_parser};
use log::{error, info};
use pretty_env_logger::formatted_builder;
use std::io::Write;
use std::process::exit;

mod cli;
mod custom_module;
mod net;
mod orchestrator;
mod tls;
mod worker;

pub const ALL_WORKERS: u32 = 0;
pub const ALL_ORIGINS: u32 = 0;
pub const SINGLE_ORIGIN: u32 = 0; // Used for single Origin measurements

/// Get 6-bits from the measurement ID for the DNS identifier for filtering.
#[inline]
pub fn dns_identifier(m_id: u32) -> u8 {
    (m_id & 0x3F) as u8
}

/// Used for `--responsive` and `--sessions` enabled when using `-m feed`.
#[inline]
pub fn probe_id(m_id: u32, session_id: u32) -> u32 {
    (m_id << 16) | (session_id & 0xFFFF)
}

/// Get the 16-bit measurement ID from a probe ID.
#[inline]
pub fn m_id_of(probe_id: u32) -> u32 {
    probe_id >> 16
}

/// Get the 16-bit session ID from a probe ID.
#[inline]
pub fn session_id_of(probe_id: u32) -> u32 {
    probe_id & 0xFFFF
}

/// Parse command line input and start MAnycastR orchestrator, worker, or CLI
///
/// Sets up logging, parses the command-line arguments, runs the appropriate initialization function.
fn main() {
    // Initialize logging with timestamps
    formatted_builder()
        .parse_env(pretty_env_logger::env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] > {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .init();
    // Parse the command-line arguments
    let matches = parse_cmd();

    if let Some(worker_matches) = matches.subcommand_matches("worker") {
        info!("[Main] Executing Worker version {}", env!("GIT_HASH"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            if let Err(e) = worker::Worker::new(worker_matches).await {
                error!(
                    "[Worker] Unable to connect to the Orchestrator (check -a, --tls, and that the Orchestrator is running): {e}"
                );
                exit(1);
            }
        });
    } else if let Some(cli_matches) = matches.subcommand_matches("cli") {
        info!("[Main] Executing CLI version {}", env!("GIT_HASH"));

        if let Err(e) = cli::execute(cli_matches) {
            error!("[CLI] {e}");
            exit(1);
        }
    } else if let Some(server_matches) = matches.subcommand_matches("orchestrator") {
        info!("[Main] Executing Orchestrator version {}", env!("GIT_HASH"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            if let Err(e) = orchestrator::start(server_matches).await {
                error!("[Orchestrator] {e}");
                exit(1);
            }
        });
    } else {
        error!("[Main] No valid subcommand provided, use --help for more information");
    }
}

/// Parse command line arguments using clap
fn parse_cmd() -> ArgMatches {
    Command::new("manycastr")
        .version(env!("GIT_HASH"))
        .author("Remi Hendriks <remi.hendriks@utwente.nl>")
        .about("Performs synchronized Internet measurement from a distributed set of anycast Points of Presence (PoPs)")
        .subcommand_required(true)
        .subcommand(
            Command::new("orchestrator").about("Launches the MAnycastR Orchestrator")
                .arg(arg!(-p --port <PORT> "Port to listen on").value_parser(value_parser!(u16)).default_value("50001"))
                .arg(arg!(--cli_port <PORT> "Port for CLI (default: CLI shares the --port listener)")
                    .value_parser(value_parser!(u16)))
                .arg(arg!(--tls <CERT> "Enable TLS with the certificate at the given path (e.g., ./tls/orchestrator.crt)"))
                .arg(arg!(--tls_key <KEY> "Path to the TLS private key (default: the --tls path with a .key extension)")
                    .requires("tls"))
                .arg(arg!(-c --config <FILE> "Worker hostname to IDs configuration").value_parser(value_parser!(String)))
                .arg(arg!(--max_rate <RATE> "Maximum probing rate allowed for measurements (probes per second, per Worker; optional)")
                    .value_parser(value_parser!(u32)))
                .arg(arg!(--origins <FILE> "Origin allow-list restricting the origins CLIs may use ('src_addr, protocol[, protocol...]' per line; 'all' allows all protocols)")
                    .value_parser(value_parser!(String)))
        )
        .subcommand(
            Command::new("worker").about("Launches the MAnycastR Worker")
                .arg(arg!(-a --orchestrator <ADDR> "address:port of the Orchestrator (e.g., 10.0.0.0:50001, [::1]:50001, or orchestrator.example.net:50001)").required(true))
                .arg(arg!(-n --hostname <NAME> "hostname for this Worker (default: $HOSTNAME)"))
                .arg(arg!(--tls <CERT> "Enable TLS, authenticating the Orchestrator against the certificate at the given path (its own certificate, or the CA that issued it)"))
                .arg(arg!(--tls_system "Enable TLS, authenticating the Orchestrator against the host's system trust store"))
                .group(ArgGroup::new("tls_mode").args(["tls", "tls_system"]))
                .arg(arg!(--tls_domain <NAME> "Name to authenticate the Orchestrator as (default: the host in -a)")
                    .requires("tls_mode"))
        )
        .subcommand(
            Command::new("cli").about("MAnycastR CLI")
                .arg(arg!(-a --orchestrator <ADDR> "address:port of the Orchestrator (e.g., 10.0.0.0:50001, [::1]:50001, or orchestrator.example.net:50001)").required(true))
                .arg(arg!(--tls <CERT> "Enable TLS, authenticating the Orchestrator against the certificate at the given path (its own certificate, or the CA that issued it)"))
                .arg(arg!(--tls_system "Enable TLS, authenticating the Orchestrator against the host's system trust store"))
                .group(ArgGroup::new("tls_mode").args(["tls", "tls_system"]))
                .arg(arg!(--tls_domain <NAME> "Name to authenticate the Orchestrator as (default: the host in -a)")
                    .requires("tls_mode"))
                .subcommand(Command::new("worker-list").about("retrieves a list of currently connected Workers from the Orchestrator"))
                .subcommand(Command::new("start").about("performs a hitlist-based measurement")
                    .arg(arg!(--hitlist <PATH> "Path to the hitlist file (can be .gz or .bz2 compressed; ISI fsdb hitlists are detected automatically)")
                        .value_parser(value_parser!(String))
                        .conflicts_with("target"))
                    .arg(arg!(-t --target <TARGETS> "Comma-separated target address(es), e.g. '1.1.1.1' or '1.1.1.1,8.8.8.8' (alternative to --hitlist)")
                        .value_parser(value_parser!(String)))
                    .arg(arg!(-p --p_type <TYPE> "Protocols to use")
                        .value_parser(PossibleValuesParser::new(["icmp", "dns", "tcp", "chaos"]))
                        .value_delimiter(',')// Allow for multiple protocols
                        .action(ArgAction::Append)
                        .default_value("icmp")
                        .ignore_case(true))
                    .arg(arg!(-m --m_type <MODE> "Measurement type to perform")
                        .value_parser(PossibleValuesParser::new(["laces", "catchment", "latency", "anycast-traceroute", "tracemap", "feed", "feed-trace"]))
                        .default_value("laces")
                        .ignore_case(true))
                    .arg(arg!(-a --address <ADDR> "Anycast source address, or 'unicastv4'/'unicastv6' to probe from each Worker's local unicast address")
                        .conflicts_with("configuration")
                        .required_unless_present("configuration"))
                    .arg(arg!(-f --configuration <CONF> "Path to config file").conflicts_with_all(["address", "sport", "dport", "p_type"]))
                    .arg(arg!(-r --rate <RATE> "Probing rate at each Worker (packets per second)")
                        .value_parser(value_parser!(u32))
                        .default_value_ifs([
                            ("m_type", ArgPredicate::Equals("anycast-traceroute".into()), Some("10")),
                            ("m_type", ArgPredicate::Equals("tracemap".into()), Some("10")),
                        ])
                        .default_value("1000"))
                    .arg(arg!(selective: -x --selective <IDS> "List of Worker IDs/hostnames that send probes [worker_id1,worker_id2,...]"))
                    .arg(arg!(-o --out <PATH> "Optional path/filename to write output").default_value("./"))
                    .arg(arg!(--parquet "Write as .parquet (instead of .csv.gz)").action(ArgAction::SetTrue))
                    .arg(arg!(--stream "Stream to stdout").action(ArgAction::SetTrue))
                    .arg(arg!(--shuffle "Shuffle hitlist").action(ArgAction::SetTrue))
                    .arg(arg!(--responsive "Check responsiveness of targets for multi-target hitlists and multi-probe measurements.").action(ArgAction::SetTrue))
                    .arg(arg!(--sessions "Enable feed sessions (-m feed only): NDJSON targets may carry a 'session' field (1-65535), reported per reply in the output's 'session' column").action(ArgAction::SetTrue))
                    .arg(arg!(--trace_max_failures <N> "Maximum number of consecutive failures (tracemap: confirmation window past a silent midpoint, default 3)")
                        .value_parser(value_parser!(u32))
                        .default_value_if("m_type", ArgPredicate::Equals("tracemap".into()), Some("3"))
                        .default_value("5"))
                    .arg(arg!(--trace_timeout <N> "Timeout for hops (in seconds)").value_parser(value_parser!(u32)).default_value("3"))
                    .arg(arg!(--trace_max_hop <N> "Maximum TTL value (covers >99% of Internet path lengths)")
                        .value_parser(value_parser!(u32))
                        .default_value("25"))
                    .arg(arg!(--trace_initial_hop <N> "Starting TTL value (skips hops within the PoP's own network)")
                        .value_parser(value_parser!(u32))
                        .default_value("4"))
                    .arg(arg!(--trace_star <BOOL> "Emit a '*' hop to the output for unresponsive (timed-out) hops").value_parser(value_parser!(bool)).default_value("true"))
                    .arg(arg!(-w --worker_interval <N> "Interval between Workers for probes to the same target").value_parser(value_parser!(u32)).default_value("1"))
                    .arg(arg!(-i --probe_interval <N> "Interval between probes from the same Worker to the same target").value_parser(value_parser!(u32)).default_value("1"))
                    .arg(arg!(-c --nprobes <N> "Number of probes to send for each origin,target pair [NOTE: violates probing rate]").value_parser(value_parser!(u32)).default_value("1"))
                    .arg(arg!(-s --sport <PORT> "Source port to use (DNS,UDP)").value_parser(value_parser!(u16)).default_value("62321"))
                    .arg(arg!(-d --dport <PORT> "Destination port to use (default DNS/CHAOS: 53, TCP: 63853)")
                        .value_parser(value_parser!(u16))
                        .default_value_ifs([
                            ("p_type", ArgPredicate::Equals("dns".into()), Some("53")),
                            ("p_type", ArgPredicate::Equals("chaos".into()), Some("53")),
                        ])
                        .default_value("63853")
                    )
                    .arg(arg!(-q --query <QUERY> "Specify DNS record to request (TXT (CHAOS) default: hostname.bind, A default: example.org)")
                        .default_value_ifs([
                            ("p_type", ArgPredicate::Equals("chaos".into()), Some("hostname.bind")),
                            ("p_type", ArgPredicate::Equals("dns".into()), Some("example.org")),
                        ]))
                    .arg(arg!(-u --url <URL> "URL encoded in probe payload (e.g., opt-out URL)"))
                )
            )
        .get_matches()
}
