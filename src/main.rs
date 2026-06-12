//! # MAnycastR
//!
//! MAnycastR (Measuring Anycast Reloaded) is a tool designed to measure anycast infrastructure.
//!
//! This includes:
//!
//! i) Measuring anycast infrastructure itself
//! * [Verfploeter](https://ant.isi.edu/~johnh/PAPERS/Vries17b.pdf) (mapping anycast catchments)
//! * [Site flipping](https://arxiv.org/pdf/2503.14351) (detecting network regions experiencing anycast site flipping)
//! * Anycast latency (measuring RTT between ping-responsive targets and the anycast infrastructure)
//! * Optimal deployment (measuring 'best' deployment using unicast latencies from all sites)
//! * Multi-deployment probing (measure multiple anycast prefixes simultaneously)
//! * Anycast traceroute (measuring the path from Anycast deployment to targets using traceroute with an anycast source address)
//! * Traceroute catchment mapping (utilizing anycast traceroute to infer catchments for intermediate routers/ASes that send `TTL Time Exceeded` replies)
//!
//! ii) Measuring external anycast infrastructure
//! * [MAnycast2](https://www.sysnet.ucsd.edu/sysnet/miscpapers/manycast2-imc20.pdf) (measuring anycast using anycast)
//! * [iGreedy](https://anycast.telecom-paristech.fr/assets/papers/JSAC-16.pdf) (measuring anycast using Great-Circle-Distance latency measurements)
//!
//! Both IPv4 and IPv6 measurements are supported, with underlying protocols ICMP, UDP (DNS), and TCP.
//!
//! # The components
//!
//! Deployment of MAnycastR consists of three components:
//!
//! * [Orchestrator](orchestrator) - a central controller orchestrating measurements
//! * [CLI](cli) - Command-line interface scheduling measurements at the orchestrator and collecting results
//! * [Worker](worker) - worker deployed on anycast sites, performing measurements
//!
//! # Measurement process
//!
//! A measurement is started by running the CLI, which can be executed e.g., locally or on a VM.
//! The CLI sends a measurement definition based on the arguments provided when running the `start` command.
//! Example commands will be provided in the Usage section.
//!
//! Upon receiving a measurement definition, the orchestrator instructs the workers to start the measurement.
//! Workers perform measurements by sending and receiving probes.
//!
//! Workers stream results to the orchestrator, which aggregates and forwards them to the CLI.
//! The CLI writes results to a CSV file.
//!
//! # Supported protocols
//!
//! Measurements can be;
//! * `icmp` ICMP ECHO requests
//! * `dns` UDP DNS A Record requests
//! * `tcp` TCP SYN/ACK probes
//! * `chaos` UDP DNS TXT CHAOS requests
//!
//! Both IPv4 and IPv6 are supported.
//!
//! # Measurement parameters
//!
//! When creating a measurement, many parameters and options are available (see `cli start --help`)
//!
//! ## Measurement Types
//! * **catchment** - implementation of [Verfploeter](https://ant.isi.edu/~johnh/PAPERS/Vries17b.pdf) using a divide-and-conquer method for rapid catchment mappings
//! * **laces** - sending anycast probes from all PoPs to the target (used for LACeS anycast censuses)
//! * **latency** - measuring anycast latencies (RTT between target and anycast infrastructure)
//! * **unicast** - measuring unicast latencies from all PoPs to the target(lowest RTT indicates 'optimal' PoP)
//! * **anycast-traceroute** - measure path from anycast deployment to target using a Paris traceroute implementation with an anycast source address
//! * **tracemap** - map catchment of unresponsive targets by finding nearby hops that reply with ICMP Time Exceeded
//!
//! # Usage
//!
//! First, run the central orchestrator.
//! ```
//! orchestrator -p [PORT NUMBER]
//! ```
//!
//! Next, run one or more workers.
//! ```
//! worker -a [ORC ADDRESS]
//! ```
//! Orchestrator address has format IPv4:port (e.g., 187.0.0.0:50001)
//!
//! To confirm that the workers are connected, you can run the worker-list command on the CLI.
//! ```
//! cli -a [ORC ADDRESS] worker-list
//! ```
//!
//! Finally, you can perform a measurement.
//! ```
//! cli -a [ORC ADDRESS] start [parameters]
//! ```
//!
//! ## Examples
//!
//! ### Catchment mapping using ICMPv4
//!
//! ```
//! cli -a [::1]:50001 start -m catchment --hitlist hitlist.txt -p icmp -a 10.0.0.0 -o results.csv.gz -r 1000
//! ```
//!
//! All workers probe the targets in hitlist.txt using ICMPv4, using source address 10.0.0.0, results are stored in results.csv.gz
//! Each hitlist target receives a single probe from any worker.
//! Catchment is inferred based on where the ping reply ends up.
//!
//! Hitlist is divided amongst workers, each worker sends out 1,000 packets per second (-r 1000)
//!
//! ### Anycast latency measurement using TCPv4
//!
//! ```
//! cli -a [::1]:50001 start --hitlist hitlist.txt -p tcp -a 10.0.0.0 -m latency
//! ```
//!
//! Similar as above, except the RTT between each hitlist target and the anycast deployment is also measured.
//! Each hitlist target receives 2 probes.
//! The first probe is a `discovery probe` to infer the catching worker for that target (i.e., to which PoP does this target route).
//! The second probe is a `measurement probe` send from the catching worker to measure the latency (sender == receiver).
//!
//! ### Unicast latency measurement using ICMPv6
//!
//! ```
//! cli -a [::1]:50001 start --hitlist hitlistv6.txt -p icmp -m unicast
//! ```
//!
//! Unicast probes will be sent from all workers to measure the latency of the target to all PoPs.
//! Each hitlist target receives a single probe from every worker.
//! Using the lowest unicast RTT, the 'optimal' PoP for that target can be inferred.
//! Furthermore, if the target does not currently route optimally, the performance gain can be estimated (subtracting the lowest unicast RTT from the actual anycast RTT).
//!
//! ### LACeS measurement
//!
//! ```
//! cli -a [::1]:50001 start --hitlist hitlist.txt -p icmp -m laces --responsive
//! ```
//!
//! Anycast probes will be sent from all workers.
//! Each hitlist target receives a single probe from every worker.
//! Used to e.g., perform [MAnycast2](https://www.sysnet.ucsd.edu/sysnet/miscpapers/manycast2-imc20.pdf) anycast censuses.
//! Targets are scanned for responsiveness, using a single worker probe, before probing from all workers (--responsive).
//!
//! ### Anycast traceroute measurement
//!
//! ```
//! cli -a [::1]:50001 start --hitlist hitlist.txt -p icmp -m anycast-traceroute
//! ```
//!
//! Measure the path from the catching PoP to the target.
//! First, a single `discovery probe` is sent to infer the catching worker.
//! Next, multiple traceroute packets are sent from the catching worker to measure the path.
//!
//! # Requirements
//!
//! * rustup
//! * protobuf-compiler
//! * musl-tools
//! * gcc
//!
//! # Installation
//!
//! ## Cargo (static binary)
//!
//! ### Install rustup
//! ```bash
//! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
//! source $HOME/.cargo/env
//! ```
//!
//! ### Install dependencies
//! ```bash
//! apt-get install -y protobuf-compiler gcc musl-tools
//! ```
//!
//! ### Install musl target
//! ```bash
//! rustup target add x86_64-unknown-linux-musl
//! ```
//!
//! ### Clone the repository
//! ```bash
//! git clone <repo>
//! cd <repo_dir>
//! ```
//!
//! ### Compile the code (16 MB binary)
//! ```bash
//! cargo build --release --target x86_64-unknown-linux-musl
//! ```
//!
//! ### Optionally strip the binary (16 MB -> 7.7 MB)
//! ```bash
//! strip target/x86_64-unknown-linux-musl/release/manycast
//! ```
//!
//! Next, distribute the binary to the workers.
//!
//! For ICMP-only measurements (no traceroute or record route), workers can run without sudo.
//!
//! For TCP, DNS, traceroute, or record route measurements, workers need sudo or CAP_NET_RAW:
//! ```bash
//! sudo setcap cap_net_raw,cap_net_admin=eip manycast
//! ```
//!
//! ## Docker
//!
//! ### Build the Docker image
//! ```bash
//! docker build -t manycast .
//! ```
//!
//! Advise is to run the container with network host mode.
//! Additionally, the container needs the CAP_NET_RAW and CAP_NET_ADMIN capability to send out packets.
//! ```bash
//! docker run -it --network host --cap-add=NET_RAW --cap-add=NET_ADMIN manycast
//! ```
//!
//! # Future
//!
//! * Unicast traceroute
//! * Allow feed of targets (instead of a pre-defined hitlist)
//! * Allow for simultaneous/mixed unicast and anycast measurements
//! * Support any/all protocol types to measure targets with multiple protocols

use clap::builder::{ArgPredicate, PossibleValuesParser};
use clap::{ArgAction, ArgMatches, Command, arg, value_parser};
use log::{error, info};
use pretty_env_logger::formatted_builder;
use std::io::Write;

mod cli;
mod custom_module;
mod net;
mod orchestrator;
mod worker;

pub const ALL_WORKERS: u32 = u32::MAX; // All workers
pub const ALL_ORIGINS: u32 = u32::MAX; // Instruction to send from all Origins
pub const SINGLE_ORIGIN: u32 = 0; // Used for single Origin measurements

/// Derive a 6-bit DNS identifier from a measurement ID for filtering.
#[inline]
pub fn dns_identifier(m_id: u32) -> u8 {
    (m_id & 0x3F) as u8
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
        info!("[Main] Executing worker version {}", env!("GIT_HASH"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let _ = rt.block_on(async { worker::Worker::new(worker_matches).await.expect("Unable to create a worker (make sure the Server address is correct, and that the Server is running)") });
    }
    // If the cli subcommand was selected, execute the cli module (i.e. the cli::execute function)
    else if let Some(cli_matches) = matches.subcommand_matches("cli") {
        info!("[Main] Executing CLI version {}", env!("GIT_HASH"));

        let _ = cli::execute(cli_matches);
    } else if let Some(server_matches) = matches.subcommand_matches("orchestrator") {
        info!("[Main] Executing orchestrator version {}", env!("GIT_HASH"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async { orchestrator::start(server_matches).await.unwrap() });
    } else {
        error!("[Main] No valid subcommand provided, use --help for more information");
    }
}

/// Parse command line arguments using clap
fn parse_cmd() -> ArgMatches {
    Command::new("MAnycastR")
        .version(env!("GIT_HASH"))
        .author("Remi Hendriks <remi.hendriks@utwente.nl>")
        .about("Performs synchronized Internet measurement from a distributed set of anycast Points of Presence (PoPs)")
        .subcommand_required(true)
        .subcommand(
            Command::new("orchestrator").about("Launches the MAnycastR orchestrator")
                .arg(arg!(-p --port <PORT> "Port to listen on").value_parser(value_parser!(u16)).default_value("50001"))
                .arg(arg!(--tls "Use TLS (requires certs in ./tls/)").action(ArgAction::SetTrue))
                .arg(arg!(-c --config <FILE> "Worker hostname to IDs configuration").value_parser(value_parser!(String)))
        )
        .subcommand(
            Command::new("worker").about("Launches the MAnycastR worker")
                .arg(arg!(-a --orchestrator <ADDR> "address:port of the orchestrator (e.g., 10.0.0.0:50001 or [::1]:50001)").required(true))
                .arg(arg!(-n --hostname <NAME> "hostname for this worker (default: $HOSTNAME)"))
                .arg(arg!(--tls <FQDN> "Enable TLS with provided FQDN (requires orchestrator.crt in ./tls/)"))
        )
        .subcommand(
            Command::new("cli").about("MAnycastR CLI")
                .arg(arg!(-a --orchestrator <ADDR> "address:port of the orchestrator (e.g., 10.0.0.0:50001 or [::1]:50001)").required(true))
                .arg(arg!(--tls <FQDN> "Enable TLS with provided FQDN (requires orchestrator.crt in ./tls/)"))
                .subcommand(Command::new("worker-list").about("retrieves a list of currently connected workers from the orchestrator"))
                .subcommand(Command::new("start").about("performs a hitlist-based measurement")
                    .arg(arg!(--hitlist <PATH> "Path to the hitlist file (can be .gz compressed)")
                        .value_parser(value_parser!(String))
                        .conflicts_with("target"))
                    .arg(arg!(-t --target <TARGETS> "Comma-separated target address(es), e.g. '1.1.1.1' or '1.1.1.1,8.8.8.8' (alternative to --hitlist)")
                        .value_parser(value_parser!(String))
                        .required_unless_present("hitlist"))
                    .arg(arg!(-p --p_type <TYPE> "Protocols to use")
                        .value_parser(PossibleValuesParser::new(["icmp", "dns", "tcp", "chaos"]))
                        .value_delimiter(',')// Allow for multiple protocols
                        .action(ArgAction::Append)
                        .default_value("icmp")
                        .ignore_case(true))
                    .arg(arg!(-m --m_type <MODE> "Measurement type to perform [traceroute ICMP only]")
                        .value_parser(PossibleValuesParser::new(["laces", "catchment", "latency", "unicast", "anycast-traceroute", "tracemap"]))
                        .default_value("laces")
                        .ignore_case(true))
                    .arg(arg!(--record "Send IPv4 packets with Record Route option [ICMP only]")
                        .action(ArgAction::SetTrue)
                        .requires_if("icmp", "p_type"))
                    .arg(arg!(-a --address <ADDR> "Anycast source address").conflicts_with("configuration"))
                    .arg(arg!(-f --configuration <CONF> "Path to config file").conflicts_with_all(["address", "sport", "dport", "p_type"]))
                    .arg(arg!(-r --rate <RATE> "Probing rate at each worker (packets per second)")
                        .value_parser(value_parser!(u32))
                        .default_value_ifs([
                            ("m_type", ArgPredicate::Equals("anycast-traceroute".into()), Some("10")),
                            ("m_type", ArgPredicate::Equals("tracemap".into()), Some("10")),
                        ])
                        .default_value("1000"))
                    .arg(arg!(selective: -x --selective <IDS> "List of worker IDs/hostnames that send probes [worker_id1,worker_id2,...]"))
                    .arg(arg!(-o --out <PATH> "Optional path/filename to write output").default_value("./"))
                    .arg(arg!(--parquet "Write as .parquet (instead of .csv.gz)").action(ArgAction::SetTrue))
                    .arg(arg!(--stream "Stream to stdout").action(ArgAction::SetTrue))
                    .arg(arg!(--shuffle "Shuffle hitlist").action(ArgAction::SetTrue))
                    .arg(arg!(--responsive "Check responsiveness from a single worker, before probing from all workers").action(ArgAction::SetTrue))
                    .arg(arg!(--any "Try protocols in order (as specified by -p); stop per-target on first responsive protocol. Implies --responsive").action(ArgAction::SetTrue))
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
                    .arg(arg!(-w --worker_interval <N> "Interval between workers for probes to the same target").value_parser(value_parser!(u32)).default_value("1"))
                    .arg(arg!(-i --probe_interval <N> "Interval between probes from the same worker to the same target").value_parser(value_parser!(u32)).default_value("1"))
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
