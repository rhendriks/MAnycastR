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
//! # Measurement types
//!
//! Measurements can be;
//! * `icmp` ICMP ECHO requests
//! * `dns` UDP DNS A Record requests
//! * `tcp` TCP SYN/ACK probes
//! * `chaos` UDP DNS TXT CHAOS requests
//!
//! # Measurement parameters
//!
//! When creating a measurement you can specify:
//!
//! ## Variables
//! * **Hitlist** - addresses to be probed (can be IP addresses or numbers) (.gz compressed files are supported)
//! * **Type of measurement** - ICMP, DNS, TCP, or CHAOS
//! * **Rate** - the rate (packets / second) at which each worker will send out probes (default: 1000)
//! * **Selective** - specify which workers have to send out probes (all connected workers will listen for packets)
//! * **Interval** - interval between separate worker's probes to the same target (default: 1s)
//! * **Address** - source anycast address to use for the probes
//! * **Source port** - source port to use for the probes (default: 62321)
//! * **Destination port** - destination port to use for the probes (default: DNS: 53, TCP: 63853)
//! * **Configuration** - path to a configuration file (allowing for complex configurations of source address, port values used by workers)
//! * **Query** - specify DNS record to request (TXT (CHAOS) default: hostname.bind, A default: google.com)
//! * **Responsive** - check if a target is responsive before probing from all workers
//! * **Out** - path to file or directory to store measurement results (default: ./)
//! * **URL** - encode URL in probes (e.g., for providing opt-out information, explaining the measurement, etc.)
//!
//! ## Flags
//! * **Stream** - stream results to the command-line interface (optional)
//! * **Shuffle** - shuffle the hitlist
//! * **Unicast** - perform measurement using the unicast address of each worker
//! * **verfploeter** - Verfploeter catchment mapping (hitlist split among probing workers)
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
//! ### Verfploeter catchment mapping using ICMPv4
//!
//! ```
//! cli -a [::1]:50001 start hitlist.txt -t icmp -a 10.0.0.0 -o results.csv
//! ```
//!
//! All workers probe the targets in hitlist.txt using ICMPv4, using source address 10.0.0.0, results are stored in results.csv
//!
//! With this measurement each target receives a probe from each worker.
//! Filtering on sender == receiver allows for calculating anycast RTTs.
//!
//! ### Verfploeter catchment mapping using TCPv4
//!
//! ```
//! cli -a [::1]:50001 start hitlist.txt -t tcp -a 10.0.0.0 --verfploeter
//! ```
//!
//! hitlist.txt will be split in equal parts among workers (divide-and-conquer), results are stored in ./
//!
//! Enabling verfploeter means each target receives a single probe, whereas before each worker would probe each target.
//! Benefits are; lower probing burden on targets, less data to process, faster measurements (hitlist split among workers).
//! Whilst this provides a quick catchment mapping, the downside is that you will not be able to calculate anycast RTTs.
//!
//! ### Unicast latency measurement using ICMPv6
//!
//! ```
//! cli -a [::1]:50001 start hitlistv6.txt -t icmp --unicast
//! ```
//!
//! Since the hitlist contains IPv6 addresses, the workers will probe the targets using their IPv6 unicast address.
//!
//! This feature gives the latency between all anycast sites and each target in the hitlist.
//! Filtering on the lowest unicast RTTs indicates the best anycast site for each target.
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
//! Workers need either sudo or the CAP_NET_RAW capability to send out packets.
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

use clap::builder::{ArgPredicate, PossibleValuesParser};
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use log::{error, info};
use pretty_env_logger::formatted_builder;
use std::io::Write;

mod cli;
mod custom_module;
mod net;
mod orchestrator;
mod worker;

pub const ALL_WORKERS: u32 = u32::MAX; // All workers
pub const DNS_IDENTIFIER: u8 = 0b101010; // 42 encoded in DNS transaction field

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
                .arg(arg!(-i --interface <IFACE> "Force interface to use"))
        )
        .subcommand(
            Command::new("cli").about("MAnycastR CLI")
                .arg(arg!(-a --orchestrator <ADDR> "address:port of the orchestrator (e.g., 10.0.0.0:50001 or [::1]:50001)").required(true))
                .arg(arg!(--tls <FQDN> "Enable TLS with provided FQDN (requires orchestrator.crt in ./tls/)"))
                .subcommand(Command::new("worker-list").about("retrieves a list of currently connected workers from the orchestrator"))
                .subcommand(Command::new("start").about("performs a hitlist-based measurement")
                    .arg(arg!(-h --hitlist <PATH> "Path to the hitlist file (can be .gz compressed)").required(true).value_parser(value_parser!(String)))
                    .arg(arg!(-p --p_type <TYPE> "Protocol to use")
                        .value_parser(PossibleValuesParser::new(["icmp", "dns", "tcp", "chaos", "any", "all"]))
                        .default_value("icmp")
                        .ignore_case(true))
                    .arg(arg!(-m --m_type <MODE> "Measurement type to perform [traceroute ICMP only]")
                        .value_parser(PossibleValuesParser::new(["laces", "verfploeter", "latency", "unicast", "anycast-traceroute"]))
                        .default_value("laces")
                        .ignore_case(true))
                    .arg(arg!(--record "Send IPv4 packets with Record Route option [ICMP only]")
                        .action(ArgAction::SetTrue)
                        .requires_if("icmp", "p_type"))
                    .arg(arg!(-a --address <ADDR> "Anycast source address").conflicts_with("configuration"))
                    .arg(arg!(-f --configuration <CONF> "Path to config file").conflicts_with("address"))
                    .arg(arg!(-r --rate <RATE> "Probing rate at each worker (packets per second)")
                        .value_parser(value_parser!(u32))
                        .default_value_if("m_type", ArgPredicate::Equals("anycast-traceroute".into()), Some("10"))
                        .default_value("1000"))
                    .arg(arg!(selective: -x --selective <IDS> "List of worker IDs/hostnames that send probes [worker_id1,worker_id2,...]"))
                    .arg(arg!(-o --out <PATH> "Optional path/filename to write output").default_value("./"))
                    .arg(arg!(--parquet "Write as .parquet (instead of .csv.gz)").action(ArgAction::SetTrue))
                    .arg(arg!(--stream "Stream to stdout").action(ArgAction::SetTrue))
                    .arg(arg!(--shuffle "Shuffle hitlist").action(ArgAction::SetTrue))
                    .arg(arg!(--responsive "Check responsiveness from a single worker, before probing from all workers").action(ArgAction::SetTrue))
                    .arg(arg!(--trace_max_failures <N> "Maximum number of consecutive failures").value_parser(value_parser!(u32)).default_value("3"))
                    .arg(arg!(--trace_timeout <N> "Timeout for hops (in seconds)").value_parser(value_parser!(u32)).default_value("1"))
                    .arg(arg!(--trace_max_hops <N> "Maximum TTL value").value_parser(value_parser!(u32)).default_value("30"))
                    .arg(arg!(--trace_initial_hops <N> "Starting TTL value").value_parser(value_parser!(u32)).default_value("1"))
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
