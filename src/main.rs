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
//! * **Responsive** - check if a target is responsive before probing from all workers (unimplemented)
//! * **Out** - path to file or directory to store measurement results (default: ./)
//! * **URL** - encode URL in probes (e.g., for providing opt-out information, explaining the measurement, etc.)
//!
//! ## Flags
//! * **Stream** - stream results to the command-line interface (optional)
//! * **Shuffle** - shuffle the hitlist
//! * **Unicast** - perform measurement using the unicast address of each worker
//! * **Divide** - divide-and-conquer Verfploeter catchment mapping
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
//! ### Divide-and-conquer Verfploeter catchment mapping using TCPv4
//!
//! ```
//! cli -a [::1]:50001 start hitlist.txt -t tcp -a 10.0.0.0 --divide
//! ```
//!
//! hitlist.txt will be split in equal parts among workers (divide-and-conquer), results are stored in ./
//!
//! Enabling divide-and-conquer means each target receives a single probe, whereas before each worker would probe each target.
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
//! * Unicast traceroute / Record Route measurements
//! * Allow feed of targets (instead of a pre-defined hitlist)
//! * Synchronous unicast and anycast measurements

use clap::builder::PossibleValuesParser;
use clap::{value_parser, Arg, ArgAction, ArgGroup, ArgMatches, Command};
use log::{error, info};
use pretty_env_logger::formatted_builder;
use std::io::Write;

mod cli;
mod custom_module;
mod net;
mod orchestrator;
mod worker;

// Measurement type IDs
pub const ICMP_ID: u8 = 1; // ICMP ECHO
pub const A_ID: u8 = 2; // UDP DNS A Record
pub const TCP_ID: u8 = 3; // TCP SYN/ACK
pub const CHAOS_ID: u8 = 4; // UDP DNS TXT CHAOS
pub const ALL_ID: u8 = 255; // All measurement types
pub const ANY_ID: u8 = 254; // Any measurement type
pub const ALL_WORKERS: u32 = u32::MAX; // All workers

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
///
/// Returns the parsed arguments as ArgMatches
fn parse_cmd() -> ArgMatches {
    Command::new("MAnycastR")
        .version(env!("GIT_HASH"))
        .author("Remi Hendriks <remi.hendriks@utwente.nl>")
        .about("Performs synchronized Internet measurement from a distributed set of anycast sites")
        .subcommand(
            Command::new("orchestrator").about("Launches the MAnycastR orchestrator")
                .arg(
                    Arg::new("port")
                        .long("port")
                        .short('p')
                        .value_parser(value_parser!(u16))
                        .required(false)
                        .default_value("50001")
                        .help("Port to listen on")
                )
                .arg(
                    Arg::new("tls")
                        .long("tls")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("Use TLS for communication with the orchestrator (requires orchestrator.crt and orchestrator.key in ./tls/)")
                )
                .arg(
                    Arg::new("config")
                        .long("config")
                        .short('c')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Worker list configuration (mapping hostname to ID)")
                )
        )
        .subcommand(
            Command::new("worker").about("Launches the MAnycastR worker")
                .arg(
                    Arg::new("orchestrator")
                        .short('a')
                        .value_parser(value_parser!(String))
                        .required(true)
                        .help("address:port of the orchestrator (e.g., 10.0.0.0:50001 or [::1]:50001)")
                )
                .arg(
                    Arg::new("hostname")
                        .long("hostname")
                        .short('n')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("hostname for this worker (default: $HOSTNAME)")
                )
                .arg(
                    Arg::new("tls")
                        .long("tls")
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Use TLS for communication with the orchestrator (requires orchestrator.crt in ./tls/), takes a FQDN as argument")
                )
        )
        .subcommand(
            Command::new("cli").about("MAnycastR CLI")
                .arg(
                    Arg::new("orchestrator")
                        .short('a')
                        .value_parser(value_parser!(String))
                        .required(true)
                        .help("address:port of the orchestrator (e.g., 10.0.0.0:50001 or [::1]:50001)")
                )
                .arg(
                    Arg::new("tls")
                        .long("tls")
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Use TLS for communication with the orchestrator (requires orchestrator.crt in ./tls/), takes a FQDN as argument")
                )
                .subcommand(Command::new("worker-list").about("retrieves a list of currently connected workers from the orchestrator"))
                .subcommand(Command::new("live").about("performs a feed-based measurement [UNIMPLEMENTED]") // TODO
                    .arg(Arg::new("pipe")
                        .long("pipe")
                        .short('p')
                        .value_parser(value_parser!(String))
                        .required(true)
                        .help("A FIFO pipe that provides IP addresses to probe")
                    )
                    .arg(Arg::new("url")
                        .long("url")
                        .short('u')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .default_value("")
                        .help("Encode URL in probes (e.g., for providing opt-out information, explaining the measurement, etc.)")
                    )
                )
                .subcommand(Command::new("start").about("performs a hitlist-based measurement")
                    .arg(Arg::new("hitlist")
                        .long("hitlist")
                        .short('h')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Path to the hitlist file (can be .gz compressed)")
                    )
                    .arg(Arg::new("target") // TODO implement single target probing (stream results to stdout and create no output file)
                        .long("target")
                        .short('g')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Probe a single target instead of a hitlist, result is streamed to stdout [UNIMPLEMENTED]")
                        .conflicts_with_all(["hitlist", "out"])
                    )
                    .arg(Arg::new("type")
                        .long("type")
                        .short('t')
                        .value_parser(PossibleValuesParser::new([
                            "icmp", "dns", "tcp", "chaos", "any", "all",
                        ]))
                        .ignore_case(true)
                        .required(false)
                        .default_value("icmp")
                        .help("The type of measurement")
                    )
                    .arg(Arg::new("rate")
                        .long("rate")
                        .short('r')
                        .value_parser(value_parser!(u32))
                        .required(false)
                        .default_value("1000")
                        .help("Probing rate at each worker (number of outgoing packets / second)")
                    )
                    .arg(Arg::new("selective")
                        .long("selective")
                        .short('x')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Specify which workers have to send out probes (all connected workers will listen for packets) [worker_id1,worker_id2,...]")
                        .conflicts_with_all(["configuration", "latency", "traceroute", "record"])
                    )
                    .arg(Arg::new("configuration")
                        .long("conf")
                        .short('f')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Path to the configuration file")
                        .conflicts_with_all(["selective", "traceroute", "record", "unicast", "address"])
                    )
                    .arg(Arg::new("out")
                        .long("out")
                        .short('o')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .default_value("./")
                        .help("Optional path and/or filename to store the results of the measurement")
                        .conflicts_with("target")
                    )
                    .arg(Arg::new("parquet")
                        .long("parquet")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("Write results as parquet instead of .csv.gz")
                        .conflicts_with("target")
                    )
                    .arg(Arg::new("stream")
                        .long("stream")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("Stream results to stdout")
                        .conflicts_with("parquet") // TODO support streaming with .parquet output file
                    )
                    .arg(Arg::new("shuffle")
                        .long("shuffle")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("Shuffle the hitlist before probing")
                        .conflicts_with("target")
                        .requires("hitlist")
                    )
                    .arg(Arg::new("unicast")
                        .long("unicast")
                        .action(ArgAction::SetTrue)
                        .help("Probe targets using each worker's unicast address")
                        .conflicts_with_all(["latency", "traceroute", "record", "divide", "address", "configuration"])
                    )
                    .arg(Arg::new("divide")
                        .long("divide")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("Divide the hitlist into equal separate parts for each worker (divide-and-conquer)")
                        .conflicts_with_all(["latency", "traceroute", "record", "unicast"])
                    )
                    .arg(Arg::new("latency")
                        .long("latency")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("Measure anycast latencies (first, measure catching PoP; second, measure latency from catching PoP to target)")
                        .conflicts_with_all(["divide", "unicast", "selective", "traceroute", "record"])
                    )
                    .arg(Arg::new("responsive")
                        .long("responsive")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("First check if the target is responsive from a single worker before sending probes from multiple workers/origins")
                        .conflicts_with_all(["latency", "divide", "traceroute", "record"])
                    )
                    .arg(Arg::new("traceroute")
                        .long("traceroute")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("Perform a traceroute from the receiving anycast site for each target [NOTE: violates probing rate]")
                        .conflicts_with_all(["latency", "responsive", "divide", "unicast", "selective", "record", "config"]) // TODO support unicast traceroute
                    )
                    .arg(Arg::new("record")
                        .long("record")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("Perform a Record Route measurement from the receiving anycast site for each target.")
                        .conflicts_with_all(["traceroute", "latency", "responsive", "divide", "unicast", "selective"])
                    )
                    .arg(Arg::new("worker_interval")
                        .long("worker-interval")
                        .short('w')
                        .value_parser(value_parser!(u32))
                        .required(false)
                        .default_value("1")
                        .help("Interval between separate worker's probes to the same target")
                        .conflicts_with_all(["latency", "divide"]) // --latency and --divide send single probes to each address, so no worker interval is needed
                    )
                    .arg(Arg::new("probe_interval")
                        .long("probe-interval")
                        .short('i')
                        .value_parser(value_parser!(u32))
                        .required(false)
                        .default_value("1")
                        .help("Interval between separate probes to the same target")
                    )
                    .arg(Arg::new("number_of_probes")
                        .long("nprobes")
                        .short('c')
                        .value_parser(value_parser!(u32))
                        .required(false)
                        .default_value("1")
                        .help("Number of probes to send to each origin,target pair [NOTE: violates probing rate]")
                    )
                    .arg(Arg::new("address")
                        .long("addr")
                        .short('a')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Anycast source address to use for probes")
                        .conflicts_with_all(["unicast", "configuration"])
                    )
                    .arg(Arg::new("source port")
                        .long("sport")
                        .short('s')
                        .value_parser(value_parser!(u16))
                        .required(false)
                        .default_value("62321")
                        .help("Source port to use")
                        .conflicts_with("configuration")
                    )
                    .arg(Arg::new("destination port")
                        .long("dport")
                        .short('d')
                        .value_parser(value_parser!(u16))
                        .required(false)
                        .help("Destination port to use (default DNS: 53, TCP: 63853)")
                        .conflicts_with("configuration")
                    )
                    .arg(Arg::new("query")
                        .long("query")
                        .short('q')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Specify DNS record to request (TXT (CHAOS) default: hostname.bind, A default: example.org)")
                    )
                    .arg(Arg::new("url")
                        .long("url")
                        .short('u')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .default_value("")
                        .help("Encode URL in probes (e.g., for providing opt-out information, explaining the measurement, etc.)")
                    )
                    .group(
                        ArgGroup::new("source_spec")
                            .args(["address", "unicast", "configuration"])
                            .required(true),
                    )
                    .group(
                        ArgGroup::new("target_spec")
                            .args(["hitlist", "target"])
                            .required(true),
                    )
                    .group(
                        ArgGroup::new("measurement_type")
                            .args(["latency", "traceroute", "record", "unicast", "divide", "responsive"])
                            .multiple(true)
                            .required(false)
                    )
                    .group(
                        ArgGroup::new("output_type")
                            .args(["out", "stream", "parquet"])
                            .multiple(true)
                            .required(false)
                    )
                    .group(
                        ArgGroup::new("probing_control")
                            .args(["rate", "number_of_probes", "probe_interval", "worker_interval", "selective"])
                            .multiple(true)
                            .required(false)
                    )
                    .group(
                        ArgGroup::new("probe_def")
                        .args(["address", "source port", "destination port", "query", "type", "url"])
                        .multiple(true)
                        .required(false)
                    )
                )
            )
        .get_matches()
}
