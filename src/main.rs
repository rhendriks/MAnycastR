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
//! * **Type of measurement** - ICMP, UDP, TCP, or CHAOS
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
//! * Responsiveness pre-check
//! * Anycast traceroute
//! * Allow feed of targets (instead of a pre-defined hitlist)
//! * Support multiple packets per <worker, target> pair
//! * Synchronous unicast and anycast measurements
//! * Anycast latency using divide-and-conquer (probe 1; assess catching anycast site - probe 2; probe from catching site to obtain latency)

use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};

mod cli;
mod custom_module;
mod net;
mod orchestrator;
mod worker;

/// Parse command line input and start MAnycastR orchestrator (orchestrator), worker, or CLI
///
/// Sets up logging, parses the command-line arguments, runs the appropriate initialization function.
fn main() {
    // Parse the command-line arguments
    let matches = parse_cmd();

    if let Some(worker_matches) = matches.subcommand_matches("worker") {
        println!("[Main] Executing worker version {}", env!("GIT_HASH"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let _ = rt.block_on(async { worker::Worker::new(worker_matches).await.expect("Unable to create a worker (make sure the Server address is correct, and that the Server is running)") });

        return;
    }
    // If the cli subcommand was selected, execute the cli module (i.e. the cli::execute function)
    else if let Some(cli_matches) = matches.subcommand_matches("cli") {
        println!("[Main] Executing CLI version {}", env!("GIT_HASH"));

        let _ = cli::execute(cli_matches);
        return;
    } else if let Some(server_matches) = matches.subcommand_matches("orchestrator") {
        println!("[Main] Executing orchestrator version {}", env!("GIT_HASH"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let _ = rt.block_on(async { orchestrator::start(server_matches).await.unwrap() });
    }
}

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
                        .help("Port to listen on [default: 50001]")
                )
                .arg(
                    Arg::new("tls")
                        .long("tls")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("Use TLS for communication with the orchestrator (requires orchestrator.crt and orchestrator.key in ./tls/)")
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
                .subcommand(Command::new("start").about("performs MAnycastR on the indicated worker")
                    .arg(Arg::new("IP_FILE").help("A file that contains IP addresses to probe")
                        .required(true)
                        .index(1)
                    )
                    .arg(Arg::new("type")
                        .long("type")
                        .short('t')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .default_value("icmp")
                        .help("The type of measurement (icmp, dns, tcp, chaos, all) [default: icmp]")
                    )
                    .arg(Arg::new("rate")
                        .long("rate")
                        .short('r')
                        .value_parser(value_parser!(u32))
                        .required(false)
                        .default_value("1000")
                        .help("Probing rate at each worker (number of outgoing packets / second) [default: 1000]")
                    )
                    .arg(Arg::new("selective")
                        .long("selective")
                        .short('x')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Specify which workers have to send out probes (all connected workers will listen for packets) [worker_id1,worker_id2,...]")
                    )
                    .arg(Arg::new("stream")
                        .long("stream")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("Stream results to stdout")
                    )
                    .arg(Arg::new("shuffle")
                        .long("shuffle")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("Randomly shuffle the ip file")
                    )
                    .arg(Arg::new("unicast")
                        .long("unicast")
                        .action(ArgAction::SetTrue)
                        .help("Probe the targets using the unicast address of each worker (GCD measurement)")
                    )
                    .arg(Arg::new("interval")
                        .long("interval")
                        .short('i')
                        .value_parser(value_parser!(u32))
                        .required(false)
                        .default_value("1")
                        .help("Interval between separate worker's probes to the same target [default: 1s]")
                    )
                    .arg(Arg::new("divide")
                        .long("divide")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("Divide the hitlist into equal separate parts for each worker (divide-and-conquer)")
                    )
                    .arg(Arg::new("address")
                        .long("addr")
                        .short('a')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Source address to use for the probes")
                    )
                    .arg(Arg::new("source port")
                        .long("sport")
                        .short('s')
                        .value_parser(value_parser!(u16))
                        .required(false)
                        .default_value("62321")
                        .help("Source port to use (default 62321)")
                    )
                    .arg(Arg::new("destination port")
                        .long("dport")
                        .short('d')
                        .value_parser(value_parser!(u16))
                        .required(false)
                        .help("Destination port to use (default DNS: 53, TCP: 63853)")
                    )
                    .arg(Arg::new("configuration")
                        .long("conf")
                        .short('f')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Path to the configuration file")
                    )
                    .arg(Arg::new("query")
                        .long("query")
                        .short('q')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Specify DNS record to request (TXT (CHAOS) default: hostname.bind, A default: google.com)")
                    )
                    .arg(Arg::new("responsive")
                        .long("responsive")
                        .short('v')
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("First check if the target is responsive using the orchestrator before sending probes from workers [UNIMPLEMENTED]")
                    )
                    .arg(Arg::new("out")
                        .long("out")
                        .short('o')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Optional path and/or filename to store the results of the measurement (default ./)")
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
        )
        .get_matches()
}
