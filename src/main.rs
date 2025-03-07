//! This project is an implementation of Verfploeter <https://conferences.sigcomm.org/imc/2017/papers/imc17-final46.pdf>.
//!
//! It is an extension of the original Verfploeter code <https://github.com/Woutifier/verfploeter>.
//!
//! Designed to:
//! 1. measure external anycast infrastructure (using the MAnycast2 and Great-Circle-Distance techniques)
//! 2. measure anycast infrastructure itself (catchment analysis, detecting anycast site fliping, latency to the Internet, ...)
//!
//! # The components
//!
//! It allows for performing synchronized probes from a distributed set of nodes.
//! To achieve this, it uses three components (all in the same binary):
//!
//! * [Orchestrator](orchestrator) - a central controller that receives a measurement definition from the CLI and sends instructions to the connected workers to perform the measurement
//! * [CLI](cli) - a locally ran instructor that takes a user command-line argument and creates a measurement definition that is sent to the orchestrator
//! * [Worker](worker) - the worker connects to the orchestrator and awaits tasks to send out probes and listen for incoming replies
//!
//! # Measurements
//!
//! A measurement consists of multiple tasks that are executed by the workers.
//! A measurement is created by locally running the CLI using a command, from this command a measurement definition is created which is sent to the orchestrator.
//! The orchestrator performs this measurement by sending tasks to the workers, who perform the desired measurement by sending out probes.
//! These workers then stream back the results to the orchestrator, as they receive replies.
//! The orchestrator forwards these results to the CLI.
//!
//! The measurement are probing measurements, which can be:
//! * ICMP ECHO requests
//! * UDP DNS A Record requests
//! * TCP SYN/ACK probes
//! * UDP CHAOS requests
//!
//! When creating a measurement you can specify:
//! * **Source address** - the source address from which the probes are to be sent out
//! * **Destination addresses** - the target addresses that will be probed (i.e., a hitlist)
//! * **Type of measurement** - ICMP, UDP, or TCP
//! * **Rate** - The rate (packets / second) at which each worker will send out probes (default: 1000)
//! * **Workers** - The workers that will send out probes for this measurement (default: all workers send probes)
//! * **Stream** - Stream the results to the command-line interface
//! * **Shuffle** - Shuffle the hitlist before sending out probes
//! * **Unicast** - Probe the targets using the unicast address of each worker
//! * **Traceroute** - Probe the targets using traceroute (currently broken)
//! * **Divide** - Divide the hitlist into equal separate parts for each worker (divide and conquer)
//! * **Interval** - Interval between separate worker's probes to the same target (default: 1s)
//! * **Address** - Source IP to use for the probes
//! * **Source port** - Source port to use for the probes (default: 62321)
//! * **Destination port** - Destination port to use for the probes (default: DNS: 53, TCP: 63853)
//! * **Conf** - Path to a configuration file (allowing for complex configurations of source address, port values used by workers)
//!
//! # Results
//!
//! The CLI will await task results after sending its command to the orchestrator.
//! When the orchestrator is finished it will notify the CLI, after which it prints out all task results on the command-line interface, and writes them to a .csv file (with the current timestamp encoded in the filename).
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
//! worker -h [HOSTNAME] -s [SERVER ADDRESS] -a [SOURCE IP]
//! ```
//! Orchestrator address has format IPv4:port (e.g., 187.0.0.0:50001), '-a SOURCE IP' is optional.
//!
//! To confirm that the workers are connected, you can run the worker-list command on the CLI.
//! ```
//! cli -s [ORCHESTRATOR ADDRESS] worker-list
//! ```
//!
//! Finally, you can perform a measurement.
//! ```
//! cli -s [ORCHESTRATOR ADDRESS] start [SOURCE IP] [HITLIST] [TYPE] [RATE] [WORKERS] --stream --shuffle
//! ```
//!
//! * SOURCE IP is the IPv4 address from which to send the probes.
//!
//! * HITLIST should be the filename of the hitlist you want to use (this file has to be in src/data).
//!
//! * TYPE integer value of desired type of measurement (1 - ICMP; 2 - UDP; 3 - TCP).
//!
//! * RATE the rate (packets / second) at which workers will sent out probes.
//!
//! * WORKERS is an optional command that is used to specify which workers have to send out probes (omitting this means all workers will send out probes).
//!
//! The hitlist can be shuffled by using the --shuffle option in the command.
//!
//! Hitlist format is a list of addresses (can be regular IPs (e.g., 1.1.1.1), or IP numbers (e.g., 16843009)
//!
//! Hitlist may not mix IPv4 and IPv6 addresses.
//!
//! The output of the measurement will be printed to command-line (if --stream is used in the command), and be stored in src/out as a CSV file.
//!
//! # Additional CLI options
//!
//! * --live - Check results for Anycast targets as they come in live (unimplemented)
//!
//! * --unicast - Probe the targets using the unicast address of each worker
//!
//! * --traceroute - Probe the targets using traceroute (broken)
//!
//! * --divide - Divide the hitlist into equal separate parts for each worker (divide and conquer)
//!
//! * --i - Interval between separate worker's probes to the same target [default: 1s]
//!
//! # Additional worker options
//!
//! * --multi-probing - Enable multi-source probing, i.e., the worker will send out probes from all addresses
//!
//! # Measurement details
//!
//! * Measurements are performed in parallel; all workers send out their probes at the same time and in the same order.
//! * Each worker probes a target address, approximately 1 second after the previous worker sent out theirs.
//! * Workers can be created with a custom source address that is used in the probes (overwriting the source specified by the CLI).
//! * The rate of the measurements is adjustable.
//! * The workers that have to send out probes can be specified.
//!
//! # Robustness
//!
//! * A list of connected workers is maintained by the orchestrator and workers that disconnect are removed.
//! * Workers disconnecting during measurements are handled and the orchestrator will finish the measurement as well as possible.
//! * CLI disconnecting during a measurement will result in the measurement being cancelled, to avoid unnecessary probes from being sent out (this allows for cancellation of measurements by forcefully closing the CLI during a measurement).
//! * Both orchestrator and workers enforce the policy that only a single measurement can be active at a time, they will refuse a new measurement if there is still a measurement active.
//! * The orchestrator ensures that measurements are started and ended properly.
//!
//! # Probe details
//!
//! ICMP
//! * ICMP ECHO requests (pings) are sent out using a unique payload that contains information about the transmission.
//! * This payload is echoed back by ICMP-responsive hosts, and the received ECHO replies are verified to be part of the current measurement.
//! * From the reply payloads we extract information that give us information from the worker that sent the probe.
//!
//! UDP
//! * DNS A Record requests are sent using UDP, within the subdomain of the A Record we encode information.
//! * Since the record does not exist, a DNS server will echo back the domain name, we use this domain to verify the reply is part of our measurement.
//! * Furthermore, we extract information from the subdomain to obtain information from the worker that sent the probe.
//!
//! TCP
//! * We send TCP SYN/ACK packets to high port numbers, such that it is very unlikely that there is a TCP service running on that port.
//! * This ensures that we will not create any TCP states on the probed targets. Responsive hosts will send back a TCP RST packet.
//! * Inside the port numbers and ACK number of the probe we encode information that gets echoed back in the RST reply.
//! * To verify a received TCP RST is part of our measurement, we verify the port numbers have valid values.
//!
//! # Requirements
//!
//! rustup
//! ```
//! rustup install stable
//! ```
//!
//! gcc
//! ```
//! apt-get install gcc
//! ```
//!
//! protobuf-compiler
//! ```
//! apt-get install protobuf-compiler
//! ```
//!
//! # gRPC
//!
//! Communication between worker, CLI, and orchestrator is achieved using tonic (a rust implementation of gRPC) <https://github.com/hyperium/tonic>.
//!
//! The protocol definitions are in /proto/verfploeter.proto
//!
//! From these definitions code is generated using protobuf (done in build.rs).

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
    Command::new("MAnycastR") // TODO change name
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
                        .help("address:port of the orchestrator (e.g., 10.0.0.0:50001 or [::1]:50001)") // TODO IPv6 compatible?
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
                .arg(
                    Arg::new("interface")
                        .long("interface")
                        .short('i')
                        .value_parser(value_parser!(String))
                        .required(false)
                        .help("Interface to use for sending probes (will use the default interface if not specified)")
                )
        )
        .subcommand(
            Command::new("cli").about("MAnycastR CLI")
                .arg(
                    Arg::new("orchestrator")
                        .short('a')
                        .value_parser(value_parser!(String))
                        .required(true)
                        .help("address:port of the orchestrator (e.g., 10.0.0.0:50001 or [::1]:50001)") // TODO IPv6 compatible?
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
                    .arg(Arg::new("traceroute")
                        .long("traceroute")
                        .action(ArgAction::SetTrue)
                        .required(false)
                        .help("This option is currently broken")
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
                        .help("Encode URL in probes (e.g., for providing opt-out information, explaining the measurement, etc.)")
                    )
                )
        )
        .get_matches()
}
