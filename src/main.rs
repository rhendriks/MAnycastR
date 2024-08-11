//! This project is an implementation of Verfploeter <https://conferences.sigcomm.org/imc/2017/papers/imc17-final46.pdf>.
//!
//! It is an extension of the original Verfploeter code <https://github.com/Woutifier/verfploeter>.
//!
//! # The components
//!
//! It allows for performing synchronized probes from a distributed set of nodes.
//! To achieve this, it uses three components (all in the same binary):
//!
//! * [Server](server) - a central controller that receives a measurement definition from the CLI and sends instructions to the connected clients to perform the measurement
//! * [CLI](cli) - a locally ran instructor that takes a user command-line argument and creates a measurement definition that is sent to the server
//! * [Client](client) - the client connects to the server and awaits tasks to send out probes and listen for incoming replies
//!
//! # Measurements
//!
//! A measurement consists of multiple tasks that are executed by the clients.
//! A measurement is created by locally running the CLI using a command, from this command a measurement definition is created which is sent to the server.
//! The server performs this measurement by sending tasks to the clients, who perform the desired measurement by sending out probes.
//! These clients then stream back the results to the server, as they receive replies.
//! The server forwards these results to the CLI.
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
//! * **Rate** - The rate (packets / second) at which each client will send out probes (default: 1000)
//! * **Clients** - The clients that will send out probes for this measurement (default: all clients send probes)
//! * **Stream** - Stream the results to the command-line interface
//! * **Shuffle** - Shuffle the hitlist before sending out probes
//! * **Unicast** - Probe the targets using the unicast address of each client
//! * **Traceroute** - Probe the targets using traceroute (currently broken)
//! * **Divide** - Divide the hitlist into equal separate parts for each client (divide and conquer)
//! * **Interval** - Interval between separate client's probes to the same target (default: 1s)
//! * **Address** - Source IP to use for the probes
//! * **Source port** - Source port to use for the probes (default: 62321)
//! * **Destination port** - Destination port to use for the probes (default: DNS: 53, TCP: 63853)
//! * **Conf** - Path to a configuration file (allowing for complex configurations of source address, port values used by clients)
//!
//! # Results
//!
//! The CLI will await task results after sending its command to the server.
//! When the server is finished it will notify the CLI, after which it prints out all task results on the command-line interface, and writes them to a .csv file (with the current timestamp encoded in the filename).
//!
//! # Usage
//!
//! First, run the central server.
//! ```
//! server -p [PORT NUMBER]
//! ```
//!
//! Next, run one or more clients.
//! ```
//! client -h [HOSTNAME] -s [SERVER ADDRESS] -a [SOURCE IP]
//! ```
//! Server address has format IPv4:port (e.g., 187.0.0.0:50001), '-a SOURCE IP' is optional.
//!
//! To confirm that the clients are connected, you can run the client-list command on the CLI.
//! ```
//! cli -s [SERVER ADDRESS] client-list
//! ```
//!
//! Finally, you can perform a measurement.
//! ```
//! cli -s [SERVER ADDRESS] start [SOURCE IP] [HITLIST] [TYPE] [RATE] [CLIENTS] --stream --shuffle
//! ```
//! SOURCE IP is the IPv4 address from which to send the probes, HITLIST should be the filename of the hitlist you want to use (this file has to be in src/data), TYPE integer value of desired type of measurement (1 - ICMP; 2 - UDP; 3 - TCP), RATE the rate (packets / second) at which clients will sent out probes, CLIENTS is an optional command that is used to specify which clients have to send out probes (omitting this means all clients will send out probes).
//!
//! The hitlist can be shuffled by using the --shuffle option in the command.
//!
//! The output of the measurement will be printed to command-line (if --stream is used in the command), and be stored in src/out as a CSV file.
//!
//! # Additional CLI options
//!
//! * --live - Check results for Anycast targets as they come in live (unimplemented)
//!
//! * --unicast - Probe the targets using the unicast address of each client
//!
//! * --traceroute - Probe the targets using traceroute (broken)
//!
//! * --divide - Divide the hitlist into equal separate parts for each client (divide and conquer)
//!
//! * --i - Interval between separate client's probes to the same target [default: 1s]
//!
//! # Additional client options
//!
//! * --multi-probing - Enable multi-source probing, i.e., the client will send out probes from all addresses
//!
//! # Measurement details
//!
//! * Measurements are performed in parallel; all clients send out their probes at the same time and in the same order.
//! * Each client probes a target address, approximately 1 second after the previous client sent out theirs.
//! * Clients can be created with a custom source address that is used in the probes (overwriting the source specified by the CLI).
//! * The rate of the measurements is adjustable.
//! * The clients that have to send out probes can be specified.
//!
//! # Robustness
//!
//! * A list of connected clients is maintained by the server and clients that disconnect are removed.
//! * Clients disconnecting during measurements are handled and the server will finish the measurement as well as possible.
//! * CLI disconnecting during a measurement will result in the measurement being cancelled, to avoid unnecessary probes from being sent out (this allows for cancellation of measurements by forcefully closing the CLI during a measurement).
//! * Both server and client enforce the policy that only a single measurement can be active at a time, they will refuse a new measurement if there is still a measurement active.
//! * The server ensures that measurements are started and ended properly.
//!
//! # Probe details
//!
//! ICMP
//! * ICMP ECHO requests (pings) are sent out using a unique payload that contains information about the transmission.
//! * This payload is echoed back by ICMP-responsive hosts, and the received ECHO replies are verified to be part of the current measurement.
//! * From the reply payloads we extract information that give us information from the client that sent the probe.
//!
//! UDP
//! * DNS A Record requests are sent using UDP, within the subdomain of the A Record we encode information.
//! * Since the record does not exist, a DNS server will echo back the domain name, we use this domain to verify the reply is part of our measurement.
//! * Furthermore, we extract information from the subdomain to obtain information from the client that sent the probe.
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
//! Communication between client, CLI, and server is achieved using tonic (a rust implementation of gRPC) <https://github.com/hyperium/tonic>.
//!
//! The protocol definitions are in /proto/verfploeter.proto
//!
//! From these definitions code is generated using protobuf (done in build.rs).

extern crate env_logger;
extern crate log;

use clap::{App, Arg, ArgMatches, SubCommand};

mod cli;
mod server;
mod client;
mod net;
mod custom_module;

/// Parse command line input and start VerfPloeter server, client, or CLI
///
/// Sets up logging, parses the command-line arguments, runs the appropriate initialization function.
fn main() {
    // Setup logging with the default environment, with filter at 'info' level
    let env = env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info");
    env_logger::Builder::from_env(env).init();

    // Parse the command-line arguments
    let matches = parse_cmd();

    if let Some(client_matches) = matches.subcommand_matches("client") {
        println!("[Main] Executing client version {}", env!("GIT_HASH"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let _ = rt.block_on(async { client::Client::new(client_matches).await.expect("Unable to create a client (make sure the Server address is correct, and that the Server is running)") });

        return;
    }
    // If the cli subcommand was selected, execute the cli module (i.e. the cli::execute function)
    else if let Some(cli_matches) = matches.subcommand_matches("cli") {
        println!("[Main] Executing CLI version {}", env!("GIT_HASH"));

        let _ = cli::execute(cli_matches);
        return;
    } else if let Some(server_matches) = matches.subcommand_matches("server") {
        println!("[Main] Executing server version {}", env!("GIT_HASH"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let _ = rt.block_on(async { server::start(server_matches).await.unwrap() });
    }
}

fn parse_cmd<'a>() -> ArgMatches<'a> {
    App::new("MAnycastR")
        .version(env!("GIT_HASH"))
        .author("Remi Hendriks <remi.hendriks@utwente.nl>")
        .about("Performs synchronized Internet measurement from a distributed set of anycast sites")
        .subcommand(
            SubCommand::with_name("server").about("Launches the verfploeter server")
                .arg(
                    Arg::with_name("port")
                        .long("port")
                        .short("p")
                        .takes_value(true)
                        .required(false)
                        .help("Port to listen on [default: 50001]")
                )
                .arg(
                    Arg::with_name("tls")
                        .long("tls")
                        .takes_value(false)
                        .required(false)
                        .help("Use TLS for communication with the server (requires server.crt and server.key in ./tls/)")
                )
        )
        .subcommand(
            SubCommand::with_name("client").about("Launches the verfploeter client")
                .arg(
                    Arg::with_name("server")
                        .short("s")
                        .takes_value(true)
                        .required(true)
                        .help("hostname/ip address:port of the server")
                )
                .arg(
                    Arg::with_name("hostname")
                        .long("hostname")
                        .short("h")
                        .takes_value(true)
                        .required(false)
                        .help("hostname for this client (default: $HOSTNAME)")
                )
                .arg(
                    Arg::with_name("tls")
                        .long("tls")
                        .takes_value(false)
                        .required(false)
                        .help("Use TLS for communication with the server (requires ca.pem in ./tls/)")
                )
        )
        .subcommand(
            SubCommand::with_name("cli").about("Verfploeter CLI")
                .arg(
                    Arg::with_name("server")
                        .short("s")
                        .takes_value(true)
                        .required(true)
                        .help("hostname/ip address:port of the server (e.g., [::1]:50001 for localhost)")
                )
                .arg(
                    Arg::with_name("tls")
                        .long("tls")
                        .takes_value(false)
                        .required(false)
                        .help("Use TLS for communication with the server (requires server.crt and server.key in ./tls/)")
                )
                .subcommand(SubCommand::with_name("client-list").about("retrieves a list of currently connected clients from the server"))
                .subcommand(SubCommand::with_name("start").about("performs verfploeter on the indicated client")
                    .arg(Arg::with_name("IP_FILE").help("A file that contains IP addresses to probe")
                        .required(true)
                        .index(1)
                    )
                    .arg(Arg::with_name("TYPE")
                        .required(true)
                        .index(2)
                        .help("The type of measurement (1: ICMP, 2: UDP/DNS, 3: TCP, 4: UDP/CHAOS)")
                    )
                    .arg(Arg::with_name("RATE")
                        .long("rate")
                        .short("r")
                        .takes_value(true)
                        .required(false)
                        .default_value("1000")
                        .help("The rate at which this measurement is to be performed at each client (number of probes / second) [default: 1000]")
                    )
                    .arg(Arg::with_name("CLIENTS")
                        .long("clients")
                        .short("c")
                        .takes_value(true)
                        .required(false)
                        .help("Specify which clients have to send out probes (all connected clients will listen for packets) [client_id1,client_id2,...]")
                    )
                    .arg(Arg::with_name("STREAM")
                        .long("stream")
                        .takes_value(false)
                        .required(false)
                        .help("Stream results to stdout")
                    )
                    .arg(Arg::with_name("SHUFFLE")
                        .long("shuffle")
                        .takes_value(false)
                        .required(false)
                        .help("Randomly shuffle the ip file")
                    )
                    .arg(Arg::with_name("UNICAST")
                        .long("unicast")
                        .takes_value(false)
                        .required(false)
                        .help("Probe the targets using the unicast address of each client (GCD measurement)")
                    )
                    .arg(Arg::with_name("TRACEROUTE")
                        .long("traceroute")
                        .takes_value(false)
                        .required(false)
                        .help("This option is currently broken")
                    )
                    .arg(Arg::with_name("INTERVAL")
                        .long("interval")
                        .short("i")
                        .takes_value(true)
                        .required(false)
                        .default_value("1")
                        .help("Interval between separate client's probes to the same target [default: 1s]")
                    )
                    .arg(Arg::with_name("DIVIDE")
                        .long("divide")
                        .takes_value(false)
                        .required(false)
                        .help("Divide the hitlist into equal separate parts for each client (divide-and-conquer)")
                    )
                    .arg(Arg::with_name("ADDRESS")
                        .long("addr")
                        .short("a")
                        .takes_value(true)
                        .required(false)
                        .help("Source IP to use for the probes")
                    )
                    .arg(Arg::with_name("SOURCE_PORT")
                        .long("sport")
                        .short("s")
                        .takes_value(true)
                        .required(false)
                        .default_value("62321")
                        .help("Source port to use (default 62321)")
                    )
                    .arg(Arg::with_name("DESTINATION_PORT")
                        .long("dport")
                        .short("d")
                        .takes_value(true)
                        .required(false)
                        .help("Destination port to use (default DNS: 53, TCP: 63853)")
                    )
                    .arg(Arg::with_name("CONF")
                        .long("conf")
                        .short("f")
                        .takes_value(true)
                        .required(false)
                        .help("Path to the configuration file")
                    )
                    .arg(Arg::with_name("CHAOS")
                        .long("chaos")
                        .short("c")
                        .takes_value(true)
                        .required(false)
                        .help("Specify CHAOS record to request (default: hostname.bind)")
                    )
                    .arg(Arg::with_name("RESPONSIVE")
                        .long("responsive")
                        .short("r")
                        .takes_value(false)
                        .required(false)
                        .help("First check if the target is responsive using the Server before sending probes from clients [UNIMPLEMENTED]")
                    )
                    .arg(Arg::with_name("OUT")
                        .long("out")
                        .short("o")
                        .takes_value(true)
                        .required(false)
                        .help("Optional path and/or filename to store the results of the measurement")
                    )
                )
        )
        .get_matches()
}
