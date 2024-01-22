//! This project is an implementation of Verfploeter <https://conferences.sigcomm.org/imc/2017/papers/imc17-final46.pdf>.
//!
//! It is an extension of the original Verfploeter code <https://github.com/Woutifier/verfploeter>.
//!
//! # The components
//!
//! It allows for performing synchronized probes from a distributed set of nodes.
//! To achieve this, it uses three components (all in the same binary):
//!
//! * [Server](server) - a central controller that receives a task from the CLI and sends instructions to the connected clients to perform measurements
//! * [CLI](cli) - a locally ran instructor that takes a user command-line argument and creates a task that is sent to the server
//! * [Client](client) - the client connects to the server and awaits tasks to send out probes and listen for incoming replies
//!
//! # Tasks
//!
//! A task is created by locally running the CLI using a command, from this command a task is created which is sent to the server.
//! The server performs this task by sending instructions to the clients, who perform the desired measurement by sending out probes.
//! These clients then stream back the results to the server, as they receive replies.
//! The server forwards these results to the CLI.
//!
//! The tasks are probing measurements, which can be:
//! * ICMP ECHO requests
//! * UDP DNS A Record requests
//! * TCP SYN/ACK probes
//!
//! When creating a task you can specify:
//! * **Source address** - the source address from which the probes are to be sent out
//! * **Destination addresses** - the target addresses that will be probed (e.g. a hitlist)
//! * **Type of measurement** - ICMP, UDP, or TCP
//! * **Rate** - The rate (packets / second) at which each client will send out probes (default: 1000)
//! * **Clients** - The clients that will send out probes for this measurement (default: all clients send probes)
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
//! Server address has format IPv4:port (e.g. 187.0.0.0:50001), '-a SOURCE IP' is optional.
//!
//! To confirm that the clients are connected, you can run the client-list command on the CLI.
//! ```
//! cli -s [SERVER ADDRESS] client-list
//! ```
//!
//! Finally, you can perform a task.
//! ```
//! cli -s [SERVER ADDRESS] start [SOURCE IP] [HITLIST] [TYPE] [RATE] [CLIENTS] --stream --shuffle
//! ```
//! SOURCE IP is the IPv4 address from which to send the probes, HITLIST should be the filename of the hitlist you want to use (this file has to be in src/data), TYPE integer value of desired type of measurement (1 - ICMP; 2 - UDP; 3 - TCP), RATE the rate (packets / second) at which clients will sent out probes, CLIENTS is an optional command that is used to specify which clients have to send out probes (omitting this means all clients will send out probes).
//!
//! The hitlist can be shuffled by using the --shuffle option in the command.
//!
//! The output of the measurement will be printed to command-line (if --stream is used in the command), and be stored in src/out as a CSV file.
//!
//! # Measurement details
//!
//! * Measurements are performed in parallel; all clients send out their probes at the same time and in the same order.
//! * Each client probes a target address, approximately 1 second after the previous client sent out theirs.
//! * Clients can be created with a custom source address that is used in the probes (overwriting the source specified by the CLI) [UNIMPLEMENTED].
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
#[macro_use]
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
        println!("[Main] Executing client");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let _ = rt.block_on(async { client::Client::new(client_matches).await.unwrap() });

        return;
    }
    // If the cli subcommand was selected, execute the cli module (i.e. the cli::execute function)
    else if let Some(cli_matches) = matches.subcommand_matches("cli") {
        println!("[Main] Executing CLI");

        let _ = cli::execute(cli_matches);
        return;
    }

    else if let Some(server_matches) = matches.subcommand_matches("server") {
        println!("[Main] Executing server");
        debug!("Selected SERVER_MODE!");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let _ = rt.block_on(async { server::start(server_matches).await.unwrap() });
    }
}

/// Parse $ verfploeter to start server, client, CLI or help (--help)
fn parse_cmd<'a>() -> ArgMatches<'a> {
    App::new("Verfploeter")
        .version(env!("GIT_HASH"))
        //.author(" Wouter B. de Vries <w.b.devries@utwente.nl> and Leandro Bertholdo <l.m.bertholdo@utwente.nl>")
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("Performs measurements")
        .subcommand(SubCommand::with_name("server").about("Launches the verfploeter server")
            .arg(Arg::with_name("port").short("p").takes_value(true).help("Port to listen on").required(false))
        )
        .subcommand(
            SubCommand::with_name("client").about("Launches the verfploeter client")
                .arg(
                    Arg::with_name("hostname")
                        .short("h")
                        .takes_value(true)
                        .help("hostname for this client")
                        .required(true)
                )
                .arg(
                    Arg::with_name("server")
                        .short("s")
                        .takes_value(true)
                        .help("hostname/ip address:port of the server")
                        .default_value("[::1]:50001")
                )
                .arg(
                    Arg::with_name("source")
                        .short("a")
                        .takes_value(true)
                        .help("Source address for this client's probes")
                        .required(false)
                )
                .arg(
                    Arg::with_name("source_port")
                        .short("p")
                        .takes_value(true)
                        .help("Source port for this client's probes (must be at least 61440)")
                        .required(false)
                )
        )
        .subcommand(
            SubCommand::with_name("cli").about("Verfploeter CLI")
                .arg(
                    Arg::with_name("server")
                        .short("s")
                        .takes_value(true)
                        .help("hostname/ip address:port of the server")
                        .default_value("[::1]:50001")
                )
                .subcommand(SubCommand::with_name("client-list").about("retrieves a list of currently connected clients from the server"))
                .subcommand(SubCommand::with_name("start").about("performs verfploeter on the indicated client")
                    .arg(Arg::with_name("SOURCE_IP").help("The IP to send the pings from")
                        .required(true)
                        .index(1))
                    .arg(Arg::with_name("IP_FILE").help("A file that contains IP addresses to probe")
                        .required(true)
                        .index(2))
                    .arg(Arg::with_name("TYPE").help("The type of task (1: ICMP, 2: UDP/DNS, 3: TCP, 4: UDP/CHAOS)")
                        .required(true)
                        .index(3))
                    .arg(Arg::with_name("RATE").help("The rate at which this task is to be performed at each client (number of probes / second)")
                        .required(false)
                        .index(4)
                        .default_value("1000"))
                    .arg(Arg::with_name("CLIENTS").help("Specify which clients have to send out probes (all connected clients will listen for packets)")
                        .required(false)
                        .index(5)
                        .multiple(true))
                    .arg(Arg::with_name("STREAM").help("Stream results to stdout")
                        .takes_value(false)
                        .long("stream")
                        .required(false))
                    .arg(Arg::with_name("SHUFFLE").help("Randomly shuffle the ip file")
                        .takes_value(false)
                        .long("shuffle")
                        .required(false))
                    .arg(Arg::with_name("LIVE").help("Check results for Anycast targets as they come in live")
                        .takes_value(true)
                        .long("live")
                        .required(false))

                    // TODO option to perform manycast for all 3 protocols on a hitlist
                    // TODO this command would then work with igreedy, but make sure to run igreedy once for each prefix (not 3 times if it is confirmed by all protocols) (i.e. keep a list of anycast targets checked by igreedy)
                    // TODO do we scan the hitlist for each protocol individually (i.e., first scan hitlist with ICMP, then repeat with TCP, then UPD..), or go through the hitlist and probe with all 3 protocols (i.e., probe first target with ICMP, UDP, TCP, iGreedy -> move on to next, etc..)

                )
        )
        .get_matches()
}
