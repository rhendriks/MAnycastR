// Provides a macro for initializing a logger from environment variables.
extern crate env_logger;

// A crate for creating bytes used in packets
extern crate byteorder;

// A crate for logging with various levels of verbosity (debug, info, warning, etc.)
#[macro_use]
extern crate log;

// Command line argument parser (clap) for Rust
use clap::{App, Arg, ArgMatches, SubCommand};
use std::thread;
use std::time::Duration;
use crate::client::ClientClass;

mod cli;
mod server;
mod client;
mod net; // TODO not used?


/// VerfPloeter:: main() - Parse command line input and start VerfPloeter server/client or CLI
fn main() {
    // Setup logging with the default environment, with filter at 'info' level
    let env = env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info");
    env_logger::Builder::from_env(env).init();

    // Log a message indicating that the main function has started
    debug!("comecou a bagaca!");

    // Parse the command line arguments
    let matches = parse_cmd();

    if let Some(cli_matches) = matches.subcommand_matches("client") {
        println!("[Main] Executing client");

        // let mut client = client::ClientClass::new(cli_matches).await.unwrap();
        // client.start();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let mut client = rt.block_on(async { client::ClientClass::new(cli_matches).await.unwrap() });
        // client.start();

        return;
    }
    // If the cli subcommand was selected, execute the cli module (i.e. the cli::execute function)
    if let Some(cli_matches) = matches.subcommand_matches("cli") {
        println!("[Main] Executing CLI");
        cli::execute(cli_matches);
        return;
    }

    if let Some(server_matches) = matches.subcommand_matches("server") {
        println!("[Main] Executing server");
        debug!("Selected SERVER_MODE!");
        server::main();
    }
}

/// Parse $ verfploeter [OPTIONS][SUBCOMANDS]  to start server, client, CLI or help (--help)
fn parse_cmd<'a>() -> ArgMatches<'a> { // TODO requires deprecated version of clap
    App::new("Verfploeter")
        .version(env!("CARGO_PKG_VERSION"))
        //.author(" Wouter B. de Vries <w.b.devries@utwente.nl> and Leandro Bertholdo <l.m.bertholdo@utwente.nl>")
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("Performs measurements")
        // .arg(Arg::with_name("prometheus").short("p").long("prometheus").takes_value(true).required(false).help("Enables prometheus metrics"))
        .subcommand(SubCommand::with_name("server").about("Launches the verfploeter server")
            // .arg(Arg::with_name("certificate").short("c").takes_value(true).help("Certificate to use for SSL connection from clients (PEM-encoded file)").required(false))
            // .arg(Arg::with_name("private-key").short("P").takes_value(true).help("Private key to use for SSL connection from clients (PEM-encoded file)").required(false))
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
                        .default_value("127.0.0.1:50001")
                )
            // .arg(Arg::with_name("certificate").short("c").takes_value(true).help("Certificate to use for SSL connection to server (PEM-encoded file)").required(false))
        )
        .subcommand(
            SubCommand::with_name("cli").about("Verfploeter CLI")
                .arg(
                    Arg::with_name("server")
                        .short("s")
                        .takes_value(true)
                        .help("hostname/ip address:port of the server")
                        .default_value("127.0.0.1:50001")
                )
                .subcommand(SubCommand::with_name("client-list").about("retrieves a list of currently connected clients from the server"))
                .subcommand(SubCommand::with_name("start").about("performs verfploeter on the indicated client")
                                .arg(Arg::with_name("CLIENT_HOSTNAME").help("Sets the client to run verfploeter from (i.e. the outbound ping)")
                                    .required(true)
                                    .index(1))
                                .arg(Arg::with_name("SOURCE_IP").help("The IP to send the pings from")
                                    .required(true)
                                    .index(2))
                                .arg(Arg::with_name("IP_FILE").help("A file that contains IP address to ping")
                                    .required(true)
                                    .index(3))
                                .arg(Arg::with_name("stream")
                                    .short("s")
                                    .multiple(false)
                                    .help("Stream results to stdout"))
                            // .arg(Arg::with_name("json")
                            //     .short("j")
                            //     .multiple(false)
                            //     .help("Output results in JSON format"))
                            // .arg(Arg::with_name("ip2country")
                            //     .short("c")
                            //     .takes_value(true)
                            //     .help("Adds a column with IP2Country information. Needs a path to a IP2Country database (MaxMind binary format)"))
                            // .arg(Arg::with_name("ip2asn")
                            //     .short("a")
                            //     .takes_value(true)
                            //     .help("Adds a column with IP2ASN information. Needs a path to a IP2ASN database (MaxMind binary format)"))
                )
        )
        .get_matches()
}
