extern crate env_logger;
extern crate byteorder;
#[macro_use]
extern crate log;

use clap::{App, Arg, ArgMatches, SubCommand};

mod cli;
mod server;
mod client;
mod net;


/// VerfPloeter:: main() - Parse command line input and start VerfPloeter server/client or CLI
fn main() {
    // Setup logging with the default environment, with filter at 'info' level
    let env = env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info");
    env_logger::Builder::from_env(env).init();

    // Parse the command line arguments
    let matches = parse_cmd();

    if let Some(client_matches) = matches.subcommand_matches("client") {
        println!("[Main] Executing client");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let _ = rt.block_on(async { client::ClientClass::new(client_matches).await.unwrap() });
        // client.start();

        return;
    }
    // If the cli subcommand was selected, execute the cli module (i.e. the cli::execute function)
    if let Some(cli_matches) = matches.subcommand_matches("cli") {
        println!("[Main] Executing CLI");

        let _ = cli::execute(cli_matches);
        return;
    }

    if let Some(server_matches) = matches.subcommand_matches("server") {
        println!("[Main] Executing server");
        debug!("Selected SERVER_MODE!");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let _ = rt.block_on(async { server::start(server_matches).await.unwrap() });
    }
}

/// Parse $ verfploeter [OPTIONS][SUBCOMANDS]  to start server, client, CLI or help (--help)
fn parse_cmd<'a>() -> ArgMatches<'a> {
    App::new("Verfploeter")
        .version(env!("CARGO_PKG_VERSION"))
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
                        .help("Source address of this client")
                        .required(false)
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
                        .default_value("[::1]:50001")
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
                )
        )
        .get_matches()
}
