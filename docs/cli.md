# Command-Line Help for `manycastr`

This document contains the help content for the `manycastr` command-line program.

**Command Overview:**

* [`manycastr`↴](#manycastr)
* [`manycastr orchestrator`↴](#manycastr-orchestrator)
* [`manycastr worker`↴](#manycastr-worker)
* [`manycastr cli`↴](#manycastr-cli)
* [`manycastr cli worker-list`↴](#manycastr-cli-worker-list)
* [`manycastr cli start`↴](#manycastr-cli-start)

## `manycastr`

Performs synchronized Internet measurement from a distributed set of anycast Points of Presence (PoPs)

**Usage:** `manycastr <COMMAND>`

###### **Subcommands:**

* `orchestrator` — Launches the MAnycastR orchestrator
* `worker` — Launches the MAnycastR worker
* `cli` — MAnycastR CLI



## `manycastr orchestrator`

Launches the MAnycastR orchestrator

**Usage:** `manycastr orchestrator [OPTIONS]`

###### **Options:**

* `-p`, `--port <PORT>` — Port to listen on

  Default value: `50001`
* `--cli_port <PORT>` — Port for CLI (default: CLI shares the --port listener)
* `--tls <CERT>` — Enable TLS with the certificate at the given path (e.g., ./tls/orchestrator.crt)
* `--tls_key <KEY>` — Path to the TLS private key (default: the --tls path with a .key extension)
* `-c`, `--config <FILE>` — Worker hostname to IDs configuration
* `--max_rate <RATE>` — Maximum probing rate allowed for measurements (probes per second, per worker; optional)
* `--origins <FILE>` — Origin allow-list restricting the origins CLIs may use ('src_addr, protocol[, protocol...]' per line; 'all' allows all protocols)



## `manycastr worker`

Launches the MAnycastR worker

**Usage:** `manycastr worker [OPTIONS] --orchestrator <ADDR>`

###### **Options:**

* `-a`, `--orchestrator <ADDR>` — address:port of the orchestrator (e.g., 10.0.0.0:50001, [::1]:50001, or orchestrator.example.net:50001)
* `-n`, `--hostname <NAME>` — hostname for this worker (default: $HOSTNAME)
* `--tls <CERT>` — Enable TLS, authenticating the orchestrator against the certificate at the given path (its own certificate, or the CA that issued it)
* `--tls_system` — Enable TLS, authenticating the orchestrator against the host's system trust store
* `--tls_domain <NAME>` — Name to authenticate the orchestrator as (default: the host in -a)



## `manycastr cli`

MAnycastR CLI

**Usage:** `manycastr cli [OPTIONS] --orchestrator <ADDR> [COMMAND]`

###### **Subcommands:**

* `worker-list` — retrieves a list of currently connected workers from the orchestrator
* `start` — performs a hitlist-based measurement

###### **Options:**

* `-a`, `--orchestrator <ADDR>` — address:port of the orchestrator (e.g., 10.0.0.0:50001, [::1]:50001, or orchestrator.example.net:50001)
* `--tls <CERT>` — Enable TLS, authenticating the orchestrator against the certificate at the given path (its own certificate, or the CA that issued it)
* `--tls_system` — Enable TLS, authenticating the orchestrator against the host's system trust store
* `--tls_domain <NAME>` — Name to authenticate the orchestrator as (default: the host in -a)



## `manycastr cli worker-list`

retrieves a list of currently connected workers from the orchestrator

**Usage:** `manycastr cli worker-list`



## `manycastr cli start`

performs a hitlist-based measurement

**Usage:** `manycastr cli start [OPTIONS]`

###### **Options:**

* `--hitlist <PATH>` — Path to the hitlist file (can be .gz or .bz2 compressed; ISI fsdb hitlists are detected automatically)
* `-t`, `--target <TARGETS>` — Comma-separated target address(es), e.g. '1.1.1.1' or '1.1.1.1,8.8.8.8' (alternative to --hitlist)
* `-p`, `--p_type <TYPE>` — Protocols to use

  Default value: `icmp`

  Possible values: `icmp`, `dns`, `tcp`, `chaos`

* `-m`, `--m_type <MODE>` — Measurement type to perform

  Default value: `laces`

  Possible values: `laces`, `catchment`, `latency`, `anycast-traceroute`, `tracemap`, `feed`, `feed-trace`

* `-a`, `--address <ADDR>` — Anycast source address, or 'unicastv4'/'unicastv6' to probe from each worker's local unicast address
* `-f`, `--configuration <CONF>` — Path to config file
* `-r`, `--rate <RATE>` — Probing rate at each worker (packets per second)

  Default value: `1000`
* `-x`, `--selective <IDS>` — List of worker IDs/hostnames that send probes [worker_id1,worker_id2,...]
* `-o`, `--out <PATH>` — Optional path/filename to write output

  Default value: `./`
* `--parquet` — Write as .parquet (instead of .csv.gz)
* `--stream` — Stream to stdout
* `--shuffle` — Shuffle hitlist
* `--responsive` — Check responsiveness of targets for multi-target hitlists and multi-probe measurements.
* `--sessions` — Enable feed sessions (-m feed only): NDJSON targets may carry a 'session' field (1-65535), reported per reply in the output's 'session' column
* `--trace_max_failures <N>` — Maximum number of consecutive failures (tracemap: confirmation window past a silent midpoint, default 3)

  Default value: `5`
* `--trace_timeout <N>` — Timeout for hops (in seconds)

  Default value: `3`
* `--trace_max_hop <N>` — Maximum TTL value (covers >99% of Internet path lengths)

  Default value: `25`
* `--trace_initial_hop <N>` — Starting TTL value (skips hops within the PoP's own network)

  Default value: `4`
* `--trace_star <BOOL>` — Emit a '*' hop to the output for unresponsive (timed-out) hops

  Default value: `true`

  Possible values: `true`, `false`

* `-w`, `--worker_interval <N>` — Interval between workers for probes to the same target

  Default value: `1`
* `-i`, `--probe_interval <N>` — Interval between probes from the same worker to the same target

  Default value: `1`
* `-c`, `--nprobes <N>` — Number of probes to send for each origin,target pair [NOTE: violates probing rate]

  Default value: `1`
* `-s`, `--sport <PORT>` — Source port to use (DNS,UDP)

  Default value: `62321`
* `-d`, `--dport <PORT>` — Destination port to use (default DNS/CHAOS: 53, TCP: 63853)

  Default value: `63853`
* `-q`, `--query <QUERY>` — Specify DNS record to request (TXT (CHAOS) default: hostname.bind, A default: example.org)
* `-u`, `--url <URL>` — URL encoded in probe payload (e.g., opt-out URL)



<hr/>

<small><i>
    This document was generated automatically by
    <a href="https://crates.io/crates/clap-markdown"><code>clap-markdown</code></a>.
</i></small>
