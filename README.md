# MAnycastR

MAnycastR (Measure Anycast Routing) performs synchronized Internet measurements from a distributed
set of anycast Points of Presence (PoPs).

**Measuring your own anycast infrastructure**
* Mapping catchments using an improved version of [Verfploeter](https://ant.isi.edu/~johnh/PAPERS/Vries17b.pdf)
* Anycast latency (RTT between the anycast infrastructure and the Internet)
* Optimal deployment ('best' deployment inferred from unicast latencies from all PoPs)
* Multi-deployment probing (measure multiple anycast prefixes simultaneously)
* [Site flipping](https://doi.org/10.1109/TNSM.2025.3636785) (network regions experiencing anycast site flipping)
* [Anycast routing stability](https://doi.org/10.1007/978-3-031-85960-1_16) and [BGP convergence time](https://dl.acm.org/doi/epdf/10.1145/3673422.3674890)

**Measuring external anycast infrastructure**
* [LACeS](https://doi.org/10.1145/3730567.3764484) — anycast-based detection of anycast, and latency-based detection using Great-Circle-Distance.

IPv4 and IPv6 are both supported, over ICMP, UDP (DNS), and TCP (can be mixed within a single measurement).

This README is the manual for installing and running MAnycastR.
Documentation of the code itself is available via [rustdoc](https://rhendriks.github.io/MAnycastR/manycastr/index.html).

## Contents

* [Installation](#installation)
* [Quick start](#quick-start)
* [How it works](#how-it-works)
* [Measurement types](#measurement-types)
* [Targets and hitlists](#targets-and-hitlists)
* [Configuration files](#configuration-files)
* [Output formats](#output-formats)
* [Running a shared deployment](#running-a-shared-deployment)
* [Options reference](#options-reference)
* [Contributing](#contributing)
* [Citation](#citation)

Further documentation lives in [docs/](docs):
[deployment](docs/deployment.md) ·
[output formats](docs/output.md) ·
[traceroute internals](docs/traceroute.md) ·
[generated CLI reference](docs/cli.md)

## Installation

All three components are subcommands of a single `manycastr` binary.

### Download a binary

```bash
curl -L -o manycastr https://github.com/rhendriks/MAnycastR/releases/latest/download/manycastr
chmod +x manycastr
sudo setcap cap_net_raw+ep manycastr
```

### Docker

```bash
docker pull ghcr.io/rhendriks/manycastr:latest
```

Run with `--network host`, so probes use the anycast/unicast addresses of the host:

```bash
docker run -it --init --network host --cap-drop=ALL --cap-add=NET_RAW --read-only manycastr
```

### Build from source

Requires rustup, protobuf-compiler, gcc, and musl-tools.
Building against a musl target produces a statically linked binary (recommended for distribution to Workers).

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source $HOME/.cargo/env
apt-get install -y protobuf-compiler gcc musl-tools
git clone https://github.com/rhendriks/MAnycastR.git && cd MAnycastR
cargo build --release
sudo setcap cap_net_raw+ep target/release/manycastr
```

### Socket privileges

Workers send and receive probes over **raw sockets** (`SOCK_RAW`),
which require the `CAP_NET_RAW` capability (or sudo).
For reference, the standard `ping` utility also has `CAP_NET_RAW` capabilities.
The orchestrator and CLI run unprivileged and require no capabilities.

A raw socket is required as MAnycastR is an anycast measurement tool:
replies to probes sent by one Worker may be received by *another* Worker.
Permissionless sockets such as `SOCK_DGRAM` would drop such replies.

> **DNS NOTE:** the kernel answers DNS replies with ICMP *port-unreachable*
> as raw sockets do not register a UDP listener on the source port.

Grant the capability as a file capability (`setcap`, above), under systemd, or in Docker:

```ini
[Service]
User=manycastr
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
```

```bash
docker run --cap-drop=ALL --cap-add=NET_RAW --read-only --network host manycastr worker ...
```

If raw-socket privileges are a concern, bound the process further with nftables/tc egress policies and rate-limits.

## Quick start

**1. Start the Orchestrator** (Workers and CLIs share `--port` by default):

```bash
manycastr orchestrator -p 50001
```

**2. Start one or more workers.** The orchestrator address is `address:port`, where the address may
be IPv4, IPv6, or a hostname (resolved at connect time):

```bash
manycastr worker -a 10.0.0.0:50001
manycastr worker -a [2001::1]:50001
manycastr worker -a orchestrator.example.net:50001
```

**3. Confirm the workers are connected:**

```bash
manycastr cli -a [::1]:50001 worker-list
```

**4. Run a measurement:**

```bash
manycastr cli -a [::1]:50001 start -m catchment --hitlist hitlist.txt -p icmp -a 10.0.0.0 -r 1000
```

All Workers probe the targets in `hitlist.txt` over ICMPv4 from source address 10.0.0.0,
at 1,000 packets per second per Worker.
The hitlist is divided amongst the Workers, each target receiving a single probe;
catchment is inferred from which PoP receives the reply.
Results are written to a timestamped `.csv.gz` file in the working directory (see [Output formats](#output-formats)).

## How it works

A deployment consists of three components:

| Component        | Role                                                            |
|------------------|-----------------------------------------------------------------|
| **Orchestrator** | Central controller orchestrating measurements                   |
| **CLI**          | Schedules measurements at the orchestrator and collects results |
| **Worker**       | Deployed on anycast PoPs, sends and receives probes             |

The CLI sends a measurement definition built from the arguments of its `start` command.
The orchestrator instructs the workers to begin, and the workers stream results back to it.
The orchestrator aggregates them (and may create follow-up tasks for some measurement types)
and forwards them to the CLI, which writes the output file.

Probes can be sent as ICMP ECHO requests (`-p icmp`), UDP DNS A record requests (`-p dns`),
TCP SYN/ACK probes (`-p tcp`), or UDP DNS TXT CHAOS requests (`-p chaos`).

## Measurement types

Selected with `-m`.

### catchment

```bash
manycastr cli -a [::1]:50001 start -m catchment --hitlist hitlist.txt -p icmp -a 10.0.0.0
```

Simple catchment mapping to see which PoP catches each target.
The hitlist is divided amongst the workers (round-robin),
so each target receives a single probe,
and the receiving PoP is its catchment.

### laces

```bash
manycastr cli -a [::1]:50001 start -m laces --hitlist hitlist.txt -p icmp -a 10.0.0.0 --responsive
```

Every worker probes every target, so a target is probed once per worker.
Used to perform anycast censuses, with an extended version of [MAnycast2](https://www.sysnet.ucsd.edu/sysnet/miscpapers/manycast2-imc20.pdf):
a target whose replies end are received at several Worker PoPs is inferred to be anycast.
With `--responsive`, targets are first probed from a single Worker to confirm probe responsiveness
before being probed from all workers

### latency

Anycast latency measures the RTT between each target and the anycast deployment:

```bash
manycastr cli -a [::1]:50001 start -m latency --hitlist hitlist.txt -p tcp -a 10.0.0.0
```

Each target receives two probes: a `discovery probe` establishing which PoP catches it,
then a `measurement probe` from that catching worker, so that sender and receiver are the same PoP.
Measurement probes respect the per-worker probing rate (`-r`).
This means that the measurement time is non-deterministic as they are distributed based on the catchment distribution.
The measurement will finish when the Worker with the largest catchment share finishes sending its `measurement probes`.

Unicast latency instead measures each target's RTT from *every* PoP:

```bash
manycastr cli -a [::1]:50001 start -m latency --hitlist hitlistv6.txt -p icmp -a unicastv6 --responsive
```

`-a unicastv4`/`-a unicastv6` creates an origin where each worker probes
from its own local unicast address of that IP version.
Every Worker probes every target (like `-m laces`) which can also be combined with --responsive
to avoid unnecessary probes for probe unresponsive targets.
This allows for anycast-detection using Great-Circle-distance
and for inferring 'optimal' routing.
We identify the Worker with the lowest unicast RTT as 'optimal'
which can be used to identify catchment/latency improvements when
compared against the catchment/latency experienced by the target using anycast.

### anycast-traceroute

```bash
manycastr cli -a [::1]:50001 start -m anycast-traceroute --hitlist hitlist.txt -p icmp
manycastr cli -a [::1]:50001 start -m anycast-traceroute -t 1.1.1.1 -p dns
```

Measures the path from the catching PoP to a target.

Uses `discovery probes` (like Anycast latency) to establish the catching PoP,
which then sends `traceroute probes` to measure the path.
Each intermediate router returns an ICMP **Time Exceeded** towards the anycast IP address
which may return at different PoPs.
This allows for troubleshooting targets reaching a distant anycast PoP
and catchment mapping of networks that e.g., do not respond to ping but send ICMP Time Exceeded replies.

Traceroute works over ICMP, DNS, and TCP using Paris traceroute.
When using multi-origin configurations (e.g., multiple protocols, or different port/src address combinations)
multi-paths can be measured to e.g., assess anycast routing differences amongst protocols.

See [docs/traceroute.md](docs/traceroute.md) for a more detailed description.

### tracemap

```bash
manycastr cli -a [::1]:50001 start -m tracemap --hitlist unresponsives.txt -a 10.0.0.1 -p icmp
```

Experimental feature to map the catchment of probe unresponsive targets
by soliciting an ICMP Time Exceeded reply from routers near the target.
This method uses a binary-search implementation to find a hop near to the target
whilst sending as little traceroute probes as possible.

### feed — live measurements

```bash
manycastr cli -a [::1]:50001 start -m feed -p icmp -a 10.0.0.0
```

Allows for feeding targets over stdin as NDJSON (or bare addresses).

```
{"dst":"192.0.2.1"}
{"dst":"203.0.113.7","worker":"ams01"}
{"dst":"198.51.100.9","origin":2,"worker":"all"}
192.0.2.1
```

| Field     | Values                                                                                                        | Default                                 |
|-----------|---------------------------------------------------------------------------------------------------------------|-----------------------------------------|
| `dst`     | target address                                                                                                | required                                |
| `worker`  | `"any"` (round-robin), a worker ID (`1`) or hostname (`"ams01"`), a hostname glob (`"us-*"`), or `"all"`      | `"any"`                                 |
| `origin`  | an origin ID (`2`), or `"all"`                                                                                | first origin of the target's IP version |
| `nprobes` | measurement probes to send per selected worker (1–255)                                                        | 1                                       |
| `session` | session ID for attribution with shared CLI set-ups (e.g., multiple web-interfaces connecting to the same CLI) | none                                    |

Adding `--responsive` gates tasks involving multiple probes to a discovery probe first.

Use cases include reactive measurements.
For instance, to measure the catchment and latency of a target after observing a routing change in BGP.
Or to verify the catchment of a target when receiving potentially spoofed traffic.

```bash
bgp-monitor | manycastr cli -a [::1]:50001 start -m feed -p icmp -a 10.0.0.0
```

Notes:
* Results are written as LACeS rows (`rx`, `addr`, `ttl`, `tx`, `rtt`), plus `session` with `--sessions`.
* Session attribution is supported only for ICMP.
* Origins must be shared among all workers (live mode does not support worker-specific origins).

### feed-trace — live traceroute

```bash
manycastr cli -a [::1]:50001 start -m feed-trace -p icmp -a 10.0.0.0
```

Similar to `-m feed` except it adds TTL level control to the user using an additional `ttl` field (default 255).
This is added a separate measurement type as it requires Workers to also listen for ICMP **Time Exceeded** replies
which increases resource usage as there are no measurement hashes encoded in such replies for easy filtering.

```
{"dst":"192.0.2.1","ttl":4}
{"dst":"192.0.2.1","ttl":5}
```

Notes:
* Results are written as traceroute rows, with `probe_ttl` recording the TTL each probe was sent with.
* Unrelated ICMP Time Exceeded are filtered by the orchestrator that tracks ongoing tasks.

## Targets and hitlists

Targets come either from a file (`--hitlist`, one IP address or number per line, optionally gzip- or
bzip2-compressed) or directly on the command line (`-t 1.1.1.1,8.8.8.8`) for ad-hoc measurements.
Exactly one of the two must be given.

### USC/ISI ANT hitlists

[USC/ISI ANT hitlists](https://ant.isi.edu/datasets/ip_hitlists/) are created specifically for catchment mappings:
they list one to several addresses per /24 prefix, ranked by ping responsiveness over time.
MAnycastR detects and parses them automatically.

Default behavior is to probe every target address (i.e. multiple targets per /24).
Combined with `--responsive`, candidates are instead tried in rank order until one replies,
so at most one responsive target per prefix is measured - 
maximizing coverage at prefix granularity while keeping probing costs low.

```bash
manycastr cli -a [::1]:50001 start -m latency --hitlist isi-hitlist.fsdb.bz2 -p icmp -a 10.0.0.0 --responsive
```

### fsdb format

We use the [USC/ISI ANT](https://ant.isi.edu/datasets/ip_hitlists/) format, extended for IPv6.

IPv4 — candidates are last-octets in hex:
```text
#fsdb -F t block octets
01000400	01,04,09
01000500	01
01001100	-
```
Row 1 lists 1.0.4.1, 1.0.4.4, and 1.0.4.9 (in rank order) for 1.0.4.0/24;
row 2 lists 1.0.5.1 for 1.0.5.0/24.

IPv6 — candidates are hex suffixes within the 80 host bits of the /48 (no colons, no leading zeros needed):
```text
#fsdb -F t block suffixes
20010db80001	1
20010db81234	1,2a3f,ec4a01
```
Row 1 lists 2001:db8:1::1 for 2001:db8:1::/48;
row 2 lists 2001:db8:1234::1, 2001:db8:1234::2a3f, and 2001:db8:1234::ec4a01 for 2001:db8:1234::/48.

## Configuration files

An *origin* is a combination of source address, ports, and protocol.
Simple measurements define one via `-a`, `-s`, `-d`, and `-p`;
a configuration file (`-f`) defines several, and may vary them per worker:

```text
# Worker, src_addr, src_port, dst_port, protocol
ALL, 10.0.0.0, 62321, 63853, icmp
ALL, unicastv4, 62321, 63853, icmp
```

The worker field is `ALL`, a worker ID, a hostname, or a hostname glob (`us-*`);
workers listen for every anycast origin defined, regardless of which they probe with.
See [example.conf](example.conf) for the full syntax.
Replies are tagged with an `origin_id` column identifying the origin that produced them.

Multi-origin probing allows for measuring two anycast prefixes side-by-side (e.g., a control and test prefix)
to e.g., compare routing differences.
One use-case could be to measure the impact of a site outage,
or a Traffic Engineering policy (e.g., a community or prepend).

### Multi-protocol probing

```bash
manycastr cli -a [::1]:50001 start -m catchment --hitlist hitlist.txt -p icmp,tcp,dns -a 10.0.0.0
```

Each protocol given to `-p` becomes its own origin, and every target is probed with all of them.
This measures whether targets route to a different PoP depending on the protocol used.

This feature also enables for measuring routing differences when varying the protocol
(e.g., when networks route TCP/UDP differently than ICMP).

### Multi-flow probing
Multiple origins can be defined with varied port values or anycast source addresses.
This enables measuring routing differences when varying the flow-header of packets
(e.g., when hash based load-balancers may cause packets to reach different PoPs).

### Mixed anycast and unicast

Configurations can mix anycast and unicast source addresses.
With `-m laces` this allows for measuring the anycast catchment/latency and per-PoP unicast latencies in a single run.

### Mixed IPv4/IPv6

A configuration file can declare IPv4 and IPv6 origins side by side.
Hitlist can also mix IPv4 and IPv6 targets.
Targets are only probed by the origin matching its IP version.

```text
# Worker, src_addr, src_port, dst_port, protocol
ALL, 10.0.0.0, 62321, 63853, icmp
ALL, 2001:db8::1, 62321, 63853, icmp
ALL, unicastv4, 62321, 63853, icmp
ALL, unicastv6, 62321, 63853, icmp
```

```bash
manycastr cli -a [::1]:50001 start -m catchment --hitlist mixed_hitlist.txt -f mixed.conf
```

This allows for measuring the IP version differences for dual-stack anycast deployments.
E.g., to compare how resolvers reach your authoritative nameserver using both IPv4 and IPv6.

## Output formats

Results are written to the path given by `-o` as gzip-compressed CSV (`.csv.gz`) by default,
or as parquet with `--parquet`.
Which columns are present depends on the measurement type.

See **[docs/output.md](docs/output.md)** for the full column reference, the Parquet file metadata
and IP address encoding, and snippets for reading results with pandas and DuckDB.

## Running a shared deployment

For infrastructure shared between users, the orchestrator can cap the probing rate (`--max_rate`)
and restrict the origins a CLI may use (`--origins`).
This can be used to provide CLI access to external parties.
We run such a set-up using TANGLED, please contact me if you are interested in running measurements.

For security considerations we support
CLI and worker connections on separate ports (`--cli_port`).
The inter-component gRPC connections also support TLS (`--tls`, `--tls_system`).

See **[docs/deployment.md](docs/deployment.md)** for configuring these, generating certificates,
using an internal CA, and keeping workers connected across restarts.

## Options reference

Also available as `manycastr <orchestrator|worker|cli> --help` and `manycastr cli start --help`, or
as the generated full reference in [docs/cli.md](docs/cli.md).

### `manycastr orchestrator`

| Option                  | Default                  | Description                                                            |
|-------------------------|--------------------------|------------------------------------------------------------------------|
| `-p`, `--port <PORT>`   | `50001`                  | Port to listen on                                                      |
| `--cli_port <PORT>`     | shares `--port`          | Separate port for CLI connections                                      |
| `-c`, `--config <FILE>` |                          | Static worker hostname to ID mapping (see [example.map](example.map))  |
| `--max_rate <RATE>`     | unlimited                | Maximum probing rate allowed for measurements (per second, per worker) |
| `--origins <FILE>`      | all allowed              | Origin allow-list restricting the origins CLIs may use                 |
| `--tls <CERT>`          | off                      | Enable TLS with the certificate at this path                           |
| `--tls_key <KEY>`       | `--tls` path with `.key` | Path to the TLS private key                                            |

### `manycastr worker` and `manycastr cli`

| Option                        | Default      | Description                                                          |
|-------------------------------|--------------|----------------------------------------------------------------------|
| `-a`, `--orchestrator <ADDR>` | required     | `address:port` of the orchestrator                                   |
| `-n`, `--hostname <NAME>`     | `$HOSTNAME`  | Hostname for this worker (worker only)                               |
| `--tls <CERT>`                | off          | Enable TLS, authenticating the orchestrator against this certificate |
| `--tls_system`                | off          | Enable TLS, authenticating against the host's system trust store     |
| `--tls_domain <NAME>`         | host in `-a` | Name to authenticate the orchestrator as                             |

The CLI takes a subcommand: `worker-list` (list connected workers) or `start` (run a measurement).

### `manycastr cli start`

**Targets and origins**

| Option                         | Default                                    | Description                                                              |
|--------------------------------|--------------------------------------------|--------------------------------------------------------------------------|
| `--hitlist <PATH>`             |                                            | Hitlist file (`.gz`/`.bz2` supported; ISI fsdb detected automatically)   |
| `-t`, `--target <TARGETS>`     |                                            | Comma-separated target address(es), instead of `--hitlist`               |
| `-a`, `--address <ADDR>`       | required                                   | Anycast source address, or `unicastv4`/`unicastv6`                       |
| `-p`, `--p_type <TYPE>`        | `icmp`                                     | Protocol(s): `icmp`, `dns`, `tcp`, `chaos` (comma-separated for several) |
| `-f`, `--configuration <CONF>` |                                            | Config file defining origins; conflicts with `-a`, `-s`, `-d`, `-p`      |
| `-s`, `--sport <PORT>`         | `62321`                                    | Source port (DNS, TCP)                                                   |
| `-d`, `--dport <PORT>`         | `63853`; `53` for `dns`/`chaos`            | Destination port                                                         |
| `-q`, `--query <QUERY>`        | `example.org`; `hostname.bind` for `chaos` | DNS record to request                                                    |
| `-u`, `--url <URL>`            |                                            | URL encoded in the probe payload (e.g. opt-out information)              |

**Measurement**

| Option                        | Default                              | Description                                                                                                                          |
|-------------------------------|--------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `-m`, `--m_type <MODE>`       | `laces`                              | `laces`, `catchment`, `latency`, `anycast-traceroute`, `tracemap`, `feed`, `feed-trace`                                              |
| `-r`, `--rate <RATE>`         | `1000`; `10` for traceroute/tracemap | Probing rate per worker (packets per second)                                                                                         |
| `-x`, `--selective <IDS>`     | all workers                          | Workers that send probes, as IDs, hostnames, or globs (`us-*`); all workers still listen                                             |
| `-w`, `--worker_interval <N>` | `1`                                  | Seconds between different workers' probes to the same target                                                                         |
| `-i`, `--probe_interval <N>`  | `1`                                  | Seconds between probes from one worker to the same target                                                                            |
| `-c`, `--nprobes <N>`         | `1`                                  | Probes per origin,target pair (not counted against the probing rate)                                                                 |
| `--responsive`                | off                                  | Screen targets for responsiveness before probing from all workers; with ISI hitlists, try candidates in rank order until one replies |
| `--shuffle`                   | off                                  | Shuffle the hitlist                                                                                                                  |
| `--sessions`                  | off                                  | Enable feed sessions (`-m feed` only): report a per-reply `session` column                                                           |

**Traceroute** (`anycast-traceroute`, `tracemap`, `feed-trace`)

| Option                     | Default               | Description                                                                                  |
|----------------------------|-----------------------|----------------------------------------------------------------------------------------------|
| `--trace_initial_hop <N>`  | `4`                   | Starting TTL (skips hops within the PoP's own network)                                       |
| `--trace_max_hop <N>`      | `25`                  | Maximum TTL (covers >99% of Internet path lengths)                                           |
| `--trace_timeout <N>`      | `3`                   | Per-hop timeout in seconds                                                                   |
| `--trace_max_failures <N>` | `5`; `3` for tracemap | Consecutive failures before advancing (tracemap: confirmation window past a silent midpoint) |
| `--trace_star <BOOL>`      | `true`                | Emit a `*` row for unresponsive hops                                                         |

**Output**

| Option               | Default | Description                                                       |
|----------------------|---------|-------------------------------------------------------------------|
| `-o`, `--out <PATH>` | `./`    | Output file, or directory (trailing `/`) for a generated filename |
| `--parquet`          | off     | Write `.parquet` instead of `.csv.gz`                             |
| `--stream`           | off     | Stream results to stdout                                          |

## Contributing

Issues and pull requests are welcome.

## Citation

MAnycastR as a tool for anycast censuses was developed for the following paper.
Please cite it when using MAnycastR to perform anycast censuses — `-m laces`.

```
@inproceedings{10.1145/3730567.3764484,
      author = {Hendriks, Remi and Luckie, Matthew and Jonker, Mattijs and Sommese, Raffaele and van Rijswijk-Deij, Roland},
      title = {LACeS: An Open, Fast, Responsible and Efficient Longitudinal Anycast Census System},
      year = {2025},
      isbn = {9798400718601},
      publisher = {Association for Computing Machinery},
      address = {New York, NY, USA},
      url = {https://doi.org/10.1145/3730567.3764484},
      doi = {10.1145/3730567.3764484},
      booktitle = {Proceedings of the 2025 ACM Internet Measurement Conference},
      pages = {445–461},
      numpages = {17},
      keywords = {internet measurement, anycast, internet topology, routing, ip},
      location = {USA},
      series = {IMC '25}
}
```

MAnycastR as a tool for detecting networks experiencing anycast site flipping was used for the following paper.
Please cite it when using MAnycastR to detect anycast site flipping.

```
@ARTICLE{11268317,
      author={Hendriks, Remi and Jonker, Mattijs and van Rijswijk-Deij, Roland and Sommese, Raffaele},
      journal={IEEE Transactions on Network and Service Management},
      title={Load-Balancing Versus Anycast: A First Look at Operational Challenges},
      year={2025},
      volume={},
      number={},
      pages={1-1},
      keywords={Routing;Internet;Routing protocols;Probes;IP networks;Costs;Tunneling;Time measurement;Source address validation;Servers;Anycast;Load Balancing;Routing Stability},
      doi={10.1109/TNSM.2025.3636785}
}
```

We are currently working on a paper describing MAnycastR as a tool itself.
For now, we kindly ask you to cite the LACeS paper (first listed) when using MAnycastR for non-listed goals.
