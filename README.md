# MAnycastR

MAnycastR (Measure Anycast Routing) is a tool designed to measure anycast infrastructure.

This includes:

i) Measuring anycast infrastructure itself
* Mapping catchments using [Verfploeter](https://ant.isi.edu/~johnh/PAPERS/Vries17b.pdf)
* Anycast latency (measuring RTT between the anycast infrastructure and the Internet)
* Optimal deployment (measuring 'best' deployment inferred from unicast latencies from all PoPs)
* Multi-deployment probing (measure multiple anycast prefixes simultaneously)
* [Site flipping](https://doi.org/10.1109/TNSM.2025.3636785) (detecting network regions experiencing anycast site flipping)
* Measuring [anycast routing stability](https://doi.org/10.1007/978-3-031-85960-1_16)
* Measuring [BGP convergence time](https://dl.acm.org/doi/epdf/10.1145/3673422.3674890)

ii) Measuring external anycast infrastructure
* [LACeS](https://doi.org/10.1145/3730567.3764484) (anycast-based detection of anycast and latency-based detection, enumeration, geolocation of anycast using Great-Circle-Distance)

Full documentation is available via [rustdoc](https://rhendriks.github.io/MAnycastR/manycast/index.html).

## The components

Deployment of MAnycastR consists of three components:
* `Orchestrator` - a central controller orchestrating measurements
* `CLI` - Command-line interface scheduling measurements at the orchestrator and collecting results
* `Worker` - Deployed on anycast PoPs, performing measurements

## Measurement process

A measurement is started by running the CLI, which can be executed e.g., locally or automated using a cronjob on a VM.
The CLI sends a measurement definition based on the arguments provided when running the `start` command.
Example commands will be provided in the Usage section.

Upon receiving a measurement definition, the orchestrator instructs the workers to start the measurement.
Workers perform measurements by sending and receiving probes.

Workers stream results to the orchestrator, which aggregates and forwards them to the CLI.
For some measurements, the orchestrator creates follow-up tasks based on the 'catching' PoP for a target.
The CLI writes results to a .csv.gz file (or .parquet).

## Measurement types
Measurements can be;
* `icmp` ICMP ECHO requests
* `dns` UDP DNS A Record requests
* `tcp` TCP SYN/ACK probes
* `chaos` UDP DNS TXT CHAOS requests

## Measurement parameters

When creating a measurement you can specify (for more information run --help):

### Variables
* **Hitlist** (`-h`/`--hitlist`) - path to a file of addresses to be probed (IP-addresses or -numbers seperated by newlines) (supports gzipped files)
* **Target** (`-t`/`--target`) - one or more target addresses given directly on the command line, comma-separated (e.g. `1.1.1.1` or `1.1.1.1,8.8.8.8`). An alternative to `--hitlist` for ad-hoc measurements; exactly one of `--hitlist`/`--target` must be provided.
* **Protocol** - ICMP, DNS, TCP, or CHAOS (multiple allowed)
* **Measurement Type** - `laces`, `catchment`, `unicast`, `latency`, `anycast-traceroute`, or `tracemap`
* **Rate** - the rate (packets / second) at which each worker will send out probes (default: 1000)
* **Selective** - specify which workers have to send out probes (all connected workers will listen for packets)
* **Worker-interval** - interval between separate worker's probes to the same target (default: 1s)
* **Probe-interval** - interval between probes sent by a worker to the same target (default: 1s)
* **nprobes** - number of probes to send to each target (default: 1)
* **Address** - source anycast address to use for the probes
* **Source port** - source port to use for probes (default: 62321)
* **Destination port** - destination port to use for probes (default: DNS: 53, TCP: 63853)
* **Configuration** - path to a configuration file (allowing for complex configurations, e.g., various source address, port values used by different workers)
* **Query** - specify DNS record to request (TXT (CHAOS) default: hostname.bind, A default: example.org)
* **Out** - path to file or directory (ending with '/') to store measurement results (default: ./) (.parquet, .csv, and .csv.gz supported)
* **URL** - encode URL in probes (e.g., for providing opt-out information, explaining the measurement, etc.)

### Flags
* **Stream** - stream results to the command-line interface
* **Shuffle** - shuffle the hitlist
* **Responsive** - check if a target is responsive before probing from all workers
* **Parquet** - store results in .parquet format instead of .csv.gz


## Usage

First, run the central orchestrator.
```
manycastr orchestrator -p [PORT NUMBER]
```

Next, run one or more workers.

To minimize packet loss at high probing rates, increase the kernel receive buffer limit to 32 MB on each worker:
```bash
sudo sysctl -w net.core.rmem_max=33554432
```
To persist across reboots, add `net.core.rmem_max=33554432` to `/etc/sysctl.conf`.

```
manycastr worker -a [ORC ADDRESS]
```
Orchestrator address has format IPv4:port (e.g., 187.0.0.0:50001)

To confirm that the workers are connected, you can run the worker-list command on the CLI.
```
manycastr cli -a [ORC ADDRESS] worker-list
```

Finally, you can perform a measurement.
See [Socket privileges](#socket-privileges) below for what the worker needs in order to send and receive probes.
```
manycastr cli -a [ORC ADDRESS] start [parameters]
```

## Socket privileges

Workers send and receive probes, which requires opening sockets.
How much privilege this needs depends on the protocol.
This section explains the options and the trade-offs, so that operators can make an informed decision about what to grant.

### What each protocol needs

| Protocol | Raw socket required? | Notes |
|----------|----------------------|-------|
| ICMP | No (with a sysctl) — see below | Can use an *unprivileged ICMP socket* if `net.ipv4.ping_group_range` permits, otherwise falls back to a raw socket |
| DNS (UDP) | No | Always uses an unprivileged UDP datagram socket (see below) to avoid ICMP port-unreachable replies |
| CHAOS (UDP) | No | Same as DNS |
| TCP (SYN/ACK) | Yes | Crafting custom TCP SYN/ACK packets requires a raw socket |

The worker prefers raw sockets when available for ICMP and TCP, as used by the standard `ping` utility, because they allow for more accurate RTT measurements and more control over packet contents (e.g., TTL, IP options).
As fall-back we provide `SOCK_DGRAM` for ICMP ping if `SOCK_RAW` lacks permissions.

For DNS measurements we prefer `SOCK_DGRAM` to avoid generating ICMP port-unreachable replies, which would be generated for every DNS reply if a raw socket were used (since the kernel has no UDP listener bound to the source port).

> **Traceroute exception:** UDP/DNS and TCP traceroute (`-m anycast-traceroute -p dns|tcp`) always require a raw socket (`CAP_NET_RAW`), even for DNS, because the worker needs per-probe TTL control and direct access to the checksum / sequence-number fields. See [Anycast traceroute measurement](#anycast-traceroute-measurement).

### Running with a raw socket (CAP_NET_RAW) (recommended/preferable)

We recommend granting `CAP_NET_RAW` to the worker binary, which allows it to open raw sockets without running as root.

```bash
sudo setcap cap_net_raw,cap_net_admin=eip manycastr
```
Or, under systemd, without setuid or root:
```ini
[Service]
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
```

### Running ICMP measurements without a raw socket

If granting `CAP_NET_RAW` is not possible/undesirable,
the worker can still send ICMP echo requests using an unprivileged ICMP socket,
but this requires a one-time configuration change to the kernel's `ping_group_range`.

To enable the unprivileged ICMP path for all groups (one-time, persists across reboots):
```bash
echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee /etc/sysctl.d/99-manycastr.conf
sudo sysctl --system
```

### Examples

#### Catchment mapping

```
manycastr cli -a [::1]:50001 start -m catchment -h hitlist.txt -p icmp -a 10.0.0.0 -o results.csv.gz -r 1000
```

All workers probe the targets in hitlist.txt using ICMPv4, using source address 10.0.0.0, results are stored in results.csv.gz
Each hitlist target receives a single probe from any worker.
Catchment is inferred based on where the ping reply ends up.

Hitlist is divided amongst workers, each worker sends out 1,000 packets per second (-r 1000)

### Anycast latency measurement using TCPv4

```
manycastr cli -a [::1]:50001 start -h hitlist.txt -p tcp -a 10.0.0.0 -m latency
```

Similar as above, except the RTT between each hitlist target and the anycast deployment is also measured.
Each hitlist target receives 2 probes.
The first probe is a `discovery probe` to infer the catching worker for that target (i.e., to which PoP does this target route).
The second probe is a `measurement probe` send from the catching worker to measure the latency (sender == receiver).

Measurement probes respect the per-worker probing rate (`-r`).
If a single worker catches a large share of the targets,
the orchestrator throttles discovery probing so the catching worker can keep up with its measurement probes;
the measurement then takes proportionally longer.

### Unicast latency measurement using ICMPv6

```
manycastr cli -a [::1]:50001 start -h hitlistv6.txt -p icmp -m unicast
```

Unicast probes will be sent from all workers to measure the latency of the target to all PoPs.
Each hitlist target receives a single probe from every worker.
Using the lowest unicast RTT, the 'optimal' PoP for that target can be inferred.
Furthermore, if the target does not currently route optimally, the performance gain can be estimated (subtracting the lowest unicast RTT from the actual anycast RTT).

### LACeS measurement

```
manycastr cli -a [::1]:50001 start -h hitlist.txt -p icmp -m laces --responsive
```

Anycast probes will be sent from all workers.
Each hitlist target receives a single probe from every worker.
Used to e.g., perform [MAnycast2](https://www.sysnet.ucsd.edu/sysnet/miscpapers/manycast2-imc20.pdf) anycast censuses.
Targets are scanned for responsiveness, using a single worker probe, before probing from all workers (`--responsive`).

### Anycast traceroute measurement

```
manycastr cli -a [::1]:50001 start -h hitlist.txt -p icmp -m anycast-traceroute
```

Or, for an ad-hoc trace to one or a few targets, pass them directly with `-t` instead of a hitlist file:
```
manycastr cli -a [::1]:50001 start -t 1.1.1.1 -p icmp -m anycast-traceroute
```

Measure the path from the catching PoP to a target.
First a single `discovery probe` is sent (round-robin across workers) to infer which PoP
"catches" the target. The catching worker then sends `traceroute probes` with an increasing
TTL / hop-limit (from `--trace_initial_hop`, default 4). Each intermediate router returns an
ICMP **Time Exceeded** message quoting the original probe; the hop is recorded and the next TTL
is sent. The trace ends when the **target itself** replies (see below), on a routing loop, or at
`--trace_max_hop`.

Hops that do not respond within `--trace_timeout` are advanced after `--trace_max_failures` consecutive timeouts (up to `--trace_max_hop`).
By default, each unresponsive hop is recorded as a `*` row (no reply);
pass `--trace_star false` to omit these rows and leave a gap in `hop_count` instead.

Traceroute works over all three protocols (`-p icmp`, `-p dns`, `-p tcp`):

```
manycastr cli -a [::1]:50001 start -t 1.1.1.1 -p dns -m anycast-traceroute
manycastr cli -a [::1]:50001 start -t 1.1.1.1 -p tcp -m anycast-traceroute
```

#### Probe type and destination detection

| Protocol | Probe sent | Intermediate-hop reply | "Destination reached" signal |
|----------|-----------|------------------------|------------------------------|
| ICMP | Echo Request | ICMP Time Exceeded | ICMP Echo Reply from the target |
| UDP (DNS) | a valid DNS `A` query to the destination port | ICMP Time Exceeded | DNS answer from the target (open port), or ICMP Destination Unreachable (closed port) |
| TCP | unsolicited TCP SYN-ACK | ICMP Time Exceeded | TCP RST from the target |

#### Paris traceroute (UDP and TCP)

UDP and TCP traceroute are Paris traceroute implementations: the flow 5-tuple
(src IP, dst IP, protocol, sport, dport) is held **constant across all TTL values**, so ECMP
load-balancers forward every probe of a trace along the same path. The per-probe identity
(hop TTL, worker ID, send timestamp) is therefore encoded in header fields that are *not* part
of the flow hash, and recovered from the ICMP Time Exceeded quote (original IP header + first 8
transport bytes):

**NOTE** Multiple origins (with varying port or IP address values) can be used to purposefully (and in a controlled manner)
trigger load-balancers and observe their behavior (e.g., for detecting anycast site flipping).

| Protocol | Identity carried in                                                                                            |
|----------|----------------------------------------------------------------------------------------------------------------|
| ICMP | ICMP identifier + SEQ                                                                                          |
| UDP | UDP checksum (TTL + low worker bits) + IPv4 IP Identification / IPv6 Flow Label (high worker bits + timestamp) |
| TCP | TCP **SEQ** (worker + TTL + timestamp), copied into the **ACK** as well                                        |

* An **intermediate** router's ICMP Time Exceeded is only *guaranteed* to quote the original IP
  header plus the **first 8 bytes** of the transport header (RFC 792). For TCP those 8 bytes are
  the source port, destination port, and **SEQ**, not the **ACK**.
* The **destination** answers with a **RST**, which reflects the ACK field.
  Therefore, we encode the identity in both the SEQ and ACK fields.

> **Middlebox caveat (UDP traceroute):** some middleboxes (NATs, firewalls) rewrite the IPv4 IP
> Identification field or the IPv6 Flow Label. If this happens the 14-bit transmit timestamp and
> the 2 high bits of the worker ID are lost; path discovery still works, but the per-hop RTT
> cannot be computed and worker identification is limited to 256 workers.

#### Sockets and privileges

ICMP traceroute uses a single socket. UDP and TCP traceroute use **two raw sockets** per origin:

* a raw **ICMP** socket to receive Time Exceeded / Destination Unreachable messages, and
* a raw **UDP/TCP** socket to send the probes and receive the target's reply (DNS answer / RST).

Both therefore require a raw socket (`CAP_NET_RAW`) — the unprivileged `SOCK_DGRAM` path used by
normal DNS measurements is not available for traceroute, because we need IP header control.

#### Limitations

* **DNS traceroute** terminates at the destination only if the target answers on the configured
  destination port — a DNS reply on an open port, or an ICMP port-unreachable on a closed one. A
  silent/firewalled target walks to `--trace_max_hop`.
* **TCP traceroute** distinguishes discovery replies from trace replies using a flag bit that
  overlaps the top worker-id bit, so destination detection is reliable for worker IDs below 512.
* **Intermediate-hop RTTs** use a 14-bit millisecond transmit timestamp (it wraps every ~16.4 s);
  this is ample for traceroute RTTs but the value is modular. The ICMP and DNS destination hops
  instead carry a full microsecond timestamp.

### Tracemap measurement

```
manycastr cli -a [::1]:50001 start -h unresponsives.txt -a 10.0.0.1 -p icmp -m tracemap
```

Map the catchment of **unresponsive** targets. Each target is assigned to a random probing PoP,
which sends traceroute probes with the **anycast** source address.
Routers on the path reply with ICMP **Time Exceeded**; routed to the catching PoP for each router
The highest `hop_count` per `trace_dst` is a proxy for the catchment (`rx`) of the unresponsive target itself.

Tracemap **binary-searches** the TTL space for the deepest responding hop,
minimizing traceroute packets.
The first probe is sent at TTL 12 — the empirical median Internet path length (typical IP paths
are 10–20 hops, 95% at most 15) — rather than the midpoint of the search range, since a
responsive probe resolves with a single fast reply while a silent one costs a full confirmation
window of timeouts.
Because paths may contain unresponsive hops before the target, a timed-out TTL is first confirmed by
probing the next `--trace_max_failures` TTLs; only if all stay silent does the search conclude
it exceeded the target and continue in the lower half. Responding hops move the search deeper.

The search runs between `--trace_initial_hop` and `--trace_max_hop`; `--trace_timeout` and
`--trace_max_failures` govern the per-hop timeout and the confirmation window. Output uses the
traceroute format (see below).

Tracemap uses its own statistically-motivated defaults for these options:

| Option                 | tracemap default | anycast-traceroute default | Rationale                                                                                                                                                                            |
|------------------------|------------------|----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--trace_initial_hop`  | 4                | 4                          | The first hops sit inside the probing PoP's own network; their catchment is trivially the prober                                                                                     |
| `--trace_max_hop`      | 25               | 25                         | ≈ mean + 3σ of Internet path lengths (mean ≈ 12.6, σ ≈ 4), covering >99% of paths.                                                                                                   |
| `--trace_max_failures` | 3                | 5                          | Consecutive non-responsive hops are predominantly 1–2 hops, so a window of 3 absorbs them; the linear gap limit of 5 detects end-of-path. For traceroute we favor completeness more. |

Statistics sources:
* **Path-length distribution** (mean ≈ 12.6 hops, σ ≈ 4; median ≈ 12):
  [Begtašević & Van Mieghem, *Measurements of the Hopcount in Internet* (PAM 2001)](http://web.eng.ucsd.edu/~massimo/ECE158A/Handouts_files/hop-count.pdf); (NOTE outdated paper, find new sources)
  live per-vantage-point path-length CCDFs: [CAIDA Ark monitor statistics](https://www.caida.org/projects/ark/statistics/)
## CSV output format

By default, results are written as gzip-compressed CSV files (`.csv.gz`).
Measurement metadata is stored as `#`-prefixed comment lines at the top of the file, followed by a header row and data rows.

### Columns

All values are stored as text. Columns depend on the measurement type:

| Column       | Type               | Description                                                                                                           | Measurement types                   |
|--------------|--------------------|-----------------------------------------------------------------------------------------------------------------------|-------------------------------------|
| `rx`         | `String`           | Hostname of the receiving worker (`*` for unresponsive trace hops — no reply was received)                            | All                                 |
| `addr`       | `String`           | Source IP of the reply, or traceroute hop address (`*` if no reply)                                                   | All                                 |
| `ttl`        | `String (integer)` | TTL of the reply                                                                                                      | All                                 |
| `rtt`        | `String (float)`   | Round-trip time in ms (Latency/Unicast/Traceroute); for LACeS, the signed `rx_time - tx_time` offset in ms (see note) | Latency, Unicast, Traceroute, LACeS |
| `tx`         | `String`           | Hostname of the sending worker                                                                                        | LACeS, Traceroute                   |
| `trace_dst`  | `String`           | Traceroute destination IP address                                                                                     | Traceroute                          |
| `hop_count`  | `String (integer)` | TTL used to trigger this hop reply                                                                                    | Traceroute                          |
| `chaos_data` | `String`           | DNS TXT CHAOS record value                                                                                            | CHAOS                               |
| `origin_id`  | `String (integer)` | Origin ID (multi-origin only)                                                                                         | Multi-origin                        |

### Column order per measurement type

| Measurement type  | Columns (in order)                                                |
|-------------------|-------------------------------------------------------------------|
| Catchment         | `rx`, `addr`, `ttl` [, `chaos_data`] [, `origin_id`]              |
| Latency / Unicast | `rx`, `addr`, `ttl`, `rtt` [, `origin_id`]                        |
| LACeS             | `rx`, `addr`, `ttl`, `tx`, `rtt` [, `chaos_data`] [, `origin_id`] |
| Traceroute        | `rx`, `addr`, `ttl`, `tx`, `trace_dst`, `hop_count`, `rtt`        |

> **LACeS `rtt`**: for LACeS the `rtt` column is not a true round-trip time.
> It is the signed offset `rx_time - tx_time` (milliseconds).
> Under anycast the probe sender (`tx`) and the reply receiver (`rx`) may be **different PoPs**,
> and it can be **negative** when PoP clocks are slightly desynchronized.

### Reading CSV files

#### Python (pandas)

```python
import pandas as pd

df = pd.read_csv("results.csv.gz", comment="#")
```

#### DuckDB

```sql
SELECT * FROM read_csv('results.csv.gz', comment='#');
```

## Parquet output format

When using `--parquet`, results are written as Apache Parquet files with Zstd compression.
Measurement metadata (type, hitlist, probing rate, connected workers, etc.) is stored in the Parquet file's key-value metadata.

### Columns

Columns depend on the measurement type:

| Column | Type | Description | Measurement types |
|--------|------|-------------|-------------------|
| `rx` | `ENUM` | Hostname of the receiving worker (null for unresponsive trace hops — no reply was received) | All |
| `addr` | `FIXED_LEN_BYTE_ARRAY(16)` | Source IP of the reply, or traceroute hop address (see below) | All |
| `ttl` | `UINT8` | TTL of the reply | All |
| `rtt` | `FLOAT` | Round-trip time in ms (Latency/Unicast/Traceroute); for LACeS, the signed `rx_time - tx_time` offset in ms (see note) | Latency, Unicast, Traceroute, LACeS |
| `tx` | `ENUM` | Hostname of the sending worker | LACeS, Traceroute |
| `trace_dst` | `FIXED_LEN_BYTE_ARRAY(16)` | Traceroute destination IP address (see below) | Traceroute |
| `hop_count` | `UINT8` | TTL used to trigger this hop reply | Traceroute |
| `chaos_data` | `STRING` | DNS TXT CHAOS record value | CHAOS |
| `origin_id` | `UINT8` | Origin ID (multi-origin only) | Multi-origin |

> **LACeS `rtt`**: for LACeS the `rtt` column is not a true round-trip time — it is the signed offset `rx_time - tx_time` (milliseconds). Under anycast the probe sender (`tx`) and reply receiver (`rx`) may be **different PoPs**, so this is a one-way delay plus clock offset rather than a round-trip, and can be **negative** when PoP clocks are slightly desynchronised. For TCP the send time is a 21-bit microsecond value, so the value is the 21-bit-wrapped delta (`0`..~`2.097 s`) and is always non-negative.

### IP address encoding

The `addr` column stores IP addresses as 16-byte fixed-length binary using IPv4-mapped-IPv6 format ([RFC 4291 Section 2.5.5.2](https://www.rfc-editor.org/rfc/rfc4291#section-2.5.5.2)):

* **IPv4** `192.0.2.1` is stored as `::ffff:192.0.2.1` (`00 00 00 00 00 00 00 00 00 00 FF FF C0 00 02 01`)
* **IPv6** addresses are stored as-is in 16 bytes big-endian

### Reading Parquet files

#### Python (pyarrow / pandas)

```python
import pandas as pd
import ipaddress

df = pd.read_parquet("results.parquet")

def parse_addr(b: bytes) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse a 16-byte IPv4-mapped-IPv6 address back to an IPv4 or IPv6 address."""
    addr = ipaddress.ip_address(b)
    # Convert IPv4-mapped-IPv6 (::ffff:x.x.x.x) back to IPv4
    if hasattr(addr, 'ipv4_mapped') and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr

df["addr"] = df["addr"].apply(parse_addr)
```

#### DuckDB

```sql
-- Load the parquet file
CREATE TABLE results AS SELECT * FROM read_parquet('results.parquet');

-- IPv4: bytes 13-16 contain the address (1-indexed)
-- Check for IPv4-mapped prefix (bytes 11-12 = 0xFFFF, bytes 1-10 = 0x00)
SELECT
    rx,
    CASE
        WHEN addr[11:12] = '\xFF\xFF'::BLOB AND addr[1:10] = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'::BLOB
        THEN printf('%d.%d.%d.%d',
            get_byte(addr, 12), get_byte(addr, 13),
            get_byte(addr, 14), get_byte(addr, 15))
        ELSE encode(addr)
    END AS ip_address,
    ttl
FROM results;
```

#### Polars

```python
import polars as pl
import ipaddress

df = pl.read_parquet("results.parquet")
df = df.with_columns(
    pl.col("addr").map_elements(
        lambda b: str(ipaddress.ip_address(b).ipv4_mapped or ipaddress.ip_address(b)),
        return_dtype=pl.Utf8,
    ).alias("addr")
)
```

## Installation

### Cargo

---

* Option 1. Download x86_64 musl binary

#### Download
```bash
curl -L -o manycastr https://github.com/rhendriks/MAnycastR/releases/latest/download/manycastr
chmod +x manycastr
```

#### Give permissions for opening raw sockets
```bash
sudo setcap cap_net_raw,cap_net_admin=eip manycastr
```

---

* Option 2. Build locally from source

Requirements:
* rustup
* protobuf-compiler
* gcc
* musl-tools

#### Install Rust via rustup
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

#### Install dependencies
```bash
apt-get install -y protobuf-compiler gcc musl-tools
```

#### Clone repo
```bash
git clone https://github.com/rhendriks/MAnycastR.git
cd MAnycastR
```

#### Build  (recommendation is to build using a statically linked binary target for distribution)
```bash
cargo build --release
```

#### Move binary and set permissions (NOTE: path may differ when built using a specific target)
```bash
target/release/manycastr
sudo setcap cap_net_raw,cap_net_admin=eip manycastr
```

---

Next, distribute the binary to the workers.

### Docker

#### Fetch the Docker image
```bash
docker pull ghcr.io/rhendriks/manycastr:latest
```

Alternatively clone the repo and build yourself.
```bash
docker build -t manycastr .
```

Advise is to run the container with network host mode.
Additionally, the container needs the CAP_NET_RAW and CAP_NET_ADMIN capability to send out packets.
```bash
docker run -it --init --network host --cap-add=NET_RAW --cap-add=NET_ADMIN manycastr
```

## Contributions

Issues and pull requests are welcome


## Citation
MAnycastR as a tool for anycast censuses was developed for the following paper. Please cite this when using MAnycastR to perform anycast censuses.
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
      abstract = {IP anycast replicates an address at multiple locations to reduce latency and enhance resilience. Due to anycast's crucial role in the modern Internet, earlier research introduced tools to perform anycast censuses. The first, iGreedy, uses latency measurements from geographically dispersed locations to map anycast deployments. The second, MAnycast2, uses anycast to perform a census of other anycast networks. MAnycast2's advantage is speed and coverage but suffers from problems with accuracy, while iGreedy is highly accurate but slower using author-defined probing rates and costlier. In this paper we address the shortcomings of both systems and present LACeS (Longitudinal Anycast Census System). Taking MAnycast2 as a basis, we completely redesign its measurement pipeline, and add support for distributed probing, additional protocols (DNS over UDP, TCP SYN/ACK, and IPv6) and latency measurements similar to iGreedy. We validate LACeS on an anycast testbed with 32 globally distributed nodes, compare against an external anycast production deployment, extensive latency measurements with RIPE Atlas and cross-check over 60\% of detected anycast using operator ground truth that shows LACeS achieves high accuracy. Finally, we provide a longitudinal analysis of anycast, covering 17+months, showing LACeS achieves high precision. We make continual daily LACeS censuses available to the community and release the source code of the tool under a permissive open source license.},
      booktitle = {Proceedings of the 2025 ACM Internet Measurement Conference},
      pages = {445–461},
      numpages = {17},
      keywords = {internet measurement, anycast, internet topology, routing, ip},
      location = {USA},
      series = {IMC '25}
}
```
* Use `-m unicast` to perform GCD measurements (for iGreedy).
* Use `-m laces` to perform anycast-based measurements (similar to [MAnycast2](https://www.sysnet.ucsd.edu/sysnet/miscpapers/manycast2-imc20.pdf)).
---
MAnycastR as a tool for detecting networks experiencing anycast site flipping was used for the following paper. Please cite this when using MAnycastR to detect anycast site flipping.
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
* Use `--config` configuration-based probing to send probes with varied flow header fields (thus triggering load-balancers).
* Use `-m anycast-traceroute` to perform anycast Paris traceroute measurements to determine where load-balancers (causing anycast site flipping) reside
