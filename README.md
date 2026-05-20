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
* **Hitlist** - addresses to be probed (IP-addresses or -numbers seperated by newlines) (supports gzipped files)
* **Protocol** - ICMP, DNS, TCP, or CHAOS (multiple allowed)
* **Measurement Type** - `laces`, `catchment`, `unicast`, `latency`, or `anycast-traceroute`
* **Rate** - the rate (packets / second) at which each worker will send out probes (default: 1000)
* **Selective** - specify which workers have to send out probes (all connected workers will listen for packets)
* **Worker-interval** - interval between separate worker's probes to the same target (default: 1s)
* **Probe-interval** - interval between probes sent by a worker to the same target (default: 1s)
* **nprobes** - number of probes to send to each target (default: 1)
* **Address** - source anycast address to use for the probes
* **Source port** - source port to use for probes (default: 62321)
* **Destination port** - destination port to use for probes (default: DNS: 53, TCP: 63853)
* **Configuration** - path to a configuration file (allowing for complex configurations, e.g., various source address, port values used by different workers)
* **Query** - specify DNS record to request (TXT (CHAOS) default: hostname.bind, A default: google.com)
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
orchestrator -p [PORT NUMBER]
```

Next, run one or more workers.
```
worker -a [ORC ADDRESS]
```
Orchestrator address has format IPv4:port (e.g., 187.0.0.0:50001)

To confirm that the workers are connected, you can run the worker-list command on the CLI.
```
cli -a [ORC ADDRESS] worker-list
```

Finally, you can perform a measurement.
```
cli -a [ORC ADDRESS] start [parameters]
```

### Examples

#### Catchment mapping

```
cli -a [::1]:50001 start -m catchment -h hitlist.txt -t icmp -a 10.0.0.0 -o results.csv.gz -r 1000
```

All workers probe the targets in hitlist.txt using ICMPv4, using source address 10.0.0.0, results are stored in results.csv.gz
Each hitlist target receives a single probe from any worker.
Catchment is inferred based on where the ping reply ends up.

Hitlist is divided amongst workers, each worker sends out 1,000 packets per second (-r 1000)

### Anycast latency measurement using TCPv4

```
cli -a [::1]:50001 start hitlist.txt -t tcp -a 10.0.0.0 -m latency
```

Similar as above, except the RTT between each hitlist target and the anycast deployment is also measured.
Each hitlist target receives 2 probes.
The first probe is a `discovery probe` to infer the catching worker for that target (i.e., to which PoP does this target route).
The second probe is a `measurement probe` send from the catching worker to measure the latency (sender == receiver).

### Unicast latency measurement using ICMPv6

```
cli -a [::1]:50001 start hitlistv6.txt -t icmp -m unicast
```

Unicast probes will be sent from all workers to measure the latency of the target to all PoPs.
Each hitlist target receives a single probe from every worker.
Using the lowest unicast RTT, the 'optimal' PoP for that target can be inferred.
Furthermore, if the target does not currently route optimally, the performance gain can be estimated (subtracting the lowest unicast RTT from the actual anycast RTT).

### LACeS measurement

```
cli -a [::1]:50001 start hitlist.txt -t icmp -m laces --responsive
```

Anycast probes will be sent from all workers.
Each hitlist target receives a single probe from every worker.
Used to e.g., perform [MAnycast2](https://www.sysnet.ucsd.edu/sysnet/miscpapers/manycast2-imc20.pdf) anycast censuses.
Targets are scanned for responsiveness, using a single worker probe, before probing from all workers (`--responsive`).

### Anycast traceroute measurement

```
cli -a [::1]:50001 start hitlist.txt -t icmp -m anycast-traceroute
```

Measure the path from the catching PoP to the target.
First, a single `discovery probe` is sent to infer the catching worker.
Next, multiple traceroute packets are sent from the catching worker to measure the path.

## CSV output format

By default, results are written as gzip-compressed CSV files (`.csv.gz`).
Measurement metadata is stored as `#`-prefixed comment lines at the top of the file, followed by a header row and data rows.

### Columns

All values are stored as text. Columns depend on the measurement type:

| Column | Type | Description | Measurement types |
|--------|------|-------------|-------------------|
| `rx` | `String` | Hostname of the receiving worker | All |
| `addr` | `String` | Source IP of the reply (human-readable, e.g., `192.0.2.1` or `2001:db8::1`) | All except Traceroute |
| `ttl` | `String (integer)` | TTL of the reply | All |
| `rtt` | `String (float)` | Round-trip time (ms) | Latency, Unicast, Traceroute |
| `tx` | `String` | Hostname of the sending worker | LACeS, Traceroute |
| `rx_time` | `String (integer)` | Receive timestamp (microseconds since epoch; 21-bit masked for TCP) | LACeS |
| `tx_time` | `String (integer)` | Send timestamp (microseconds since epoch) | LACeS |
| `hop_addr` | `String` | IP address of the traceroute hop (`*` if no reply) | Traceroute |
| `trace_dst` | `String` | Traceroute destination IP address | Traceroute |
| `hop_count` | `String (integer)` | TTL used to trigger this hop reply | Traceroute |
| `chaos_data` | `String` | DNS TXT CHAOS record value | CHAOS |
| `origin_id` | `String (integer)` | Origin ID (multi-origin only) | Multi-origin |

### Column order per measurement type

| Measurement type | Columns (in order) |
|------------------|--------------------|
| Catchment | `rx`, `addr`, `ttl` [, `chaos_data`] [, `origin_id`] |
| Latency / Unicast | `rx`, `addr`, `ttl`, `rtt` [, `origin_id`] |
| LACeS | `rx`, `rx_time`, `addr`, `ttl`, `tx_time`, `tx` [, `chaos_data`] [, `origin_id`] |
| Traceroute | `rx`, `hop_addr`, `ttl`, `tx`, `trace_dst`, `hop_count`, `rtt` |

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
| `rx` | `ENUM` | Hostname of the receiving worker | All |
| `addr` | `FIXED_LEN_BYTE_ARRAY(16)` | Source IP of the reply (see below) | All |
| `ttl` | `UINT8` | TTL of the reply | All |
| `rtt` | `FLOAT` | Round-trip time (ms) | Latency, Unicast |
| `tx` | `ENUM` | Hostname of the sending worker | LACeS |
| `rx_time` | `TIMESTAMP(MICROS, UTC)` | Receive timestamp | LACeS |
| `tx_time` | `TIMESTAMP(MICROS, UTC)` | Send timestamp | LACeS |
| `chaos_data` | `STRING` | DNS TXT CHAOS record value | CHAOS |
| `origin_id` | `UINT8` | Origin ID (multi-origin only) | Multi-origin |

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
curl -L -o manycastr https://github.com/rhendriks/MAnycastR/releases/download/latest/manycastr
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
