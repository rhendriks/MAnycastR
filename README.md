# MAnycastR

MAnycastR (Measure Anycast Routing) is a tool designed to measure anycast infrastructure.

This includes:

i) Measuring anycast infrastructure itself
* [Verfploeter](https://ant.isi.edu/~johnh/PAPERS/Vries17b.pdf) (mapping anycast catchments)
* Anycast latency (measuring RTT between the anycast infrastructure and the Internet)
* Optimal deployment (measuring 'best' deployment inferred from unicast latencies from all PoPs)
* Multi-deployment probing (measure multiple anycast prefixes simultaneously)
* [Site flipping](https://arxiv.org/abs/2503.14351) (detecting network regions experiencing anycast site flipping)

ii) Measuring external anycast infrastructure
* [LACeS](https://arxiv.org/abs/2503.20554) (anycast-based detection of anycast and latency-based detection, enumeration, geolocation of anycast using Great-Circle-Distance)

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
* **Type of measurement** - ICMP, DNS, TCP, or CHAOS
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
* **Out** - path to file or directory (ending with '/') to store measurement results (default: ./)
* **URL** - encode URL in probes (e.g., for providing opt-out information, explaining the measurement, etc.)

### Flags
* **Stream** - stream results to the command-line interface (optional)
* **Shuffle** - shuffle the hitlist
* **Unicast** - measure unicast latencies from all workers to the targets in the hitlist
* **Divide** - divide-and-conquer Verfploeter catchment mapping
* **Responsive** - check if a target is responsive before probing from all workers
* **Latency** - measure anycast latencies
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

#### Verfploeter catchment mapping using ICMPv4

```
cli -a [::1]:50001 start hitlist.txt -t icmp -a 10.0.0.0 -o results.csv.gz -x [nl-ams]
```

Worker with hostname nl-ams will probe the targets in hitlist.txt using ICMPv4 and source address 10.0.0.0.
All workers listen for probe replies. The CLI writes results live to results.csv.gz

#### Divide-and-conquer Verfploeter catchment mapping using TCPv4

```
cli -a [::1]:50001 start hitlist.txt -t tcp -a 10.0.0.0 --divide
```

hitlist.txt will be split in equal parts among workers (divide-and-conquer), results are stored in ./

Enabling divide-and-conquer means each target receives a single probe, whereas before each worker would probe all targets.
Allows for faster measurements (hitlist split among workers), and spreading probing burden amongst individual PoPs' upstreams.

### MAnycast2 anycast detection

```
cli -a [::1]:50001 start hitlist.txt -t icmp -a 10.0.0.0 -u opt-out.example.com --responsive
```

All workers will probe the targets in hitlist.txt using ICMPv4.
Probes will have the URL opt-out.example.com encoded in the payload.
--responsive will check if a target is responsive from a single worker before probing from all workers.
If probe replies for a single target are received at multiple workers, then it is likely anycast.

### Measure anycast latencies using TCPv6

```
cli -a [::1]:50001 start hitlistv6.txt -t tcp --latency --stream -a 2001:: -s 2222 -d 1111
```

Workers will probe the targets in hitlistv6.txt using TCPv6 with source address 2001::, source port 2222, and destination port 1111.
For each target a discovery probe is sent, to determine the 'catching' PoP.
Next, from the catching PoP, a follow-up probe is sent to measure the RTT.
This results in two probes per target.
Results are streamed to the CLI, and written to a .csv.gz file.
Streamed output can be piped to e.g., `grep` or `awk` for further processing.
Example, printing targets with > 100 ms RTT to the anycast deployment: `| awk -F, 'NR==1 || $4+0 > 100'`

#### Unicast latency measurement using ICMPv6

```
cli -a [::1]:50001 start hitlistv6.txt -t icmp --unicast --parquet
```

Since the hitlist contains IPv6 addresses, the workers will probe the targets using their IPv6 unicast address.

This feature gives the latency between all anycast sites and each target in the hitlist.
Filtering on the lowest unicast RTTs indicates the best anycast site for each target.

Results are stored in .parquet format.

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
@misc{hendriks2025lacesopenfastresponsible,
      title={LACeS: an Open, Fast, Responsible and Efficient Longitudinal Anycast Census System}, 
      author={Remi Hendriks and Matthew Luckie and Mattijs Jonker and Raffaele Sommese and Roland van Rijswijk-Deij},
      year={2025},
      eprint={2503.20554},
      archivePrefix={arXiv},
      primaryClass={cs.NI},
      url={https://arxiv.org/abs/2503.20554}, 
}
```
* Use `--latency` to perform GCD measurements (for iGreedy).
* Use 'default' anycast measurements to perform anycast-based measurements.
---
MAnycastR as a tool for detecting networks experiencing anycast site flipping was used for the following paper. Please cite this when using MAnycastR to detect anycast site flipping.
```
@misc{hendriks2025loadbalancingversusanycastlook,
      title={Load-Balancing versus Anycast: A First Look at Operational Challenges}, 
      author={Remi Hendriks and Mattijs Jonker and Roland van Rijswijk-Deij and Raffaele Sommese},
      year={2025},
      eprint={2503.14351},
      archivePrefix={arXiv},
      primaryClass={cs.NI},
      url={https://arxiv.org/abs/2503.14351}, 
}
```
* Use `--config` configuration-based probing to send probes with varied flow header fields (thus triggering load-balancers).
* Use `--traceroute` to perform anycast Paris traceroute measurements to determine where load-balancers (causing anycast site flipping) reside
