# ManycastR

MAnycastR (Measuring Anycast Reloaded) is a tool designed to measure anycast infrastructure.

This includes:

i) Measuring external anycast infrastructure
* [MAnycast2](https://www.sysnet.ucsd.edu/sysnet/miscpapers/manycast2-imc20.pdf) (measuring anycast using anycast)
* [iGreedy](https://anycast.telecom-paristech.fr/assets/papers/JSAC-16.pdf) (measuring anycast using Great-Circle-Distance latency measurements)

ii) Measuring anycast infrastructure itself
* [Verfploeter](https://ant.isi.edu/~johnh/PAPERS/Vries17b.pdf) (mapping anycast catchments)
* [Site flipping]() (detecting network regions experiencing anycast site flipping)
* Anycast latency (measuring RTT between the Internet and the anycast infrastructure)
* Optimal deployment (measuring 'best' deployment using unicast latencies from all sites to the Internet)
* Multi-deployment probing (measure multiple anycast prefixes simultaneously)

Both IPv4 and IPv6 measurements are supported, with underlying protocols ICMP, UDP (DNS), and TCP.

## The components

Deployment of MAnycastR consists of three components:
* `Orchestrator` - a central controller orchestrating measurements
* `CLI` - Command-line interface scheduling measurements at the orchestrator and collecting results
* `Worker` - Deployed on anycast sites, performing measurements

## Measurement process

A measurement is started by running the CLI, which can be executed e.g., locally or on a VM.
The CLI sends a measurement definition based on the arguments provided when running the `start` command.
Example commands will be provided in the Usage section.

Upon receiving a measurement definition, the orchestrator instructs the workers to start the measurement.
Workers perform measurements by sending and receiving probes.

Workers stream results to the orchestrator, which aggregates and forwards them to the CLI.
The CLI writes results to a CSV file.

## Measurement types
Measurements can be;
* `icmp` ICMP ECHO requests
* `dns` UDP DNS A Record requests
* `tcp` TCP SYN/ACK probes
* `chaos` UDP DNS TXT CHAOS requests

## Measurement parameters

When creating a measurement you can specify:

### Variables
* **Hitlist** - addresses to be probed (can be IP addresses or numbers)
* **Type of measurement** - ICMP, UDP, TCP, or CHAOS
* **Rate** - the rate (packets / second) at which each worker will send out probes (default: 1000)
* **Selective** - specify which workers have to send out probes (all connected workers will listen for packets)
* **Interval** - interval between separate worker's probes to the same target (default: 1s)
* **Address** - source anycast address to use for the probes
* **Source port** - source port to use for the probes (default: 62321)
* **Destination port** - destination port to use for the probes (default: DNS: 53, TCP: 63853)
* **Configuration** - path to a configuration file (allowing for complex configurations of source address, port values used by workers)
* **Query** - specify DNS record to request (TXT (CHAOS) default: hostname.bind, A default: google.com)
* **Responsive** - check if a target is responsive before probing from all workers (unimplemented)
* **Out** - path to file or directory to store measurement results (default: ./)
* **URL** - encode URL in probes (e.g., for providing opt-out information, explaining the measurement, etc.)

### Flags
* **Stream** - stream results to the command-line interface (optional)
* **Shuffle** - shuffle the hitlist
* **Unicast** - perform measurement using the unicast address of each worker
* **Traceroute** - anycast traceroute (currently broken)
* **Divide** - divide-and-conquer Verfploeter catchment mapping

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
cli -a [::1]:50001 start hitlist.txt -t icmp -a 10.0.0.0 -o results.csv
```

All workers probe the targets in hitlist.txt using ICMPv4, using source address 10.0.0.0, results are stored in results.csv

With this measurement each target receives a probe from each worker.
Filtering on sender == receiver allows for calculating anycast RTTs.

#### Divide-and-conquer Verfploeter catchment mapping using TCPv4

```
cli -a [::1]:50001 start hitlist.txt -t tcp -a 10.0.0.0 --divide
```

hitlist.txt will be split in equal parts among workers (divide-and-conquer), results are stored in ./

Enabling divide-and-conquer means each target receives a single probe, whereas before each worker would probe each target.
Benefits are; lower probing burden on targets, less data to process, faster measurements (hitlist split among workers).
Whilst this provides a quick catchment mapping, the downside is that you will not be able to calculate anycast RTTs.

#### Unicast latency measurement using ICMPv6

```
cli -a [::1]:50001 start hitlistv6.txt -t icmp --unicast
```

Since the hitlist contains IPv6 addresses, the workers will probe the targets using their IPv6 unicast address.

This feature gives the latency between all anycast sites and each target in the hitlist.
Filtering on the lowest unicast RTTs indicates the best anycast site for each target.

## Requirements

* rustup
* protobuf-compiler

## Installation

### Cargo (static binary)

#### Install rustup
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

#### Install protobuf-compiler
```bash
apt-get install protobuf-compiler
```

#### Clone the repository
```bash
git clone <repo>
cd <repo_dir>
```

#### Compile the code (16 MB binary)
```bash
cargo build --release --target x86_64-unknown-linux-musl
```

#### Optionally strip the binary (16 MB -> 7.7 MB)
```bash
strip target/x86_64-unknown-linux-musl/release/manycast
```

Next, distribute the binary to the workers.

Workers need either sudo or the CAP_NET_RAW capability to send out packets.
```bash
sudo setcap cap_net_raw,cap_net_admin=eip manycast
```

### Docker

#### Build the Docker image
```bash
docker build -t manycast .
```

Advise is to run the container with network host mode.
Additionally, the container needs the CAP_NET_RAW and CAP_NET_ADMIN capability to send out packets.
```bash
docker run -it --network host --cap-add=NET_RAW --cap-add=NET_ADMIN manycast
```

## Contributions

Issues and pull requests are welcome
