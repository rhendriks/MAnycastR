# Changelog

All notable changes to MAnycastR are documented in this file.

## [1.7.0] - 2026-06-06

Adds `--any` multi-protocol fallback and substantially simplifies the
orchestrator internals.

### Added
- **`--any` protocol fallback** -- when multiple protocols are specified with
  `-p` (e.g. `-p icmp,dns,tcp`), `--any` tries them in order and stops
  per-target on the first responsive protocol. Implies `--responsive`. Requires
  at least two protocols. (#70)

### Fixed
- **DNS measurement ID filtering** -- DNS probes now encode the measurement ID in
  the QNAME and the top 6 bits of the DNS transaction ID. The BPF filter and
  receive path validate both, so stale replies from a previous measurement
  (e.g. from a broken resolver) are dropped. CHAOS measurements use the
  transaction-ID bits only (6-bit discriminator).
- **Orchestrator no longer panics when the CLI disconnects** during an active
  measurement. Result forwarding and measurement-finished notifications now
  handle a dropped CLI gracefully.
- **Orchestrator no longer finishes measurements prematurely** —
  a 5-second reply grace period after the hitlist is exhausted gives discovery
  replies time to arrive and create follow-up tasks before the idle cooldown
  can start.

### Changed
- **Consolidated per-measurement state** into a single `MeasurementState` struct
  behind one `RwLock` `send_result` now acquires one lock instead of three.
- **Unified three task distributors** (broadcast, round-robin, discovery) into a
  single `distribute_tasks` function with a `DistributionStrategy` enum.
- **Removed `task_sender` channel indirection** -- tasks are now sent directly to
  workers via a `send_to_workers` helper instead of routing through an
  intermediate mpsc channel.
- **Eliminated hitlist copies at measurement start** -- the address vec is moved
  out of the protobuf message.
- **Broke up `do_measurement`** into helper functions.

## [1.6.0] - 2026-06-04

Adds an unprivileged ("sudo-less") operating mode and, alongside it, reworks the
worker send/receive path, adds Parquet support for
traceroute, and improves LACeS and traceroute output.

### Added
- **Direct targets on the command line** — `-t`/`--target` accepts one or more
  comma-separated addresses (e.g. `-t 1.1.1.1` or `-t 1.1.1.1,8.8.8.8`) as an
  alternative to a `--hitlist` file, for ad-hoc measurements. (#86)
- **Unprivileged probing**:
  - ICMP falls back to an unprivileged `SOCK_DGRAM` socket when no raw socket is
    available (requires `net.ipv4.ping_group_range`), so no `sudo`/root or
    `CAP_NET_RAW` is needed for ICMP. (#86)
  - DNS/CHAOS prefer an unprivileged `SOCK_DGRAM` UDP socket even when raw is
    available — a bound UDP socket also prevents the kernel from sending
    ICMP/ICMPv6 *port-unreachable* replies to solicited DNS responses. (#86)
- **In-kernel packet filtering (classic BPF)** — raw sockets attach a cBPF filter
  (`SO_ATTACH_FILTER`, no extra privilege) so the kernel drops non-matching
  packets before they reach the receive buffer. Filters for ICMP echo (by
  identifier), ICMP traceroute (by type), TCP RST (flag + port), and DNS
  (port + identifier), on both IPv4 and IPv6. (#86)
- **Traceroute over Parquet** — anycast-traceroute results can now be written to
  `.parquet` (`--parquet`), not just CSV. (#85)
- **Unresponsive traceroute hops** are emitted to the output as `*` rows on
  timeout, controlled by the new `--trace_star` option (default `true`). (#86)
- Documented the worker privilege model and trade-offs (raw vs. `ping_group_range`
  vs. unprivileged UDP) in the README, and the recommended `net.core.rmem_max`
  tuning for high probing rates. (#86)

### Changed
- **Receive timestamps now come from the kernel (`SO_TIMESTAMP`)** at packet
  arrival rather than from userspace, removing latency inflation under load. (#86)
- **Raw sockets are preferred** for ICMP/TCP, with performant cBPF filters
  and kernel timestamps for more accurate RTTs.
- **Send/receive path performance**: lock-free channel between the listener and
  result-forwarding threads (replacing a mutex-guarded queue); blocking socket
  with a read timeout instead of nonblocking + sleep; the destination address
  and send buffer are constructed once and reused; avoided per-packet string
  clones. (#86)
- **LACeS `rtt`** is the signed `rx_time - tx_time` offset in milliseconds.
  Under anycast the sender (`tx`) and receiver (`rx`) may be different PoPs, so
  this is a one-way delay plus clock offset (and may be negative), not a true
  round-trip. (#86)
- RTT values are formatted to three decimal places (millisecond precision). (#83)
- Traceroute `hop_count` is stored as `UINT8` in Parquet. (#85)
- Reworked output-file creation and display. (#84)

### Fixed
- **Traceroute RTT** was wrong: the 14-bit-millisecond hop timestamp was being
  compared against a microsecond receive time. (#86)
- **Traceroute measurements with few/single targets no longer finish early** —
  the orchestrator stays alive while traceroute sessions are still walking hops
  or waiting on per-hop timeouts. (#86)
- Output paths that are directories are recognized even without a trailing `/`. (#84)
- Corrected README measurement examples. (#86)

> Entries for releases before 1.6.0 are summarized from the git history and are
> coarser than the changelog above.

## [1.5.0] - 2026-05-18

### Changed
- Parquet output optimized for size and queryability: Zstd compression, `rtt`
  stored as `FLOAT`, send/receive times stored as `TIMESTAMP` (not integers),
  IP addresses stored as fixed-length IPv4-mapped-IPv6 byte arrays, and `rx`/`tx`
  hostnames stored as categorical `ENUM` columns.
- Adjusted the "measurement finished" cooldown handling.
- Updated dependencies (parquet, rand, others).

### Fixed
- Inbound listener threads can now exit cleanly at the end of a measurement.

## [1.4.0] - 2026-01-26

### Added
- **Multi-protocol scanning**: a single measurement can use multiple protocols
  (`-p icmp,dns,...`); each protocol gets its own origin, and tasks/reply batches
  are coupled to a specific `origin_id`.

### Changed
- Renamed the `verfploeter` measurement type to `catchment`.
- TCP send times are encoded as milliseconds; receive times use microseconds.
- Faster packet reception (removed a long wait and an unnecessary heap allocation).
- Workers only probe using matching origin IDs.

### Fixed
- Round-robin distributor cooldown handling.

## [1.3.1] - 2026-01-20

### Changed
- Release builds optimized for speed rather than size; pinned `rand` to a stable
  version; configured the release profile.

## [1.3.0] - 2026-01-13

### Changed
- **Replaced `pnet` with `socket2`** for socket handling (the kernel writes the
  Ethernet and IPv6 headers).
- Reworked IPv6 support: separate inbound/outbound sockets/threads per origin,
  IPv6 hop-limit handling, and a non-blocking listener socket.

## [1.2.0] - 2026-01-09

### Added
- **Anycast traceroute** (`anycast-traceroute`): per-target session tracking with
  a timeout handler, hop fields encoded in the ICMP identifier/sequence, `*` rows
  for unresolved hops, optional RTT, and CLI/proto trace options (max hops,
  timeout, initial hop).
- **Record Route** (ICMP RR, IPv4-only) measurements.
- **Measurement types** selectable via `clap` (e.g. catchment, unicast, latency),
  with protocol types carried in the proto.
- Published rustdoc (`docs.yml`), a `LICENSE`, and a citation file.

### Changed
- **Renamed the package `manycast` → `manycastr`** (binary, Docker image, docs).
- Restructured replies into discovery/measurement/trace types, sent as batches of
  a single reply type; unified the ICMP echo builder for IPv4 and IPv6.
- DNS: verify transaction-ID bits on replies; encode the sender worker ID in the
  CHAOS transaction ID.
- The MUSL binary is uploaded to a GitHub release.

## [1.0.5] - 2025-08-10

### Added
- **Optional Parquet output** with metadata (connected workers, worker count, …).

### Changed
- Timestamps switched from nanoseconds to **microseconds**.
- `--responsive` forces the probing rate; increased buffer sizes.

### Fixed
- TCP RTT calculation.
- Slow `--responsive` discovery probing.

## [1.03] - 2025-07-30

### Added
- **Responsiveness mode** (`--responsive`): a single-worker discovery probe before
  probing from all workers.
- Worker **configuration-file** support; configurations can reference workers by
  hostname.
- DNS protocol handling reworked (protocol enum, IPv6 query names, checksum and
  transaction-ID fixes); multi-probe support.

### Changed
- Reworked the task distributor (round-robin distribution and follow-up handling)
  and added worker reconnect support.
- Output writes compressed IP addresses; the reply source column was renamed to
  `addr`; merged the bidirectional hashmaps into a single `BiHashMap`.
- Default gateway MAC is read from `/proc/net/route` instead of `ip route`.
- CI: added the Docker image workflow and switched to nightly with clippy/rustfmt.

## [1.0.2] - 2025-05-21

### Added
- **Multi-origin probing** (multiple source addresses/ports) with origin inference
  and an `origin_id` column (written only when multiple origins are used).
- `.gz` hitlist support and gzip-compressed output/metadata.
- Spoofed-reply filtering and IPv4 parsing sanity checks.
- Dynamic default-gateway MAC retrieval.

### Changed
- Write IP addresses instead of IP-numbers; consolidated on a single `Address`
  type and `u32`-based IP handling; flattened result structures.
- Stripped the MUSL binary in the Docker image (≈120 MB → 8 MB).

## [1.0.1] - 2025-03-25

### Added
- Outbound rate-limiting to avoid bursts.
- Client-selective measurements (per-worker configuration); `worker-list` shows
  whether each worker is currently measuring.
- FreeBSD ARP lookup support; skip empty lines in hitlist files.
- Initial CI workflow (`rust.yml`).

### Fixed
- Measurement timer; configuration-address validation (skipped for unicast).

## [1.0.0] - 2025-03-18

- Initial release.

[1.7.0]: https://github.com/rhendriks/MAnycastR/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/rhendriks/MAnycastR/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/rhendriks/MAnycastR/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/rhendriks/MAnycastR/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/rhendriks/MAnycastR/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/rhendriks/MAnycastR/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/rhendriks/MAnycastR/compare/v1.0.5...v1.2.0
[1.0.5]: https://github.com/rhendriks/MAnycastR/compare/v1.03...v1.0.5
[1.03]: https://github.com/rhendriks/MAnycastR/compare/v1.0.2...v1.03
[1.0.2]: https://github.com/rhendriks/MAnycastR/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/rhendriks/MAnycastR/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/rhendriks/MAnycastR/releases/tag/v1.0.0
