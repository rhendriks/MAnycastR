# Changelog

All notable changes to MAnycastR are documented in this file.

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

[1.6.0]: https://github.com/rhendriks/MAnycastR/compare/v1.5.0...v1.6.0
