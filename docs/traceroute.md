# Traceroute internals

Reference for how MAnycastR's traceroute measurements
(`-m anycast-traceroute`, `-m tracemap`,`-m feed-trace`)
encode and recover per-probe identity.
See the [README](../README.md#anycast-traceroute) for how to run them.

## Probe type and destination detection

| Protocol  | Probe sent                                    | Intermediate-hop reply | "Destination reached" signal                                                          |
|-----------|-----------------------------------------------|------------------------|---------------------------------------------------------------------------------------|
| ICMP      | Echo Request                                  | ICMP Time Exceeded     | ICMP Echo Reply from the target                                                       |
| UDP (DNS) | a valid DNS `A` query to the destination port | ICMP Time Exceeded     | DNS answer from the target (open port), or ICMP Destination Unreachable (closed port) |
| TCP       | unsolicited TCP SYN-ACK                       | ICMP Time Exceeded     | TCP RST from the target                                                               |

## Paris traceroute (UDP and TCP)

UDP and TCP traceroute are Paris traceroute implementations:
the flow 5-tuple (src IP, dst IP, protocol, sport, dport) is held **constant across all TTL values**,
so ECMP load-balancers forward every probe of a trace along the same path.
The per-probe identity (hop TTL, worker ID, send timestamp)
is therefore encoded in header fields that are *not* part of the flow hash,
and recovered from the ICMP Time Exceeded quote (original IP header + first 8 transport bytes):

| Protocol | Identity carried in                                                                                            |
|----------|----------------------------------------------------------------------------------------------------------------|
| ICMP     | ICMP identifier + SEQ                                                                                          |
| UDP      | UDP checksum (TTL + low worker bits) + IPv4 IP Identification / IPv6 Flow Label (high worker bits + timestamp) |
| TCP      | TCP **SEQ** (worker + TTL + timestamp), copied into the **ACK** as well                                        |

* An **intermediate** router's ICMP Time Exceeded
  is only *guaranteed* to quote the original IP header
  plus the **first 8 bytes** of the transport header (RFC 792).
  For TCP those 8 bytes are the source port, destination port, and **SEQ**, not the **ACK**.
* The **destination** answers with a **RST**, which reflects the ACK field (and not the SEQ field).
  Therefore, we encode the identity in both the SEQ and ACK fields.

> **Middlebox caveat (UDP traceroute):** middleboxes may rewrite the IPv4 IP Identification field or the IPv6 Flow Label.
> If this happens the 14-bit transmit timestamp and the 2 high bits of the worker ID are lost;
> path discovery still works, but the per-hop RTT cannot be computed and worker identification is limited to 256 workers.

## Sockets

ICMP traceroute uses a single socket. UDP and TCP traceroute use **two sockets** per origin:

* a raw **ICMP** socket to receive Time Exceeded / Destination Unreachable messages
* a raw **UDP/TCP** socket to send the probes and receive the target's reply (DNS answer / RST).

## Tracemap TTL search (experimental)

`-m tracemap` binary-searches the TTL space for the deepest responding hop,
minimizing traceroute packets.
The first probe is sent at TTL 12 based on median Internet path length.

Because paths may contain unresponsive hops before the target,
a timed-out TTL is first confirmed by probing the next `--trace_max_failures` TTLs.
If all stay silent, it assumes that it went past the target.
Responding hops move the search to higher hop counts.
