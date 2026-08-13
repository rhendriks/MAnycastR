# Output formats

How MAnycastR writes measurement results, and how to read them back.
See the [README](../README.md) for running the measurements that produce them.

Results are written to the path given by `-o` (default: the working directory).
When a directory is given, the filename is generated as `<type>-<protocol>-<version>-<timestamp>.<ext>`,
where `<version>` is `v4`, `v6`, or `mixed`,
and latency measurements are distinguished as `anycast-latency` or `unicast-latency` depending on the source address used.
Example: `anycast-latency-icmp-v4-1753363200.csv.gz`.

## Columns

| Column       | CSV type           | Parquet type               | Description                                                                        | Measurement types          |
|--------------|--------------------|----------------------------|------------------------------------------------------------------------------------|----------------------------|
| `rx`         | `String`           | `STRING`                   | Hostname of the receiving worker (`*`/null for unresponsive trace hops)            | All                        |
| `addr`       | `String`           | `FIXED_LEN_BYTE_ARRAY(16)` | Source IP of the reply, or traceroute hop address (`*` if no reply)                | All                        |
| `ttl`        | `String (integer)` | `UINT8`                    | TTL of the reply                                                                   | All                        |
| `rtt`        | `String (float)`   | `FLOAT`                    | Round-trip time in ms; for LACeS the signed `rx_time - tx_time` offset (see below) | Latency, Traceroute, LACeS |
| `tx`         | `String`           | `STRING`                   | Hostname of the sending worker                                                     | LACeS, Traceroute          |
| `trace_dst`  | `String`           | `FIXED_LEN_BYTE_ARRAY(16)` | Traceroute destination IP address                                                  | Traceroute                 |
| `hop_count`  | `String (integer)` | `UINT8`                    | TTL used to trigger this hop reply                                                 | Traceroute                 |
| `chaos_data` | `String`           | `STRING`                   | DNS TXT CHAOS record value                                                         | CHAOS                      |
| `origin_id`  | `String (integer)` | `UINT8`                    | Origin ID (multi-origin only)                                                      | Multi-origin               |

| Measurement type  | Columns (in order)                                                |
|-------------------|-------------------------------------------------------------------|
| Catchment         | `rx`, `addr`, `ttl` [, `chaos_data`] [, `origin_id`]              |
| Latency           | `rx`, `addr`, `ttl`, `rtt` [, `origin_id`]                        |
| LACeS             | `rx`, `addr`, `ttl`, `tx`, `rtt` [, `chaos_data`] [, `origin_id`] |
| Traceroute        | `rx`, `addr`, `ttl`, `tx`, `trace_dst`, `hop_count`, `rtt`        |

In CSV the columns present depend on the measurement type;
in Parquet the schema is fixed per measurement type,
so every column that type can produce is always present and null when unused.

> NOTEs:
> For LACeS the `rtt` column is not a true round-trip time.
> Instead it is the offset of `rx_time - tx_time` (milliseconds).
> Where rx_time is set by the catching PoP, and tx_time by the sending PoP.
> For TCP the send time is a 21-bit microsecond value.

## CSV (default)

Results are gzip-compressed CSV (`.csv.gz`), with measurement metadata as `#`-prefixed comment lines
above the header row. All values are stored as text.

```python
import pandas as pd

df = pd.read_csv("results.csv.gz", comment="#")
```
```sql
SELECT * FROM read_csv('results.csv.gz', comment='#');
```

## Parquet (`--parquet`)

Parquet with Zstd compression;
rows are sorted by `addr` within each row group (1M rows) for better compression and predicate pushdown.

The `addr` and `trace_dst` columns store IP addresses as 16-byte fixed-length binary in IPv4-mapped-IPv6 format ([RFC 4291 §2.5.5.2](https://www.rfc-editor.org/rfc/rfc4291#section-2.5.5.2)):
IPv4 `192.0.2.1` is stored as `::ffff:192.0.2.1`, IPv6 addresses as-is, big-endian.

```python
import pandas as pd, ipaddress

df = pd.read_parquet("results.parquet")
df["addr"] = df["addr"].apply(lambda b: ipaddress.ip_address(b).ipv4_mapped or ipaddress.ip_address(b))
```
```sql
SELECT rx, ttl,
       CASE WHEN addr[1:12] = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF'::BLOB
            THEN printf('%d.%d.%d.%d', get_byte(addr, 12), get_byte(addr, 13),
                                       get_byte(addr, 14), get_byte(addr, 15))
            ELSE encode(addr) END AS ip_address
FROM read_parquet('results.parquet');
```

Measurement metadata is stored as parquet metadata.

| Key                                                    | Description                                                                                                                                            |
|--------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `format_version`                                       | Version of the Parquet output format (currently `1`; bumped on incompatible changes)                                                                   |
| `tool_version`                                         | MAnycastR version that produced the file                                                                                                               |
| `measurement_type`                                     | Measurement type performed                                                                                                                             |
| `start_time` / `end_time`                              | Measurement start and end (RFC 3339, UTC)                                                                                                              |
| `responsive_mode`                                      | Present (`true`) when `--responsive` was used                                                                                                          |
| `hitlist_path` / `hitlist_length` / `hitlist_shuffled` | Hitlist used, its target count, and whether it was shuffled                                                                                            |
| `probing_rate`                                         | Probing rate (probes per second)                                                                                                                       |
| `worker_interval_ms`                                   | Interval between probes from different workers                                                                                                         |
| `probe_interval_s` / `number_of_probes`                | Interval between and count of probes per origin,dst pair                                                                                               |
| `record` / `url`                                       | DNS record queried / URL encoded in probes (present when set)                                                                                          |
| `connected_workers` / `connected_workers_count`        | Hostnames and count of connected workers                                                                                                               |
| `configurations`                                       | JSON array of origin definitions (`worker`, `origin_id`, `src`, `sport`, `dport`, `protocol`) — the mapping needed to interpret the `origin_id` column |

