# Running a shared deployment

More detailed instructions when
operating a MAnycastR deployment used by more than one person,
securing a deployment,
and/or keeping Workers connected.
See the [README](../README.md) for installation and everyday use.

## Restricting rates and origins

To share measurement infrastructure between users,
the Orchestrator can enforce limits that any CLI requesting a measurement must adhere to.
`--max_rate` caps the probing rate (probes per second, per Worker).
`--origins [FILE]` supplies an allow-list, one origin per line as`src_addr, protocol[, protocol...]`,
where `src_addr` is an anycast address or `unicastv4`/`unicastv6`
and the protocol list may be `all` (see [example.origins](example.origins)):

```bash
manycastr orchestrator -p 50001 --max_rate 1000 --origins ./example.origins
```

A measurement is refused unless every origin it uses matches a rule. Without `--origins`, all origins
are allowed.

## Separating CLI and Worker access

`--cli_port` puts CLI and Worker connections on different ports,
so CLI access can be restricted separately (e.g. with iptables).
gRPC calls that do not belong to a port are refused with `PermissionDenied`.

## Worker connection loss and reconnects

A Worker that loses its connection to the Orchestrator exits
When it reconnects with the same hostname (`-n`, default `$HOSTNAME`) it keeps its Worker ID,
and rejoins the measurement it was participating in if that is still active.
Probe replies during the disconnected period are missed,
and the Orchestrator drops follow-up tasks queued for the Worker on disconnect.

Run Workers under a supervisor that restarts them, e.g. systemd:

```ini
[Service]
Restart=always
RestartSec=5
StartLimitIntervalSec=0
```

## TLS

The inter-component gRPC connections optionally use TLS.
The Orchestrator holds a certificate and private key;
Workers and the CLI verify its identity against the certificate given with `--tls` —
either the Orchestrator's own self-signed certificate,
the certificate of the CA that issued it,\
or a CA bundle.
The Orchestrator is authenticated as the host given in `-a`, or as `--tls_domain [NAME]`.

**1. Generate a certificate** on the Orchestrator host (skip this if your own CA issues it):

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout orchestrator.key -out orchestrator.crt \
  -subj "/CN=orchestrator.example.com" \
  -addext "subjectAltName=DNS:orchestrator.example.com" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"
```

Replace `orchestrator.example.com` with the FQDN of your Orchestrator —
if Workers connect by hostname, use that hostname.
A Subject Alternative Name is required, though the name need not be resolvable in DNS.
`basicConstraints=critical,CA:FALSE` is also required: without it `openssl req-x509` marks the certificate as a CA,
and clients reject it with `InvalidCertificate(CaUsedAsEndEntity)`,
since rustls does not allow a CA certificate to be presented as a server certificate.

**2. Start the Orchestrator with TLS.** The key defaults to the `--tls` path with a `.key`extension:

```bash
manycastr orchestrator -p 50001 --tls ./orchestrator.crt
manycastr orchestrator -p 50001 --tls ./orchestrator.crt --tls_key /other/path/orchestrator.key
```

**3. Copy `orchestrator.crt` to every Worker and CLI host, and connect:**

```bash
manycastr worker -a [ORC ADDRESS] --tls ./orchestrator.crt
manycastr cli -a [ORC ADDRESS] --tls ./orchestrator.crt worker-list
```

### Using an internal CA

The Orchestrator must serve its own certificate
**and** every intermediate CA certificate between it and the CA the clients trust;
without them clients cannot link the certificate to the CA and reject the connection with `InvalidCertificate(UnknownIssuer)`.
The `--tls` file therefore has to hold the full chain, leaf first.

```bash
manycastr orchestrator -p 50001 --tls /etc/letsencrypt/live/example.com/fullchain.pem \
  --tls_key /etc/letsencrypt/live/example.com/privkey.pem

cat orchestrator.crt intermediate-ca.crt > orchestrator-chain.crt
manycastr orchestrator -p 50001 --tls orchestrator-chain.crt --tls_key orchestrator.key
```

The Orchestrator logs what it serves, so an incomplete chain is visible at startup:

```text
[TLS] Serving a certificate valid for orchestrator.example.com
[TLS] Serving a chain of 2 certificates, issued by 'CN=Internal Intermediate CA'
```

```bash
manycastr worker -a orchestrator.example.com:50001 --tls /etc/ssl/certs/internal-ca.crt
```

### Using the system trust store

When the CA is installed on the Worker and CLI hosts — a public CA, or your own distributed by
configuration management — `--tls_system` verifies against the host's own trust store,
and no certificate file has to be distributed:

```bash
manycastr worker -a orchestrator.example.com:50001 --tls_system
manycastr cli -a orchestrator.example.com:50001 --tls_system worker-list
```

