use clap::ArgMatches;
use log::{info, warn};
use std::error::Error;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tonic::transport::{Certificate, ClientTlsConfig, Identity};
use x509_parser::prelude::{GeneralName, Pem, X509Certificate};

/// PEM label of an X.509 certificate (other blocks, e.g. private keys, are ignored).
const CERTIFICATE_LABEL: &str = "CERTIFICATE";

/// Track what the SAN is authenticated against (based on user parameters).
enum NameSource {
    /// Given explicitly with `--tls_domain`
    Flag,
    /// The host part of the orchestrator address (`-a`)
    Address,
    /// The Subject Alternative Name of a pinned self-signed certificate
    Pinned,
}

impl NameSource {
    fn as_str(&self) -> &'static str {
        match self {
            NameSource::Flag => "--tls_domain",
            NameSource::Address => "-a",
            NameSource::Pinned => "certificate SAN",
        }
    }
}

/// The TLS settings of a worker or CLI, as given on the command line.
pub struct TlsOptions<'a> {
    /// Path to the trust anchor to verify the orchestrator against (`--tls`)
    cert_path: Option<&'a str>,
    /// Verify against the host's system trust store (`--tls_system`) (if true)
    system_roots: bool,
    /// The name to verify the orchestrator as, overriding the address (`--tls_domain`)
    domain: Option<&'a str>,
}

impl<'a> TlsOptions<'a> {
    /// Read the TLS settings from the parsed command-line arguments of a worker or CLI.
    pub fn from_args(args: &'a ArgMatches) -> Self {
        Self {
            cert_path: args.get_one::<String>("tls").map(String::as_str),
            system_roots: args.get_flag("tls_system"),
            domain: args.get_one::<String>("tls_domain").map(String::as_str),
        }
    }

    /// Whether the connection to the orchestrator is secured with TLS.
    pub fn is_enabled(&self) -> bool {
        self.cert_path.is_some() || self.system_roots
    }

    /// Build the client-side TLS configuration used by workers and the CLI.
    ///
    /// # Arguments
    /// * `address` - the orchestrator address (`-a`), whose host names the orchestrator
    ///
    /// # Returns
    /// A tonic [`ClientTlsConfig`] holding the trust anchors and the name to authenticate.
    ///
    /// # Errors
    /// If the certificate file cannot be read or holds no PEM certificate.
    pub fn client_config(&self, address: &str) -> Result<ClientTlsConfig, Box<dyn Error>> {
        let Some(cert_path) = self.cert_path else {
            // Use the trust store
            let (server_name, source) = server_name(&[], address, self.domain);
            info!(
                "[TLS] Trusting the system trust store, authenticating orchestrator as '{server_name}' (from {})",
                source.as_str()
            );

            return Ok(ClientTlsConfig::new()
                .with_native_roots()
                .domain_name(server_name));
        };

        // Use the provided certificate
        client_config(cert_path, address, self.domain)
    }
}

/// Build the client-side TLS configuration from a file of trust anchors.
///
/// # Arguments
/// * `cert_path` - path to the trust anchor to verify the orchestrator against
/// * `address` - the orchestrator address (`-a`), whose host names the orchestrator
/// * `tls_domain` - the name to verify the orchestrator as, overriding the address (`--tls_domain`)
///
/// # Returns
/// A tonic [`ClientTlsConfig`] that trusts the certificates in `cert_path`.
///
/// # Errors
/// If the certificate file cannot be read or holds no PEM certificate.
fn client_config(
    cert_path: &str,
    address: &str,
    tls_domain: Option<&str>,
) -> Result<ClientTlsConfig, Box<dyn Error>> {
    let pem = fs::read(cert_path)
        .map_err(|e| format!("Unable to read certificate at {cert_path}: {e}"))?;
    let certificates = certificates(&pem, cert_path)?;

    let (server_name, source) = server_name(&certificates, address, tls_domain);

    info!(
        "[TLS] Trusting {} certificate(s) from {cert_path}, authenticating orchestrator as '{server_name}' (from {})",
        certificates.len(),
        source.as_str()
    );

    // Verifying an IP address requires the orchestrator's certificate to carry an IP SAN
    if matches!(source, NameSource::Address) && server_name.parse::<IpAddr>().is_ok() {
        warn!("[TLS] Authenticating an IP address requires an IP Subject Alternative Name.");
    }

    Ok(ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(pem))
        .domain_name(server_name))
}

/// Load the orchestrator's TLS identity (certificate + private key).
///
/// The certificate file may hold a chain with intermediate CA certificates.
///
/// # Arguments
/// * `cert_path` - path to the certificate (chain)
/// * `key_path` - path to the private key, defaults to `cert_path` with a `.key` extension
///
/// # Returns
/// A tonic [`Identity`] to be used in the server's `ServerTlsConfig`.
///
/// # Panics
/// If the certificate or private key cannot be read.
pub fn server_identity(cert_path: &str, key_path: Option<&str>) -> Identity {
    let key_path = key_path.map_or_else(|| default_key_path(cert_path), PathBuf::from);

    let cert = fs::read(cert_path)
        .unwrap_or_else(|e| panic!("Unable to read certificate at {cert_path}: {e}"));
    let key = fs::read(&key_path)
        .unwrap_or_else(|e| panic!("Unable to read private key at {}: {e}", key_path.display()));

    info!(
        "[TLS] Using certificate {cert_path} and private key {}",
        key_path.display()
    );

    // Parse all provided PEM certificates.
    match certificates(&cert, cert_path) {
        Ok(certificates) => describe_served_chain(&certificates, cert_path),
        Err(e) => warn!("[TLS] {e}"),
    }

    Identity::from_pem(cert, key)
}

/// The private key path implied by a certificate path (same name, `.key` extension).
fn default_key_path(cert_path: &str) -> PathBuf {
    Path::new(cert_path).with_extension("key")
}

/// Parse every PEM certificate in `pem`, in file order.
///
/// # Errors
/// If the file holds no PEM certificate (e.g. it is a private key, or DER rather than PEM).
fn certificates(pem: &[u8], cert_path: &str) -> Result<Vec<Pem>, Box<dyn Error>> {
    let certificates: Vec<Pem> = Pem::iter_from_buffer(pem)
        .filter_map(Result::ok)
        .filter(|pem| pem.label == CERTIFICATE_LABEL)
        .collect();

    if certificates.is_empty() {
        return Err(format!("No PEM certificate found in {cert_path}.").into());
    }

    Ok(certificates)
}

/// Determine the name to authenticate the orchestrator as.
///
/// In order:
/// 1. `--tls_domain`, when given.
/// 2. The host part of the orchestrator address, when it is a hostname.
///    a. The Subject Alternative Name of a pinned self-signed certificate.
///    b. The address itself, an IP address verified against an IP SAN.
fn server_name(
    certificates: &[Pem],
    address: &str,
    tls_domain: Option<&str>,
) -> (String, NameSource) {
    if let Some(domain) = tls_domain {
        return (domain.to_owned(), NameSource::Flag);
    }

    let host = host_of(address);
    if host.parse::<IpAddr>().is_err() {
        return (host.to_owned(), NameSource::Address);
    }

    pinned_self_signed_name(certificates).map_or_else(
        || (host.to_owned(), NameSource::Address),
        |name| (name, NameSource::Pinned),
    )
}

/// Get the hostname/address part of an `address:port` value
fn host_of(address: &str) -> &str {
    // Strip brackets (IPv6)
    if let Some(rest) = address.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }

    address.rsplit_once(':').map_or(address, |(host, _)| host)
}

/// Get the name pinned in self-signed certificates.
fn pinned_self_signed_name(certificates: &[Pem]) -> Option<String> {
    // Must be a single PEM certificate
    let [pinned] = certificates else {
        return None;
    };

    let certificate = pinned.parse_x509().ok()?;
    if certificate.subject().as_raw() != certificate.issuer().as_raw() {
        // Issued by a different certificate
        return None;
    }

    subject_alternative_names(&certificate).into_iter().next()
}

/// Get the SAN values (hostnames and IP addresses) a certificate is valid for.
fn subject_alternative_names(certificate: &X509Certificate) -> Vec<String> {
    let names = certificate
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| san.value.general_names.as_slice())
        .unwrap_or_default();

    let dns = names.iter().filter_map(|name| match name {
        GeneralName::DNSName(dns) => Some((*dns).to_owned()),
        _ => None,
    });
    let ip = names.iter().filter_map(|name| match name {
        GeneralName::IPAddress(bytes) => to_ip(bytes).map(|ip| ip.to_string()),
        _ => None,
    });

    dns.chain(ip).collect()
}

/// Parse Orchestrator certificate and warn for possibly malformed certificates.
fn describe_served_chain(certificates: &[Pem], cert_path: &str) {
    // Get the first certificate (in case it is a chain or bundle)
    let Ok(certificate) = certificates[0].parse_x509() else {
        warn!("[TLS] Unable to parse the certificate at {cert_path}");
        return;
    };

    // Get allowed SAN values
    let names = subject_alternative_names(&certificate);
    if names.is_empty() {
        warn!(
            "[TLS] The certificate at {cert_path} has no Subject Alternative Name (SAN), \
            regenerate it with e.g. -addext \"subjectAltName=DNS:orchestrator.example.com\""
        );
    } else {
        info!("[TLS] Serving a certificate valid for {}", names.join(", "));
    }

    let is_self_signed = certificate.subject().as_raw() == certificate.issuer().as_raw();
    if is_self_signed {
        info!("[TLS] The certificate is self-signed, clients must trust it directly (--tls)");
    } else if certificates.len() == 1 {
        // Single certificate that is not self-signed -> clients must trust the CA.
        info!(
            "[TLS] The certificate was issued by '{}', clients must trust that CA (--tls); \
            if it is an intermediate CA, append its certificate to {cert_path} (a full chain, \
            leaf first), or clients will reject the connection with 'UnknownIssuer'",
            certificate.issuer()
        );
    } else {
        info!(
            "[TLS] Serving a chain of {} certificates, issued by '{}'",
            certificates.len(),
            certificate.issuer()
        );
    }
}

/// Convert the raw bytes of an IP address SAN into an [`IpAddr`].
fn to_ip(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => None,
    }
}
