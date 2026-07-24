use log::info;
use std::error::Error;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tonic::transport::{Certificate, ClientTlsConfig, Identity};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate, parse_x509_pem};

/// Build the client-side TLS configuration used by workers and the CLI.
/// Reads the SAN (Subject Alternative Name) which it uses as domain name.
/// See `README.md` for certificate creation.
///
/// # Arguments
/// * `cert_path` - path to the Orchestrator's certificate
///
/// # Returns
/// A tonic [`ClientTlsConfig`] that trusts only this certificate.
///
/// # Errors
/// If the certificate cannot be read, is not valid PEM, or carries no DNS or IP SAN.
pub fn client_config(cert_path: &str) -> Result<ClientTlsConfig, Box<dyn Error>> {
    let pem = fs::read(cert_path)
        .map_err(|e| format!("Unable to read certificate at {cert_path}: {e}"))?;
    // Read SAN from certificate to authenticate domain name against
    let server_name = server_name(&pem, cert_path)?;

    info!("[TLS] Using {cert_path}, authenticating orchestrator as '{server_name}'");

    Ok(ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(pem))
        .domain_name(server_name))
}

/// Load the orchestrator's TLS identity (certificate + private key).
///
/// # Arguments
/// * `cert_path` - path to the certificate
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

    Identity::from_pem(cert, key)
}

/// The private key path implied by a certificate path (same name, `.key` extension).
fn default_key_path(cert_path: &str) -> PathBuf {
    Path::new(cert_path).with_extension("key")
}

/// Extract the name to authenticate the orchestrator against from its certificate.
///
/// rustls ignores the Common Name, so a certificate without a SAN cannot be verified at all.
fn server_name(pem: &[u8], cert_path: &str) -> Result<String, Box<dyn Error>> {
    let (_, pem) = parse_x509_pem(pem)
        .map_err(|e| format!("{cert_path} is not a valid PEM certificate: {e}"))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| format!("Unable to parse the certificate at {cert_path}: {e}"))?;

    let names = cert
        .subject_alternative_name()?
        .map(|san| san.value.general_names.as_slice())
        .unwrap_or_default();

    let dns = names.iter().find_map(|name| match name {
        GeneralName::DNSName(dns) => Some((*dns).to_owned()),
        _ => None,
    });
    let ip = || {
        names.iter().find_map(|name| match name {
            GeneralName::IPAddress(bytes) => to_ip(bytes).map(|ip| ip.to_string()),
            _ => None,
        })
    };

    dns.or_else(ip).ok_or_else(|| {
        format!(
            "The certificate at {cert_path} has no DNS or IP Subject Alternative Name (SAN), \
             regenerate it with e.g. -addext \"subjectAltName=DNS:orchestrator.example.com\""
        )
        .into()
    })
}

/// Convert the raw bytes of an IP address SAN into an [`IpAddr`].
fn to_ip(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => None,
    }
}