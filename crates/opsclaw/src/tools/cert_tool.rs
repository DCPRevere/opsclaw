//! TLS certificate inspection tool.
//!
//! Connects to an endpoint with rustls, grabs the peer certificate chain,
//! and parses the leaf with x509-parser. Also supports parsing a local
//! PEM/DER file.
//!
//! STARTTLS is deferred — only direct TLS (`starttls=none`) is implemented
//! in v1. Adding STARTTLS for SMTP/IMAP/Postgres would require wiring a
//! plain-text upgrade dance before the TLS handshake, which is more than
//! a one-pass change and doesn't block the main use cases (HTTPS, TLS on
//! arbitrary service ports).

use std::fmt::Write as _;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde_json::json;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;
use zeroclaw::tools::traits::{Tool, ToolResult};

const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
const EXPIRES_SOON_THRESHOLD_DAYS: i64 = 30;

pub struct CertTool;

impl CertTool {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CertTool {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct CertSummary {
    subject: String,
    issuer: String,
    serial: String,
    not_before: String,
    not_after: String,
    days_remaining: i64,
    sans_dns: Vec<String>,
    sans_ip: Vec<String>,
    sig_algo: String,
    self_signed: bool,
    chain_length: usize,
}

fn verdict(days_remaining: i64, self_signed: bool) -> &'static str {
    if days_remaining < 0 {
        "EXPIRED"
    } else if self_signed {
        "SELF_SIGNED"
    } else if days_remaining < EXPIRES_SOON_THRESHOLD_DAYS {
        "EXPIRES_SOON"
    } else {
        "OK"
    }
}

fn days_remaining(not_after_unix: i64, now_unix: i64) -> i64 {
    // Floor toward negative infinity so 23h past expiry still reports -1.
    let diff = not_after_unix - now_unix;
    if diff >= 0 {
        diff / 86_400
    } else {
        -((-diff + 86_399) / 86_400)
    }
}

fn format_summary(s: &CertSummary) -> String {
    let mut out = String::new();
    let v = verdict(s.days_remaining, s.self_signed);
    writeln!(out, "verdict: {v}").ok();
    writeln!(out, "subject: {}", s.subject).ok();
    writeln!(out, "issuer: {}", s.issuer).ok();
    writeln!(out, "serial: {}", s.serial).ok();
    writeln!(out, "not_before: {}", s.not_before).ok();
    writeln!(
        out,
        "not_after: {}  (days_remaining: {})",
        s.not_after, s.days_remaining
    )
    .ok();
    writeln!(out, "sans_dns: {}", s.sans_dns.join(", ")).ok();
    writeln!(out, "sans_ip: {}", s.sans_ip.join(", ")).ok();
    writeln!(out, "sig_algo: {}", s.sig_algo).ok();
    writeln!(out, "self_signed: {}", s.self_signed).ok();
    writeln!(out, "chain_length: {}", s.chain_length).ok();
    out
}

fn parse_leaf(leaf_der: &[u8], chain_length: usize, now_unix: i64) -> anyhow::Result<CertSummary> {
    let (_, cert) =
        X509Certificate::from_der(leaf_der).map_err(|e| anyhow::anyhow!("parse error: {e}"))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let self_signed = subject == issuer;
    let serial = cert.tbs_certificate.raw_serial_as_string();

    let nb = cert.validity().not_before;
    let na = cert.validity().not_after;
    let not_before = nb.to_rfc2822().unwrap_or_else(|_| nb.to_string());
    let not_after = na.to_rfc2822().unwrap_or_else(|_| na.to_string());
    let not_after_unix = na.timestamp();

    let mut sans_dns = Vec::new();
    let mut sans_ip = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for gn in &san_ext.value.general_names {
            match gn {
                GeneralName::DNSName(n) => sans_dns.push((*n).to_string()),
                GeneralName::IPAddress(bytes) => sans_ip.push(format_ip(bytes)),
                _ => {}
            }
        }
    }

    let sig_algo = cert.signature_algorithm.algorithm.to_id_string();

    Ok(CertSummary {
        subject,
        issuer,
        serial,
        not_before,
        not_after,
        days_remaining: days_remaining(not_after_unix, now_unix),
        sans_dns,
        sans_ip,
        sig_algo,
        self_signed,
        chain_length,
    })
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => {
            let mut segs = [0u16; 8];
            for i in 0..8 {
                segs[i] = u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
            }
            std::net::Ipv6Addr::new(
                segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
            )
            .to_string()
        }
        _ => hex_string(bytes),
    }
}

fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").ok();
    }
    s
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn load_cert_file(path: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = fs::read(path).map_err(|e| anyhow::anyhow!("read {path}: {e}"))?;
    if let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(&bytes) {
        return Ok(pem.contents);
    }
    Ok(bytes)
}

async fn fetch_chain(
    host: &str,
    port: u16,
    sni: &str,
    timeout: Duration,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // We want to inspect even invalid certs, so disable verification.
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| anyhow::anyhow!("invalid SNI '{sni}': {e}"))?;

    let tcp = tokio::time::timeout(timeout, TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("connect timeout after {}s", timeout.as_secs()))?
        .map_err(|e| anyhow::anyhow!("tcp connect {host}:{port}: {e}"))?;

    let tls = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| anyhow::anyhow!("handshake timeout after {}s", timeout.as_secs()))?
        .map_err(|e| anyhow::anyhow!("TLS handshake: {e}"))?;

    let (_, session) = tls.get_ref();
    let certs = session
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("peer sent no certificates"))?;

    Ok(certs.iter().map(|c| c.as_ref().to_vec()).collect())
}

#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[async_trait]
impl Tool for CertTool {
    fn name(&self) -> &str {
        "cert"
    }

    fn description(&self) -> &str {
        "Inspect a TLS certificate. mode=endpoint (default) connects to \
         host:port and reports the peer chain; mode=file parses a local \
         PEM or DER file. Returns subject, issuer, SANs, validity, \
         days_remaining, signature algorithm, self-signed flag, chain \
         length, and a verdict (OK/EXPIRES_SOON/EXPIRED/SELF_SIGNED). \
         STARTTLS is not supported in v1 — only direct TLS."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "mode": {"type": "string", "enum": ["endpoint", "file"], "default": "endpoint"},
                "host": {"type": "string", "description": "endpoint mode: hostname or IP"},
                "port": {"type": "integer", "default": 443},
                "sni": {"type": "string", "description": "SNI name; defaults to host"},
                "starttls": {
                    "type": "string",
                    "enum": ["none", "smtp", "imap", "postgres"],
                    "default": "none"
                },
                "timeout_secs": {"type": "integer", "default": 10},
                "path": {"type": "string", "description": "file mode: path to PEM or DER file"}
            }
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let mode = args
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("endpoint");

        let now = now_unix();

        match mode {
            "file" => {
                let path = match args.get("path").and_then(|v| v.as_str()) {
                    Some(p) if !p.is_empty() => p,
                    _ => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some("file mode requires 'path'".into()),
                        });
                    }
                };
                let der = match load_cert_file(path) {
                    Ok(b) => b,
                    Err(e) => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(format!("load error: {e}")),
                        });
                    }
                };
                let summary = match parse_leaf(&der, 1, now) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(format!("parse error: {e}")),
                        });
                    }
                };
                Ok(ToolResult {
                    success: true,
                    output: format_summary(&summary),
                    error: None,
                })
            }
            "endpoint" => {
                let starttls = args
                    .get("starttls")
                    .and_then(|v| v.as_str())
                    .unwrap_or("none");
                if starttls != "none" {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!(
                            "starttls='{starttls}' is not supported in v1 (only 'none')"
                        )),
                    });
                }

                let host = match args.get("host").and_then(|v| v.as_str()) {
                    Some(h) if !h.is_empty() => h.to_string(),
                    _ => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some("endpoint mode requires 'host'".into()),
                        });
                    }
                };
                let port = args
                    .get("port")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(443) as u16;
                let sni = args
                    .get("sni")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| host.clone());
                let timeout_secs = args
                    .get("timeout_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(DEFAULT_CONNECT_TIMEOUT_SECS);
                let timeout = Duration::from_secs(timeout_secs);

                let chain = match fetch_chain(&host, port, &sni, timeout).await {
                    Ok(c) => c,
                    Err(e) => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(e.to_string()),
                        });
                    }
                };

                if chain.is_empty() {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some("empty certificate chain".into()),
                    });
                }

                let summary = match parse_leaf(&chain[0], chain.len(), now) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(format!("parse error: {e}")),
                        });
                    }
                };

                Ok(ToolResult {
                    success: true,
                    output: format_summary(&summary),
                    error: None,
                })
            }
            other => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("unknown mode '{other}' (expected endpoint|file)")),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    #[test]
    fn days_remaining_boundaries() {
        let now = 1_700_000_000_i64;
        assert_eq!(days_remaining(now, now), 0);
        assert_eq!(days_remaining(now + DAY, now), 1);
        assert_eq!(days_remaining(now + 29 * DAY, now), 29);
        assert_eq!(days_remaining(now + 31 * DAY, now), 31);
        assert_eq!(days_remaining(now - DAY, now), -1);
        assert_eq!(days_remaining(now - 100, now), -1);
    }

    #[test]
    fn verdict_selection() {
        assert_eq!(verdict(100, false), "OK");
        assert_eq!(verdict(31, false), "OK");
        assert_eq!(verdict(29, false), "EXPIRES_SOON");
        assert_eq!(verdict(0, false), "EXPIRES_SOON");
        assert_eq!(verdict(-1, false), "EXPIRED");
        assert_eq!(verdict(365, true), "SELF_SIGNED");
        // Expired trumps self-signed.
        assert_eq!(verdict(-1, true), "EXPIRED");
    }

    #[test]
    fn parse_self_signed_cert_from_rcgen() {
        let cert = rcgen::generate_simple_self_signed(vec![
            "example.com".into(),
            "www.example.com".into(),
        ])
        .expect("gen");
        let der = cert.cert.der().to_vec();
        let now = now_unix();
        let summary = parse_leaf(&der, 1, now).expect("parse");
        assert!(summary.self_signed, "expected self_signed=true");
        assert!(summary.sans_dns.contains(&"example.com".to_string()));
        assert!(summary.sans_dns.contains(&"www.example.com".to_string()));
        assert!(summary.days_remaining > 0);
        assert_eq!(summary.chain_length, 1);
        let v = verdict(summary.days_remaining, summary.self_signed);
        assert!(v == "SELF_SIGNED" || v == "EXPIRES_SOON" || v == "OK");
    }

    #[test]
    fn tool_metadata() {
        let t = CertTool::new();
        assert_eq!(t.name(), "cert");
        assert!(!t.description().is_empty());
        let schema = t.parameters_schema();
        assert!(schema["properties"]["mode"].is_object());
    }

    #[tokio::test]
    async fn file_mode_requires_path() {
        let t = CertTool::new();
        let r = t.execute(json!({"mode": "file"})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("path"));
    }

    #[tokio::test]
    async fn endpoint_mode_requires_host() {
        let t = CertTool::new();
        let r = t.execute(json!({"mode": "endpoint"})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("host"));
    }

    #[tokio::test]
    async fn unknown_mode_rejected() {
        let t = CertTool::new();
        let r = t.execute(json!({"mode": "banana"})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("unknown mode"));
    }

    #[tokio::test]
    async fn starttls_unsupported() {
        let t = CertTool::new();
        let r = t
            .execute(json!({"mode": "endpoint", "host": "example.com", "starttls": "smtp"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("not supported"));
    }

    #[tokio::test]
    async fn file_mode_rcgen_round_trip() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = cert.cert.pem();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), pem).unwrap();

        let t = CertTool::new();
        let r = t
            .execute(json!({
                "mode": "file",
                "path": tmp.path().to_str().unwrap()
            }))
            .await
            .unwrap();
        assert!(r.success, "error: {:?}", r.error);
        assert!(r.output.contains("self_signed: true"));
        assert!(r.output.contains("localhost"));
    }

    // Real-network endpoint test — keep ignored.
    #[tokio::test]
    #[ignore]
    async fn real_endpoint_cloudflare() {
        let t = CertTool::new();
        let r = t
            .execute(json!({"mode": "endpoint", "host": "one.one.one.one", "port": 443}))
            .await
            .unwrap();
        assert!(r.success, "error: {:?}", r.error);
        assert!(r.output.contains("verdict:"));
    }
}
