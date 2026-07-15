use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ares_core::event::Event;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, ProtocolVersion, SignatureScheme,
};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// Accept any cert — probing only, not for trust decisions.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let _ = end_entity;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn fingerprint_sha256(der: &[u8]) -> String {
    let hash = Sha256::digest(der);
    hash.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn version_label(v: ProtocolVersion) -> &'static str {
    match v {
        ProtocolVersion::TLSv1_3 => "TLS1.3",
        ProtocolVersion::TLSv1_2 => "TLS1.2",
        ProtocolVersion::TLSv1_1 => "TLS1.1",
        ProtocolVersion::TLSv1_0 => "TLS1.0",
        _ => "TLS?",
    }
}

fn build_config(versions: &[&'static rustls::SupportedProtocolVersion], alpn: bool) -> ClientConfig {
    let mut cfg = ClientConfig::builder_with_protocol_versions(versions)
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.enable_sni = true;
    if alpn {
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    cfg
}

fn server_name(addr: IpAddr, sni: Option<&str>) -> ServerName<'static> {
    if let Some(name) = sni {
        if let Ok(sn) = ServerName::try_from(name.to_string()) {
            return sn;
        }
    }
    ServerName::IpAddress(addr.into())
}

struct HandshakeInfo {
    version: Option<&'static str>,
    alpn: Option<String>,
    cipher: Option<String>,
    leaf_der: Option<Vec<u8>>,
}

async fn handshake_once(
    addr: IpAddr,
    port: u16,
    sni: Option<&str>,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: bool,
) -> anyhow::Result<HandshakeInfo> {
    let sa = SocketAddr::new(addr, port);
    let stream = timeout(Duration::from_secs(5), TcpStream::connect(sa)).await??;
    let cfg = build_config(versions, alpn);
    let connector = TlsConnector::from(Arc::new(cfg));
    let name = server_name(addr, sni);
    let tls = timeout(Duration::from_secs(5), connector.connect(name, stream)).await??;
    let (_, connection) = tls.get_ref();
    let version = connection.protocol_version().map(version_label);
    let alpn_s = connection
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned());
    let cipher = connection
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()));
    let leaf_der = connection
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| c.as_ref().to_vec());
    Ok(HandshakeInfo {
        version,
        alpn: alpn_s,
        cipher,
        leaf_der,
    })
}

/// Lightweight DER helpers (no x509-parser — keeps Windows builds stable).
fn printable_strings(der: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < der.len() {
        let tag = der[i];
        // PrintableString(0x13), IA5String(0x16), UTF8String(0x0c), Teletex(0x14)
        if matches!(tag, 0x0c | 0x13 | 0x14 | 0x16) {
            let (len, n) = read_len(&der[i + 1..]);
            let start = i + 1 + n;
            if let Some(l) = len {
                if start + l <= der.len() && l >= 2 && l <= 253 {
                    if let Ok(s) = std::str::from_utf8(&der[start..start + l]) {
                        let t = s.trim();
                        if t.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                            out.push(t.to_string());
                        }
                    }
                    i = start + l;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

fn read_len(bytes: &[u8]) -> (Option<usize>, usize) {
    if bytes.is_empty() {
        return (None, 0);
    }
    let b0 = bytes[0];
    if b0 < 0x80 {
        return (Some(b0 as usize), 1);
    }
    let n = (b0 & 0x7f) as usize;
    if n == 0 || n > 3 || bytes.len() < 1 + n {
        return (None, 1);
    }
    let mut v = 0usize;
    for &b in &bytes[1..1 + n] {
        v = (v << 8) | b as usize;
    }
    (Some(v), 1 + n)
}

fn scrape_dns_sans(der: &[u8]) -> Vec<String> {
    // dNSName is context-specific [2] IA5String → tag 0x82
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < der.len() {
        if der[i] == 0x82 {
            let (len, n) = read_len(&der[i + 1..]);
            let start = i + 1 + n;
            if let Some(l) = len {
                if start + l <= der.len() && (1..=253).contains(&l) {
                    if let Ok(s) = std::str::from_utf8(&der[start..start + l]) {
                        if s.contains('.') || s.starts_with('*') {
                            out.push(s.to_string());
                        }
                    }
                    i = start + l;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

fn scrape_times(der: &[u8]) -> (Option<String>, Option<String>) {
    // UTCTime 0x17 (YYMMDDHHMMSSZ), GeneralizedTime 0x18
    let mut times = Vec::new();
    let mut i = 0;
    while i + 2 < der.len() {
        if der[i] == 0x17 || der[i] == 0x18 {
            let (len, n) = read_len(&der[i + 1..]);
            let start = i + 1 + n;
            if let Some(l) = len {
                if start + l <= der.len() && (11..=20).contains(&l) {
                    if let Ok(s) = std::str::from_utf8(&der[start..start + l]) {
                        if s.ends_with('Z') && s.chars().take(10).all(|c| c.is_ascii_digit()) {
                            times.push(normalize_asn1_time(s));
                        }
                    }
                    i = start + l;
                    continue;
                }
            }
        }
        i += 1;
    }
    let not_before = times.first().cloned();
    let not_after = times.get(1).cloned();
    (not_before, not_after)
}

fn normalize_asn1_time(s: &str) -> String {
    // UTCTime YY… → approximate 20YY
    if s.len() >= 13 && s.len() <= 15 {
        let yy: u32 = s.get(0..2).and_then(|p| p.parse().ok()).unwrap_or(0);
        let century = if yy >= 50 { 19 } else { 20 };
        format!(
            "{century}{}-{}-{}T{}:{}:{}Z",
            &s[0..2],
            &s[2..4],
            &s[4..6],
            &s[6..8],
            &s[8..10],
            &s[10..12]
        )
    } else if s.len() >= 15 {
        // GeneralizedTime YYYYMMDDHHMMSSZ
        format!(
            "{}-{}-{}T{}:{}:{}Z",
            &s[0..4],
            &s[4..6],
            &s[6..8],
            &s[8..10],
            &s[10..12],
            &s[12..14]
        )
    } else {
        s.to_string()
    }
}

fn days_until(iso: &str) -> Option<i64> {
    // Expect YYYY-MM-DD…
    let y: i32 = iso.get(0..4)?.parse().ok()?;
    let m: u32 = iso.get(5..7)?.parse().ok()?;
    let d: u32 = iso.get(8..10)?.parse().ok()?;
    let expiry = chrono::NaiveDate::from_ymd_opt(y, m, d)?;
    let today = chrono::Utc::now().date_naive();
    Some((expiry - today).num_days())
}

fn pick_cn(strings: &[String]) -> String {
    for s in strings {
        let t = s.trim();
        if t.contains('.') && !t.contains(' ') && t.len() >= 3 {
            return t.chars().take(120).collect();
        }
    }
    for s in strings {
        if s.len() >= 3 && s.len() <= 64 {
            return s.chars().take(80).collect();
        }
    }
    "leaf-cert".into()
}

fn emit_cert_analysis(addr: IpAddr, port: u16, der: &[u8], emit: &impl Fn(Event)) {
    let fp = fingerprint_sha256(der);
    let strings = printable_strings(der);
    let subject = pick_cn(&strings);
    // Issuer: often the second distinct org-looking string / later CN
    let issuer = strings
        .iter()
        .rev()
        .find(|s| {
            let l = s.to_lowercase();
            l.contains("authority")
                || l.contains("ca")
                || l.contains("let's encrypt")
                || l.contains("digicert")
                || l.contains("amazon")
                || l.contains("google")
                || l.contains("microsoft")
                || l.contains("cloudflare")
        })
        .cloned()
        .or_else(|| strings.get(1).cloned())
        .unwrap_or_else(|| "unknown-issuer".into());

    let sans = scrape_dns_sans(der);
    let (not_before, not_after) = scrape_times(der);
    let not_after_s = not_after.clone().unwrap_or_else(|| "unknown".into());
    let self_signed = subject.eq_ignore_ascii_case(&issuer);

    emit(Event::TlsCert {
        addr,
        port,
        subject: subject.clone(),
        issuer: issuer.clone(),
        not_after: not_after_s.clone(),
    });

    let san_s = if sans.is_empty() {
        "-".into()
    } else {
        sans.iter().take(8).cloned().collect::<Vec<_>>().join(", ")
    };
    let nb = not_before.unwrap_or_else(|| "-".into());
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "tls-cert".into(),
        detail: format!(
            "subj={subject} issuer={issuer} not_before={nb} not_after={not_after_s} san=[{san_s}] fp={fp}"
        ),
        confidence: 0.9,
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "tls-fp".into(),
        detail: format!("sha256={fp}"),
        confidence: 0.95,
    });

    if self_signed {
        emit(Event::MisconfigFinding {
            addr,
            port: Some(port),
            finding: "TLS certificate looks self-signed".into(),
            severity: "low".into(),
        });
    }

    if let Some(ref na) = not_after {
        match days_until(na) {
            Some(d) if d < 0 => {
                emit(Event::MisconfigFinding {
                    addr,
                    port: Some(port),
                    finding: format!("TLS certificate expired ({na})"),
                    severity: "medium".into(),
                });
            }
            Some(d) if d <= 14 => {
                emit(Event::MisconfigFinding {
                    addr,
                    port: Some(port),
                    finding: format!("TLS certificate expires in {d} day(s) ({na})"),
                    severity: "low".into(),
                });
            }
            _ => {}
        }
    }

    let blob = format!("{subject} {issuer}");
    if let Some((os, conf)) = soft_stack_hint(&blob) {
        emit(Event::OsGuess {
            addr,
            os: os.into(),
            confidence: conf,
            observed_ttl: None,
        });
    }
}

fn soft_stack_hint(text: &str) -> Option<(&'static str, f32)> {
    let t = text.to_lowercase();
    if t.contains("microsoft") || t.contains("azure") {
        return Some(("Windows / Azure TLS stack (cert hint)", 0.35));
    }
    if t.contains("apple") {
        return Some(("Apple / macOS TLS stack (cert hint)", 0.3));
    }
    if t.contains("amazon") || t.contains("amazonaws") {
        return Some(("AWS edge / Amazon TLS (cert hint)", 0.3));
    }
    if t.contains("cloudflare") {
        return Some(("Cloudflare edge (cert hint)", 0.3));
    }
    if t.contains("let's encrypt") || t.contains("letsencrypt") {
        return Some(("Linux/Unix common (Let's Encrypt)", 0.2));
    }
    None
}

/// Full TLS observe: negotiated version/cipher/ALPN, multi-version probe, cert scrape.
pub async fn observe_tls_preview(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<()> {
    observe_tls(addr, port, None, emit).await
}

pub async fn observe_tls(
    addr: IpAddr,
    port: u16,
    sni: Option<&str>,
    emit: impl Fn(Event),
) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let primary = match handshake_once(addr, port, sni, rustls::DEFAULT_VERSIONS, true).await {
        Ok(h) => h,
        Err(e) => {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "tls-handshake".into(),
                detail: format!("handshake failed: {e}"),
                confidence: 0.3,
            });
            return Ok(());
        }
    };

    emit(Event::PortResult {
        addr,
        port,
        state: ares_core::model::PortState::Open,
        protocol: "tcp".into(),
        rtt_ms: None,
    });

    if let Some(v) = primary.version {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "tls-version".into(),
            detail: format!("negotiated={v}"),
            confidence: 0.95,
        });
    }
    if let Some(ref c) = primary.cipher {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "tls-cipher".into(),
            detail: c.clone(),
            confidence: 0.9,
        });
    }
    if let Some(ref proto) = primary.alpn {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "tls-alpn".into(),
            detail: format!("ALPN={proto}"),
            confidence: 0.9,
        });
    }

    let mut offered = Vec::new();
    if handshake_once(addr, port, sni, &[&rustls::version::TLS13], false)
        .await
        .is_ok()
    {
        offered.push("TLS1.3");
    }
    if handshake_once(addr, port, sni, &[&rustls::version::TLS12], false)
        .await
        .is_ok()
    {
        offered.push("TLS1.2");
    }
    if !offered.is_empty() {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "tls-versions".into(),
            detail: format!("offers={}", offered.join(",")),
            confidence: 0.85,
        });
    }

    if let Some(ref der) = primary.leaf_der {
        emit_cert_analysis(addr, port, der, &emit);
        let subject = pick_cn(&printable_strings(der));
        let alpn = primary.alpn.clone();
        let name = match alpn.as_deref() {
            Some("h2") => "http2",
            Some("http/1.1") => "https",
            _ => "ssl/tls",
        };
        let fp = fingerprint_sha256(der);
        emit(Event::ServiceDetected {
            addr,
            port,
            service: ares_core::ServiceInfo {
                name: name.into(),
                product: Some(subject),
                version: primary.version.map(|v| v.to_string()).or(alpn),
                extra: Some(format!("sha256={fp}")),
                confidence: 0.9,
            },
        });
    } else {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "tls-handshake".into(),
            detail: "handshake ok, no peer cert".into(),
            confidence: 0.7,
        });
    }

    if let Some(name) = sni {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "tls-sni".into(),
            detail: format!("sni={name}"),
            confidence: 0.9,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_utctime() {
        let s = normalize_asn1_time("250101120000Z");
        assert!(s.starts_with("2025-01-01"));
    }
}
