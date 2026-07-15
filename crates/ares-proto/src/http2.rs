//! HTTP/2 observe — prior-knowledge cleartext + TLS ALPN (no full request/response stack).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ares_core::event::Event;
use ares_core::model::PortState;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

/// Cleartext HTTP/2 prior-knowledge observe (typical on h2c ; rarely exposed publicly).
pub async fn observe_h2_cleartext(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<bool> {
    let sa = SocketAddr::new(addr, port);
    let mut stream = timeout(Duration::from_secs(4), TcpStream::connect(sa)).await??;
    stream.write_all(H2_PREFACE).await?;
    // Empty SETTINGS frame (type=0x4, flags=0, stream=0, length=0)
    stream
        .write_all(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;

    let mut buf = [0u8; 128];
    let n = match timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    let supported = n >= 9 && buf[3] == 0x04;
    let detail = if supported {
        let len = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        format!("h2c SETTINGS reply (len={len}, {n} bytes)")
    } else if n > 0 {
        format!("non-h2 reply ({n} bytes)")
    } else {
        "no h2c reply".into()
    };

    emit(Event::ProbeResult {
        addr,
        port,
        probe: "h2-cleartext".into(),
        detail: detail.clone(),
        confidence: if supported { 0.9 } else { 0.25 },
    });

    if supported {
        emit(Event::PortResult {
            addr,
            port,
            state: PortState::Open,
            protocol: "tcp".into(),
            rtt_ms: None,
        });
        emit(Event::ServiceDetected {
            addr,
            port,
            service: ares_core::ServiceInfo {
                name: "http2".into(),
                product: Some("h2c".into()),
                version: Some("2".into()),
                extra: Some(detail),
                confidence: 0.9,
            },
        });
    }

    Ok(supported)
}

/// TLS handshake advertising ALPN `h2` + `http/1.1` — reports negotiated protocol.
pub async fn observe_h2_alpn(
    addr: IpAddr,
    port: u16,
    server_name: Option<&str>,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let sa = SocketAddr::new(addr, port);
    let stream = timeout(Duration::from_secs(5), TcpStream::connect(sa)).await??;

    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg.enable_sni = server_name.is_some();

    let connector = TlsConnector::from(Arc::new(cfg));
    let name = if let Some(host) = server_name {
        ServerName::try_from(host.to_string())
            .map_err(|e| anyhow::anyhow!("bad SNI: {e}"))?
    } else {
        ServerName::IpAddress(addr.into())
    };

    let tls = match timeout(Duration::from_secs(5), connector.connect(name, stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "h2-alpn".into(),
                detail: format!("tls failed: {e}"),
                confidence: 0.2,
            });
            return Ok(None);
        }
        Err(_) => {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "h2-alpn".into(),
                detail: "tls timeout".into(),
                confidence: 0.2,
            });
            return Ok(None);
        }
    };

    let (_, conn) = tls.get_ref();
    let alpn = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned());

    let detail = match &alpn {
        Some(p) => format!("ALPN negotiated: {p}"),
        None => "TLS ok, no ALPN negotiated".into(),
    };
    let is_h2 = alpn.as_deref() == Some("h2");

    emit(Event::ProbeResult {
        addr,
        port,
        probe: "h2-alpn".into(),
        detail: detail.clone(),
        confidence: if is_h2 { 0.95 } else { 0.6 },
    });

    emit(Event::PortResult {
        addr,
        port,
        state: PortState::Open,
        protocol: "tcp".into(),
        rtt_ms: None,
    });

    if is_h2 {
        emit(Event::ServiceDetected {
            addr,
            port,
            service: ares_core::ServiceInfo {
                name: "http2".into(),
                product: Some("h2".into()),
                version: Some("2".into()),
                extra: Some(detail),
                confidence: 0.95,
            },
        });
    } else if let Some(ref p) = alpn {
        emit(Event::ServiceDetected {
            addr,
            port,
            service: ares_core::ServiceInfo {
                name: if p == "http/1.1" { "https" } else { "ssl/tls" }.into(),
                product: Some(format!("ALPN {p}")),
                version: None,
                extra: None,
                confidence: 0.75,
            },
        });
    }

    Ok(alpn)
}
