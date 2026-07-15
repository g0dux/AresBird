//! Lightweight JSON webhook POST (http/https) for CI / notify hooks.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;

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

/// POST a JSON body to `url`. Returns HTTP status code when the response parses.
pub async fn post_json(url_str: &str, body: &serde_json::Value) -> anyhow::Result<u16> {
    let url = Url::parse(url_str)?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        anyhow::bail!("webhook URL must be http or https");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("webhook URL missing host"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    let path = {
        let mut p = url.path().to_string();
        if p.is_empty() {
            p = "/".into();
        }
        if let Some(q) = url.query() {
            p.push('?');
            p.push_str(q);
        }
        p
    };
    let payload = serde_json::to_vec(body)?;

    let mut addrs = timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await??;
    let sa: SocketAddr = addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {host}"))?;

    let stream = timeout(Duration::from_secs(8), TcpStream::connect(sa)).await??;

    if scheme == "https" {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(cfg));
        let name = ServerName::try_from(host.clone())
            .map_err(|e| anyhow::anyhow!("bad SNI host: {e}"))?;
        let tls = timeout(Duration::from_secs(8), connector.connect(name, stream)).await??;
        exchange(&host, &path, &payload, tls).await
    } else {
        exchange(&host, &path, &payload, stream).await
    }
}

async fn exchange(
    host: &str,
    path: &str,
    payload: &[u8],
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
) -> anyhow::Result<u16> {
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: AresBird/0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(req.as_bytes()).await?;
    stream.write_all(payload).await?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(8), stream.read(&mut buf)).await??;
    buf.truncate(n);
    let text = String::from_utf8_lossy(&buf);
    let status_line = text.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) && status != 0 {
        anyhow::bail!("webhook HTTP {status}: {status_line}");
    }
    Ok(status)
}
