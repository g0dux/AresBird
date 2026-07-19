use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ares_core::event::Event;
use ares_core::model::PortState;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use uuid::Uuid;

pub struct HttpEngine {
    pub timeout: Duration,
    pub user_agent: String,
    /// Max redirect hops to follow (0 = no follow). Default 5.
    pub max_redirects: u8,
}

impl Default for HttpEngine {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            user_agent: "AresBird/0.1".into(),
            max_redirects: 5,
        }
    }
}

/// Simple in-memory cookie jar for observe sessions (name → value).
#[derive(Debug, Default, Clone)]
pub struct CookieJar {
    map: BTreeMap<String, String>,
}

impl CookieJar {
    pub fn absorb_headers(&mut self, headers: &[(String, String)]) {
        for (k, v) in headers {
            if !k.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            let nv = v.split(';').next().unwrap_or(v).trim();
            if let Some((name, value)) = nv.split_once('=') {
                let name = name.trim();
                if !name.is_empty() {
                    self.map.insert(name.to_string(), value.trim().to_string());
                }
            }
        }
    }

    pub fn cookie_header(&self) -> Option<String> {
        if self.map.is_empty() {
            return None;
        }
        Some(
            self.map
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn names(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    pub fn pairs(&self) -> Vec<(String, String)> {
        self.map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_line: String,
    pub headers: Vec<(String, String)>,
    pub body_preview: String,
    pub title: Option<String>,
    /// Hop URLs visited (including final), when redirects were followed.
    pub redirect_chain: Vec<String>,
    /// Cookies collected during this exchange/session hop.
    pub cookies: Vec<(String, String)>,
}

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

#[derive(Clone)]
struct Hop {
    addr: IpAddr,
    port: u16,
    host: String,
    path: String,
    use_tls: bool,
    sni: Option<String>,
}

impl Hop {
    fn url(&self) -> String {
        let scheme = if self.use_tls { "https" } else { "http" };
        let path = if self.path.starts_with('/') {
            self.path.clone()
        } else {
            format!("/{}", self.path)
        };
        format!("{scheme}://{}:{}{path}", self.host, self.port)
    }
}

impl HttpEngine {
    pub async fn get(
        &self,
        addr: IpAddr,
        port: u16,
        host_header: &str,
        path: &str,
        emit: impl Fn(Event),
    ) -> anyhow::Result<HttpResponse> {
        let mut jar = CookieJar::default();
        self.request_follow(
            Hop {
                addr,
                port,
                host: host_header.to_string(),
                path: path.to_string(),
                use_tls: false,
                sni: None,
            },
            &mut jar,
            true,
            &emit,
        )
        .await
    }

    /// HTTP/1.1 GET over TLS (SNI from hostname when provided).
    pub async fn get_tls(
        &self,
        addr: IpAddr,
        port: u16,
        host_header: &str,
        path: &str,
        sni: Option<&str>,
        emit: impl Fn(Event),
    ) -> anyhow::Result<HttpResponse> {
        let mut jar = CookieJar::default();
        self.request_follow(
            Hop {
                addr,
                port,
                host: host_header.to_string(),
                path: path.to_string(),
                use_tls: true,
                sni: sni.map(|s| s.to_string()),
            },
            &mut jar,
            true,
            &emit,
        )
        .await
    }

    /// Single GET under an existing cookie jar (observe-only). Used by `talk --repl`.
    #[allow(clippy::too_many_arguments)]
    pub async fn session_get(
        &self,
        addr: IpAddr,
        port: u16,
        host_header: &str,
        path: &str,
        use_tls: bool,
        sni: Option<&str>,
        jar: &mut CookieJar,
        emit: impl Fn(Event),
    ) -> anyhow::Result<HttpResponse> {
        let path = if path.is_empty() {
            "/".to_string()
        } else if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        self.request_follow(
            Hop {
                addr,
                port,
                host: host_header.to_string(),
                path,
                use_tls,
                sni: sni.map(|s| s.to_string()),
            },
            jar,
            true,
            &emit,
        )
        .await
    }

    /// Multi-path HTTP browse under one session: shares cookies across redirects + paths.
    ///
    /// Observe-only (GET). Useful for seeing auth walls / sticky cookies after landing.
    #[allow(clippy::too_many_arguments)]
    pub async fn session_browse(
        &self,
        addr: IpAddr,
        port: u16,
        host_header: &str,
        paths: &[String],
        use_tls: bool,
        sni: Option<&str>,
        emit: impl Fn(Event),
    ) -> anyhow::Result<(Uuid, CookieJar, Vec<HttpResponse>)> {
        let session_id = Uuid::new_v4();
        let protocol = if use_tls { "https" } else { "http" };
        emit(Event::SessionOpened {
            session_id,
            addr,
            port,
            protocol: protocol.into(),
        });

        let mut jar = CookieJar::default();
        let mut responses = Vec::new();
        let paths: Vec<String> = if paths.is_empty() {
            vec!["/".into()]
        } else {
            paths.to_vec()
        };

        for (i, path) in paths.iter().enumerate() {
            let resp = self
                .request_follow(
                    Hop {
                        addr,
                        port,
                        host: host_header.to_string(),
                        path: path.clone(),
                        use_tls,
                        sni: sni.map(|s| s.to_string()),
                    },
                    &mut jar,
                    false,
                    &emit,
                )
                .await?;
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "http-session-path".into(),
                detail: format!(
                    "[{}/{}] {} → {}",
                    i + 1,
                    paths.len(),
                    path,
                    resp.status_line
                ),
                confidence: 0.9,
            });
            responses.push(resp);
        }

        if !jar.is_empty() {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "http-session-cookies".into(),
                detail: format!("{} cookie(s): {}", jar.len(), jar.names().join(", ")),
                confidence: 0.9,
            });
        }

        emit(Event::SessionClosed { session_id });
        Ok((session_id, jar, responses))
    }

    async fn request_follow(
        &self,
        start: Hop,
        jar: &mut CookieJar,
        manage_session: bool,
        emit: &impl Fn(Event),
    ) -> anyhow::Result<HttpResponse> {
        let session_id = if manage_session {
            let id = Uuid::new_v4();
            emit(Event::SessionOpened {
                session_id: id,
                addr: start.addr,
                port: start.port,
                protocol: if start.use_tls {
                    "https".into()
                } else {
                    "http".into()
                },
            });
            Some(id)
        } else {
            None
        };

        let mut hop = start;
        let mut chain = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut hops_done = 0u8;
        let mut last: Option<(Hop, RawHttp)> = None;

        loop {
            let url = hop.url();
            if !seen.insert(url.clone()) {
                emit(Event::ProbeResult {
                    addr: hop.addr,
                    port: hop.port,
                    probe: "http-redirect".into(),
                    detail: format!("loop detected at {url}"),
                    confidence: 0.7,
                });
                break;
            }
            chain.push(url);

            let raw = self.single_exchange(&hop, jar, emit).await?;
            let code = status_code(&raw.status_line);

            let should_follow =
                matches!(code, Some(301 | 302 | 303 | 307 | 308)) && hops_done < self.max_redirects;

            if should_follow {
                if let Some(loc) = header_value(&raw.headers, "location") {
                    let from = hop.url();
                    match resolve_redirect(&hop, loc).await {
                        Ok(next) => {
                            hops_done += 1;
                            emit(Event::ProbeResult {
                                addr: hop.addr,
                                port: hop.port,
                                probe: "http-redirect".into(),
                                detail: format!("{} {from} → {}", code.unwrap_or(0), next.url()),
                                confidence: 0.95,
                            });
                            if let Some((_, server)) = raw
                                .headers
                                .iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                            {
                                emit(Event::Banner {
                                    addr: hop.addr,
                                    port: hop.port,
                                    banner: format!("HTTP Server: {server}"),
                                });
                            }
                            last = Some((hop.clone(), raw));
                            hop = next;
                            continue;
                        }
                        Err(e) => {
                            emit(Event::ProbeResult {
                                addr: hop.addr,
                                port: hop.port,
                                probe: "http-redirect".into(),
                                detail: format!("bad Location `{loc}`: {e}"),
                                confidence: 0.4,
                            });
                        }
                    }
                }
            }

            last = Some((hop.clone(), raw));
            break;
        }

        let (final_hop, raw) = last.ok_or_else(|| anyhow::anyhow!("no HTTP response"))?;
        emit_http_observations(
            final_hop.addr,
            final_hop.port,
            if final_hop.use_tls { "https" } else { "http" },
            &raw.status_line,
            &raw.headers,
            &raw.title,
            emit,
        );
        if chain.len() > 1 {
            emit(Event::ProbeResult {
                addr: final_hop.addr,
                port: final_hop.port,
                probe: "http-redirect-chain".into(),
                detail: chain.join(" → "),
                confidence: 0.9,
            });
        }

        if let Some(id) = session_id {
            if !jar.is_empty() {
                emit(Event::ProbeResult {
                    addr: final_hop.addr,
                    port: final_hop.port,
                    probe: "http-cookies".into(),
                    detail: format!("{} cookie(s): {}", jar.len(), jar.names().join(", ")),
                    confidence: 0.85,
                });
            }
            emit(Event::SessionClosed { session_id: id });
        }

        Ok(HttpResponse {
            status_line: raw.status_line,
            headers: raw.headers,
            body_preview: raw.body_preview,
            title: raw.title,
            redirect_chain: chain,
            cookies: jar.pairs(),
        })
    }

    async fn single_exchange(
        &self,
        hop: &Hop,
        jar: &mut CookieJar,
        emit: &impl Fn(Event),
    ) -> anyhow::Result<RawHttp> {
        let sa = SocketAddr::new(hop.addr, hop.port);
        let stream = timeout(self.timeout, TcpStream::connect(sa)).await??;
        let cookie = jar.cookie_header();
        let raw = if hop.use_tls {
            self.exchange_tls(hop, stream, cookie.as_deref(), emit)
                .await?
        } else {
            self.exchange_plain(hop, stream, cookie.as_deref(), emit)
                .await?
        };
        jar.absorb_headers(&raw.headers);
        Ok(raw)
    }

    async fn exchange_plain(
        &self,
        hop: &Hop,
        stream: TcpStream,
        cookie: Option<&str>,
        emit: &impl Fn(Event),
    ) -> anyhow::Result<RawHttp> {
        self.exchange_io(
            hop.addr, hop.port, &hop.host, &hop.path, "http", stream, cookie, emit,
        )
        .await
    }

    async fn exchange_tls(
        &self,
        hop: &Hop,
        stream: TcpStream,
        cookie: Option<&str>,
        emit: &impl Fn(Event),
    ) -> anyhow::Result<RawHttp> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

        let sni_host = hop.sni.clone().or_else(|| {
            if hop.host.parse::<IpAddr>().is_err() && hop.host.contains('.') {
                Some(hop.host.clone())
            } else {
                None
            }
        });
        cfg.enable_sni = sni_host.is_some();

        let connector = TlsConnector::from(Arc::new(cfg));
        let name = if let Some(host) = sni_host.as_deref() {
            ServerName::try_from(host.to_string()).map_err(|e| anyhow::anyhow!("bad SNI: {e}"))?
        } else {
            ServerName::IpAddress(hop.addr.into())
        };

        let tls = timeout(self.timeout, connector.connect(name, stream)).await??;
        let (_, conn) = tls.get_ref();
        if let Some(alpn) = conn.alpn_protocol() {
            emit(Event::ProbeResult {
                addr: hop.addr,
                port: hop.port,
                probe: "tls-alpn".into(),
                detail: format!("ALPN={}", String::from_utf8_lossy(alpn)),
                confidence: 0.9,
            });
        }
        self.exchange_io(
            hop.addr, hop.port, &hop.host, &hop.path, "https", tls, cookie, emit,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn exchange_io(
        &self,
        addr: IpAddr,
        port: u16,
        host_header: &str,
        path: &str,
        protocol: &str,
        mut stream: impl AsyncRead + AsyncWrite + Unpin,
        cookie: Option<&str>,
        _emit: &impl Fn(Event),
    ) -> anyhow::Result<RawHttp> {
        let _ = (addr, port, protocol);
        let path = if path.is_empty() { "/" } else { path };
        let mut req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {}\r\nConnection: close\r\nAccept: text/html,application/xhtml+xml,*/*\r\n",
            self.user_agent
        );
        if let Some(c) = cookie {
            if !c.is_empty() {
                req.push_str("Cookie: ");
                req.push_str(c);
                req.push_str("\r\n");
            }
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).await?;

        let mut buf = vec![0u8; 16384];
        let n = timeout(self.timeout, stream.read(&mut buf)).await??;
        buf.truncate(n);
        let text = String::from_utf8_lossy(&buf);

        let mut lines = text.split("\r\n");
        let status_line = lines.next().unwrap_or("").to_string();
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        let body_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(text.len());
        let body_preview: String = text[body_start..].chars().take(800).collect();
        let title = extract_html_title(&body_preview);

        Ok(RawHttp {
            status_line,
            headers,
            body_preview,
            title,
        })
    }
}

#[derive(Debug, Clone)]
struct RawHttp {
    status_line: String,
    headers: Vec<(String, String)>,
    body_preview: String,
    title: Option<String>,
}

fn status_code(status_line: &str) -> Option<u16> {
    status_line.split_whitespace().nth(1)?.parse().ok()
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

async fn resolve_redirect(from: &Hop, location: &str) -> anyhow::Result<Hop> {
    let base = url::Url::parse(&from.url())?;
    let next = base.join(location.trim())?;
    let scheme = next.scheme();
    let use_tls = match scheme {
        "https" => true,
        "http" => false,
        other => anyhow::bail!("unsupported redirect scheme: {other}"),
    };
    let host = next
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("redirect missing host"))?
        .to_string();
    let port = next
        .port_or_known_default()
        .unwrap_or(if use_tls { 443 } else { 80 });
    let path = {
        let mut p = next.path().to_string();
        if let Some(q) = next.query() {
            p.push('?');
            p.push_str(q);
        }
        if p.is_empty() {
            "/".into()
        } else {
            p
        }
    };

    let addr = if let Ok(ip) = host.parse::<IpAddr>() {
        ip
    } else {
        tokio::net::lookup_host((host.as_str(), port))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("resolve failed for {host}"))?
            .ip()
    };

    let sni = if host.parse::<IpAddr>().is_ok() {
        None
    } else {
        Some(host.clone())
    };

    Ok(Hop {
        addr,
        port,
        host,
        path,
        use_tls,
        sni,
    })
}

fn emit_http_observations(
    addr: IpAddr,
    port: u16,
    protocol: &str,
    status_line: &str,
    headers: &[(String, String)],
    title: &Option<String>,
    emit: &impl Fn(Event),
) {
    if let Some((_, server)) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("server"))
    {
        emit(Event::Banner {
            addr,
            port,
            banner: format!("HTTP Server: {server}"),
        });
    }
    for key in [
        "x-powered-by",
        "via",
        "www-authenticate",
        "content-type",
        "x-frame-options",
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ] {
        if let Some((_, v)) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)) {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: format!("http-header:{key}"),
                detail: v.chars().take(160).collect(),
                confidence: 0.8,
            });
        }
    }
    let looks_ok =
        status_line.contains("200") || status_line.contains("301") || status_line.contains("302");
    if looks_ok {
        for missing in [
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
        ] {
            let present = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(missing));
            if !present {
                emit(Event::ProbeResult {
                    addr,
                    port,
                    probe: "http-sec-missing".into(),
                    detail: missing.into(),
                    confidence: 0.45,
                });
            }
        }
    }
    if let Some(t) = title {
        emit(Event::Banner {
            addr,
            port,
            banner: format!("HTML title: {t}"),
        });
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "http-title".into(),
            detail: t.clone(),
            confidence: 0.85,
        });
    }

    emit(Event::PortResult {
        addr,
        port,
        state: PortState::Open,
        protocol: "tcp".into(),
        rtt_ms: None,
    });

    emit(Event::ProbeResult {
        addr,
        port,
        probe: if protocol == "https" {
            "https-get".into()
        } else {
            "http-get".into()
        },
        detail: status_line.to_string(),
        confidence: 0.9,
    });

    if let Some(t) = title {
        emit(Event::ServiceDetected {
            addr,
            port,
            service: ares_core::ServiceInfo {
                name: if protocol == "https" {
                    "https".into()
                } else {
                    "http".into()
                },
                product: headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                    .map(|(_, v)| v.clone()),
                version: None,
                extra: Some(format!("title={t}")),
                confidence: 0.9,
            },
        });
    }
}

/// Security-header assessment shared by HTTP observe and active-misconfig.
#[derive(Debug, Clone)]
pub struct SecHeaderFinding {
    pub message: String,
    pub severity: &'static str,
}

pub fn assess_security_headers(headers: &[(String, String)], https: bool) -> Vec<SecHeaderFinding> {
    let lower: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();
    let has = |name: &str| lower.iter().any(|(k, _)| k == name);
    let mut out = Vec::new();

    let checks: &[(&str, &str, bool)] = &[
        (
            "strict-transport-security",
            "Missing security header: strict-transport-security",
            true,
        ),
        (
            "x-content-type-options",
            "Missing security header: x-content-type-options",
            false,
        ),
        (
            "x-frame-options",
            "Missing security header: x-frame-options (or CSP frame-ancestors)",
            false,
        ),
        (
            "content-security-policy",
            "Missing security header: content-security-policy",
            false,
        ),
        (
            "referrer-policy",
            "Missing security header: referrer-policy",
            false,
        ),
        (
            "permissions-policy",
            "Missing security header: permissions-policy",
            false,
        ),
    ];

    for (name, msg, https_only) in checks {
        if *https_only && !https {
            if *name == "strict-transport-security" {
                out.push(SecHeaderFinding {
                    message: "HTTP cleartext — HSTS not applicable (prefer TLS)".into(),
                    severity: "info",
                });
            }
            continue;
        }
        if !has(name) {
            if *name == "x-frame-options" {
                if let Some((_, csp)) = lower.iter().find(|(k, _)| k == "content-security-policy") {
                    if csp.to_lowercase().contains("frame-ancestors") {
                        continue;
                    }
                }
            }
            let severity = if *https_only { "medium" } else { "info" };
            out.push(SecHeaderFinding {
                message: (*msg).into(),
                severity,
            });
        }
    }

    if let Some((_, hsts)) = lower.iter().find(|(k, _)| k == "strict-transport-security") {
        if https && !hsts.to_lowercase().contains("max-age=") {
            out.push(SecHeaderFinding {
                message: "HSTS present but missing max-age".into(),
                severity: "low",
            });
        }
    }
    if let Some((_, xcto)) = lower.iter().find(|(k, _)| k == "x-content-type-options") {
        if !xcto.eq_ignore_ascii_case("nosniff") {
            out.push(SecHeaderFinding {
                message: format!("Weak X-Content-Type-Options: {xcto}"),
                severity: "low",
            });
        }
    }

    // Technology / stack disclosure
    for (name, label) in [
        ("x-powered-by", "X-Powered-By"),
        ("x-aspnet-version", "X-AspNet-Version"),
        ("x-aspnetmvc-version", "X-AspNetMvc-Version"),
    ] {
        if let Some((_, v)) = lower.iter().find(|(k, _)| k == name) {
            out.push(SecHeaderFinding {
                message: format!("Stack disclosure via {label}: {v}"),
                severity: "info",
            });
        }
    }

    // Permissive CORS
    if let Some((_, acao)) = lower
        .iter()
        .find(|(k, _)| k == "access-control-allow-origin")
    {
        if acao.trim() == "*" {
            let creds = lower
                .iter()
                .find(|(k, _)| k == "access-control-allow-credentials")
                .map(|(_, v)| v.to_ascii_lowercase().contains("true"))
                .unwrap_or(false);
            out.push(SecHeaderFinding {
                message: if creds {
                    "CORS Access-Control-Allow-Origin: * with credentials (misconfig)".into()
                } else {
                    "CORS Access-Control-Allow-Origin: * (permissive)".into()
                },
                severity: if creds { "medium" } else { "low" },
            });
        }
    }

    // Cookie attribute hygiene (observe Set-Cookie only)
    for (k, v) in &lower {
        if k != "set-cookie" {
            continue;
        }
        let attrs = v.to_ascii_lowercase();
        let name = v.split('=').next().unwrap_or("cookie").trim();
        if https && !attrs.contains("secure") {
            out.push(SecHeaderFinding {
                message: format!("Cookie `{name}` missing Secure flag on HTTPS"),
                severity: "medium",
            });
        }
        if !attrs.contains("httponly") {
            out.push(SecHeaderFinding {
                message: format!("Cookie `{name}` missing HttpOnly flag"),
                severity: "low",
            });
        }
        if !attrs.contains("samesite") {
            out.push(SecHeaderFinding {
                message: format!("Cookie `{name}` missing SameSite attribute"),
                severity: "info",
            });
        }
    }

    out
}

fn extract_html_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let start = lower.find("<title")?;
    let after = &body[start..];
    let after_l = &lower[start..];
    let open_end = after_l.find('>')? + 1;
    let rest = &after[open_end..];
    let rest_l = &after_l[open_end..];
    let close = rest_l.find("</title>")?;
    let title = rest[..close]
        .replace(['\n', '\r'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if title.is_empty() {
        None
    } else {
        Some(title.chars().take(120).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_code() {
        assert_eq!(status_code("HTTP/1.1 301 Moved Permanently"), Some(301));
        assert_eq!(status_code("HTTP/1.0 200 OK"), Some(200));
    }

    #[tokio::test]
    async fn relative_redirect_keeps_host() {
        let from = Hop {
            addr: "127.0.0.1".parse().unwrap(),
            port: 80,
            host: "example.com".into(),
            path: "/a".into(),
            use_tls: false,
            sni: Some("example.com".into()),
        };
        let next = resolve_redirect(&from, "/b?x=1").await.unwrap();
        assert_eq!(next.host, "example.com");
        assert_eq!(next.path, "/b?x=1");
        assert!(!next.use_tls);
    }

    #[tokio::test]
    async fn absolute_https_redirect() {
        let from = Hop {
            addr: "127.0.0.1".parse().unwrap(),
            port: 80,
            host: "example.com".into(),
            path: "/".into(),
            use_tls: false,
            sni: None,
        };
        // Use a literal IP so CI does not depend on external DNS.
        let next = resolve_redirect(&from, "https://127.0.0.1/login")
            .await
            .unwrap();
        assert!(next.use_tls);
        assert_eq!(next.port, 443);
        assert_eq!(next.host, "127.0.0.1");
        assert_eq!(next.path, "/login");
        assert_eq!(next.addr.to_string(), "127.0.0.1");
    }
}