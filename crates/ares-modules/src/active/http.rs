//! HTTP/TLS surface checks for active-misconfig.

use std::net::IpAddr;
use std::time::Duration;

use ares_core::event::Event;
use ares_plugin_api::ModuleCtx;
use ares_proto::http::{assess_security_headers, HttpEngine, HttpResponse};
use ares_proto::tls_observe::observe_tls_preview;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

use crate::paths::{self, PathProfile};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn check_ports(
    port: u16,
    host: &str,
    addrs: &[IpAddr],
    engine: &HttpEngine,
    path_engine: &HttpEngine,
    do_paths: bool,
    path_list: &[String],
    path_gap: Duration,
    ctx: &ModuleCtx,
) -> bool {
    match port {
        80 | 8000 | 8888 | 8008 | 5000 | 81 => {
            let mut done = false;
            for addr in addrs {
                if ctx.is_cancelled() || done {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(resp) = engine.get(*addr, port, host, "/", move |e| emit(e)).await {
                    assess_http_surface(
                        *addr,
                        port,
                        false,
                        host,
                        &resp,
                        path_engine,
                        do_paths,
                        path_list,
                        path_gap,
                        ctx,
                    )
                    .await;
                    done = true;
                }
            }
        }
        8080 => {
            let mut done = false;
            for addr in addrs {
                if ctx.is_cancelled() || done {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_jenkins(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("Jenkins exposed ({detail})"),
                        severity: "medium".into(),
                    });
                    done = true;
                    continue;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_keycloak(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("Keycloak exposed ({detail})"),
                        severity: "high".into(),
                    });
                    done = true;
                    continue;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_argocd(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("Argo CD exposed ({detail})"),
                        severity: "high".into(),
                    });
                    done = true;
                    continue;
                }
                let emit_http = ctx.emit.clone();
                if let Ok(resp) = engine
                    .get(*addr, port, host, "/", move |e| emit_http(e))
                    .await
                {
                    assess_http_surface(
                        *addr,
                        port,
                        false,
                        host,
                        &resp,
                        path_engine,
                        do_paths,
                        path_list,
                        path_gap,
                        ctx,
                    )
                    .await;
                    done = true;
                }
            }
        }
        443 | 8443 => {
            let mut done = false;
            for addr in addrs {
                if ctx.is_cancelled() || done {
                    break;
                }
                let emit = ctx.emit.clone();
                let _ = observe_tls_preview(*addr, port, move |e| emit(e)).await;

                let sni = if host.parse::<IpAddr>().is_ok() {
                    None
                } else {
                    Some(host)
                };
                let emit = ctx.emit.clone();
                match engine
                    .get_tls(*addr, port, host, "/", sni, move |e| emit(e))
                    .await
                {
                    Ok(resp) => {
                        assess_http_surface(
                            *addr,
                            port,
                            true,
                            host,
                            &resp,
                            path_engine,
                            do_paths,
                            path_list,
                            path_gap,
                            ctx,
                        )
                        .await;
                        done = true;
                    }
                    Err(e) => {
                        ctx.emit(Event::Log {
                            level: "info".into(),
                            message: format!(
                                "{host}/{addr}:{port} HTTPS GET failed ({e}), trying next peer…"
                            ),
                        });
                    }
                }
            }
            if !done {
                ctx.emit(Event::Log {
                    level: "warn".into(),
                    message: format!(
                        "{host}:{port} HTTPS GET failed on all {} peer(s)",
                        addrs.len()
                    ),
                });
            }
        }
        _ => return false,
    }
    true
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn assess_http_surface(
    addr: IpAddr,
    port: u16,
    https: bool,
    host: &str,
    resp: &HttpResponse,
    path_engine: &HttpEngine,
    do_paths: bool,
    paths: &[String],
    path_gap: Duration,
    ctx: &ModuleCtx,
) {
    emit_header_findings(addr, port, https, &resp.headers, ctx);
    if let Some((_, server)) = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("server"))
    {
        if looks_versioned_disclosure(server) {
            ctx.emit(Event::MisconfigFinding {
                addr,
                port: Some(port),
                finding: format!("Server version disclosed: {server}"),
                severity: "info".into(),
            });
        }
    }
    if resp.body_preview.to_lowercase().contains("index of /") {
        ctx.emit(Event::MisconfigFinding {
            addr,
            port: Some(port),
            finding: "Possible directory listing enabled".into(),
            severity: "medium".into(),
        });
    }

    // TRACE can enable XST / information disclosure when enabled.
    if let Ok(true) = probe_http_trace(addr, port, https, host).await {
        ctx.emit(Event::MisconfigFinding {
            addr,
            port: Some(port),
            finding: "HTTP TRACE method enabled".into(),
            severity: "low".into(),
        });
    }

    if !do_paths || !should_probe_paths(&resp.status_line) {
        if do_paths {
            ctx.emit(Event::Log {
                level: "info".into(),
                message: format!(
                    "{host}:{port} skip path probes (root status: {})",
                    resp.status_line.chars().take(40).collect::<String>()
                ),
            });
        }
        return;
    }

    ctx.emit(Event::Log {
        level: "info".into(),
        message: format!("{host}:{port} path probes: {} path(s)", paths.len()),
    });

    for path in paths {
        if ctx.is_cancelled() {
            break;
        }
        sleep(path_gap).await;
        let emit = ctx.emit.clone();
        let result = if https {
            let sni = if host.parse::<IpAddr>().is_ok() {
                None
            } else {
                Some(host)
            };
            path_engine
                .get_tls(addr, port, host, path, sni, move |e| emit(e))
                .await
        } else {
            path_engine
                .get(addr, port, host, path, move |e| emit(e))
                .await
        };
        match result {
            Ok(r) => {
                if paths::sensitive_path_hit(path, &r.status_line, &r.body_preview) {
                    let sev = paths::path_severity(path);
                    ctx.emit(Event::MisconfigFinding {
                        addr,
                        port: Some(port),
                        finding: format!(
                            "Sensitive path may be exposed: {path} ({})",
                            r.status_line.chars().take(48).collect::<String>()
                        ),
                        severity: sev.into(),
                    });
                }
                if r.status_line.contains("403")
                    || r.status_line.contains("429")
                    || r.status_line.contains("503")
                {
                    ctx.emit(Event::Log {
                        level: "info".into(),
                        message: format!("{host}:{port} stop path probes after {}", r.status_line),
                    });
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

pub(crate) fn build_path_list(ctx: &ModuleCtx) -> anyhow::Result<Vec<String>> {
    let profile = ctx
        .extra
        .get("path_profile")
        .and_then(|v| v.as_str())
        .and_then(PathProfile::parse)
        .unwrap_or(PathProfile::Default);

    let mut list: Vec<String> = profile.paths().into_iter().map(|s| s.to_string()).collect();

    if let Some(file) = ctx.extra.get("paths_file").and_then(|v| v.as_str()) {
        let extra = paths::load_paths_file(std::path::Path::new(file))?;
        for p in extra {
            if !list.contains(&p) {
                list.push(p);
            }
        }
    }

    if let Some(arr) = ctx.extra.get("paths").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(s) = v.as_str() {
                let p = if s.starts_with('/') {
                    s.to_string()
                } else {
                    format!("/{s}")
                };
                if !list.contains(&p) {
                    list.push(p);
                }
            }
        }
    }

    Ok(list)
}

fn should_probe_paths(status_line: &str) -> bool {
    status_line.contains("200")
        || status_line.contains("301")
        || status_line.contains("302")
        || status_line.contains("304")
}

fn emit_header_findings(
    addr: IpAddr,
    port: u16,
    https: bool,
    headers: &[(String, String)],
    ctx: &ModuleCtx,
) {
    for finding in assess_security_headers(headers, https) {
        ctx.emit(Event::MisconfigFinding {
            addr,
            port: Some(port),
            finding: finding.message,
            severity: finding.severity.into(),
        });
    }
}

fn looks_versioned_disclosure(server: &str) -> bool {
    let s = server.to_lowercase();
    s.contains('/')
        && (s.contains("apache")
            || s.contains("nginx")
            || s.contains("iis")
            || s.contains("tomcat")
            || s.contains("jetty")
            || s.contains("openresty"))
}

/// Cleartext TRACE probe (skip TLS — keep misconfig cheap/safe).
async fn probe_http_trace(
    addr: IpAddr,
    port: u16,
    https: bool,
    host: &str,
) -> anyhow::Result<bool> {
    if https {
        return Ok(false);
    }
    let sa = std::net::SocketAddr::new(addr, port);
    let mut stream = timeout(Duration::from_secs(2), TcpStream::connect(sa)).await??;
    let req = format!(
        "TRACE / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    timeout(Duration::from_secs(2), stream.write_all(req.as_bytes())).await??;
    let mut buf = [0u8; 1024];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    if n == 0 {
        return Ok(false);
    }
    let text = String::from_utf8_lossy(&buf[..n]);
    let ok = text.contains("200")
        && (text.to_ascii_lowercase().contains("trace /") || text.contains("TRACE /"));
    Ok(ok)
}
