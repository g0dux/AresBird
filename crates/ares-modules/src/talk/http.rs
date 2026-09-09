//! HTTP / auto talk path (session + single GET).

use std::net::IpAddr;

use ares_plugin_api::ModuleCtx;
use ares_probe::guess_os_from_banner;
use ares_proto::http::HttpEngine;
use url::Url;

use super::{parse_host_port, resolve_one, sni_name_from_target};

pub(crate) async fn run(ctx: &ModuleCtx, target: &str) -> anyhow::Result<()> {
    let want_session = ctx
        .extra
        .get("session")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut follow_paths: Vec<String> = ctx
        .extra
        .get("follow_paths")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if let Ok(url) = Url::parse(target) {
        let host = url.host_str().unwrap_or("127.0.0.1").to_string();
        let port = url.port_or_known_default().unwrap_or(80);
        let path = {
            let p = url.path();
            if p.is_empty() {
                "/".to_string()
            } else {
                p.to_string()
            }
        };
        let addr = resolve_one(&host).await?;
        let engine = HttpEngine::default();
        let emit = ctx.emit.clone();
        let use_tls = url.scheme() == "https" || port == 443 || port == 8443;
        let sni = if host.parse::<IpAddr>().is_ok() {
            None
        } else {
            Some(host.as_str())
        };

        if want_session {
            let mut paths = vec![path.clone()];
            if follow_paths.is_empty() {
                follow_paths = vec!["/robots.txt".into(), "/login".into()];
            }
            for p in follow_paths {
                let p = if p.starts_with('/') {
                    p
                } else {
                    format!("/{p}")
                };
                if !paths.iter().any(|x| x == &p) {
                    paths.push(p);
                }
            }
            match engine
                .session_browse(addr, port, &host, &paths, use_tls, sni, move |e| emit(e))
                .await
            {
                Ok((sid, jar, resps)) => {
                    if let Some(last) = resps.last() {
                        if let Some((_, server)) = last
                            .headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                        {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, server, move |e| emit(e));
                        }
                    }
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!(
                            "session {sid}: {} path(s), {} cookie(s) — last: {}",
                            paths.len(),
                            jar.len(),
                            resps.last().map(|r| r.status_line.as_str()).unwrap_or("-")
                        ),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk http session failed: {e}"),
                    });
                }
            }
        } else {
            let result = if use_tls {
                engine
                    .get_tls(addr, port, &host, &path, sni, move |e| emit(e))
                    .await
            } else {
                engine.get(addr, port, &host, &path, move |e| emit(e)).await
            };
            match result {
                Ok(resp) => {
                    if let Some((_, server)) = resp
                        .headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                    {
                        let emit = ctx.emit.clone();
                        guess_os_from_banner(addr, server, move |e| emit(e));
                    }
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!(
                            "{} | body preview: {}{}{}",
                            resp.status_line,
                            resp.body_preview.chars().take(120).collect::<String>(),
                            if resp.redirect_chain.len() > 1 {
                                format!(" | redirects: {}", resp.redirect_chain.join(" → "))
                            } else {
                                String::new()
                            },
                            if resp.cookies.is_empty() {
                                String::new()
                            } else {
                                format!(" | cookies={}", resp.cookies.len())
                            }
                        ),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk http failed: {e}"),
                    });
                }
            }
        }
    } else {
        let (addr, port) = parse_host_port(target, 80)?;
        let engine = HttpEngine::default();
        let emit = ctx.emit.clone();
        let sni = sni_name_from_target(target);
        let host = sni.clone().unwrap_or_else(|| addr.to_string());
        let use_tls = port == 443 || port == 8443;
        if want_session {
            let mut paths = vec!["/".into()];
            if follow_paths.is_empty() {
                follow_paths = vec!["/robots.txt".into(), "/login".into()];
            }
            for p in follow_paths {
                let p = if p.starts_with('/') {
                    p
                } else {
                    format!("/{p}")
                };
                if !paths.iter().any(|x| x == &p) {
                    paths.push(p);
                }
            }
            if let Err(e) = engine
                .session_browse(
                    addr,
                    port,
                    &host,
                    &paths,
                    use_tls,
                    sni.as_deref(),
                    move |e| emit(e),
                )
                .await
            {
                ctx.emit(ares_core::Event::Log {
                    level: "warn".into(),
                    message: format!("talk http session failed: {e}"),
                });
            }
        } else {
            let result = if use_tls {
                engine
                    .get_tls(addr, port, &host, "/", sni.as_deref(), move |e| emit(e))
                    .await
            } else {
                engine.get(addr, port, &host, "/", move |e| emit(e)).await
            };
            if let Err(e) = result {
                ctx.emit(ares_core::Event::Log {
                    level: "warn".into(),
                    message: format!("talk http failed: {e}"),
                });
            }
        }
    }
    Ok(())
}
