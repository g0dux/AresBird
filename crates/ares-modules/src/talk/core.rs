//! Core talk protocols (DNS/SSH/TLS/H2/SMB/FTP/SMTP).

use std::net::IpAddr;

use ares_plugin_api::ModuleCtx;
use ares_probe::{grab_banner, guess_os_from_banner, guess_os_from_smb};
use ares_proto::dns::DnsEngine;
use ares_proto::http2::{observe_h2_alpn, observe_h2_cleartext};
use ares_proto::smb::smb_negotiate;
use ares_proto::ssh::SshBanner;
use ares_proto::tls_observe::observe_tls;
use url::Url;

use super::{parse_host_port, resolve_one, sni_name_from_target};

pub(crate) async fn run(proto: &str, ctx: &ModuleCtx, target: &str) -> anyhow::Result<()> {
    match proto {
        "dns" => {
            let dns = DnsEngine::system()?;
            let emit = ctx.emit.clone();
            dns.enrich_domain(target, move |e| emit(e)).await;
        }
        "ssh" => {
            let (addr, port) = parse_host_port(target, 22)?;
            let emit = ctx.emit.clone();
            match SshBanner::grab(addr, port, move |e| emit(e)).await {
                Ok(banner) => {
                    let emit = ctx.emit.clone();
                    guess_os_from_banner(addr, &banner, move |e| emit(e));
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk ssh failed: {e}"),
                    });
                }
            }
        }
        "tls" => {
            let (addr, port) = parse_host_port(target, 443)?;
            let sni = sni_name_from_target(target);
            let emit = ctx.emit.clone();
            if let Err(e) = observe_tls(addr, port, sni.as_deref(), move |e| emit(e)).await {
                ctx.emit(ares_core::Event::Log {
                    level: "warn".into(),
                    message: format!("talk tls failed: {e}"),
                });
            }
        }
        "h2" | "http2" => {
            // Prefer TLS ALPN on 443-ish; cleartext prior-knowledge otherwise.
            let default_port = if target.contains(":80") { 80 } else { 443 };
            let (addr, port, sni) = if let Ok(url) = Url::parse(target) {
                let host = url.host_str().unwrap_or("127.0.0.1").to_string();
                let port = url
                    .port_or_known_default()
                    .unwrap_or(if url.scheme() == "http" { 80 } else { 443 });
                let addr = resolve_one(&host).await?;
                let sni = if host.parse::<IpAddr>().is_ok() {
                    None
                } else {
                    Some(host)
                };
                (addr, port, sni)
            } else {
                let (addr, port) = parse_host_port(target, default_port)?;
                (addr, port, None)
            };

            let use_tls = port == 443 || port == 8443 || target.starts_with("https://");
            if use_tls {
                let emit = ctx.emit.clone();
                match observe_h2_alpn(addr, port, sni.as_deref(), move |e| emit(e)).await {
                    Ok(Some(alpn)) => {
                        ctx.emit(ares_core::Event::Log {
                            level: "info".into(),
                            message: format!("talk h2 ALPN={alpn}"),
                        });
                    }
                    Ok(None) => {
                        ctx.emit(ares_core::Event::Log {
                            level: "warn".into(),
                            message: "talk h2: no ALPN result".into(),
                        });
                    }
                    Err(e) => {
                        ctx.emit(ares_core::Event::Log {
                            level: "warn".into(),
                            message: format!("talk h2 failed: {e}"),
                        });
                    }
                }
            } else {
                let emit = ctx.emit.clone();
                match observe_h2_cleartext(addr, port, move |e| emit(e)).await {
                    Ok(true) => {
                        ctx.emit(ares_core::Event::Log {
                            level: "info".into(),
                            message: "talk h2c: SETTINGS ok".into(),
                        });
                    }
                    Ok(false) => {
                        ctx.emit(ares_core::Event::Log {
                            level: "warn".into(),
                            message: "talk h2c: not supported / no SETTINGS".into(),
                        });
                    }
                    Err(e) => {
                        ctx.emit(ares_core::Event::Log {
                            level: "warn".into(),
                            message: format!("talk h2c failed: {e}"),
                        });
                    }
                }
            }
        }
        "smb" => {
            let (addr, port) = parse_host_port(target, 445)?;
            let emit = ctx.emit.clone();
            match smb_negotiate(addr, port, move |e| emit(e)).await {
                Ok(Some(dialect)) => {
                    let emit = ctx.emit.clone();
                    guess_os_from_smb(addr, &dialect, move |e| emit(e));
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk smb: {dialect}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk smb: no SMB dialect detected".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk smb failed: {e}"),
                    });
                }
            }
        }
        "ftp" => {
            let (addr, port) = parse_host_port(target, 21)?;
            let emit = ctx.emit.clone();
            match grab_banner(addr, port, move |e| emit(e)).await {
                Some(banner) => {
                    let emit = ctx.emit.clone();
                    guess_os_from_banner(addr, &banner, move |e| emit(e));
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk ftp: {banner}"),
                    });
                }
                None => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk ftp: empty banner".into(),
                    });
                }
            }
        }
        "smtp" => {
            let (addr, port) = parse_host_port(target, 25)?;
            let emit = ctx.emit.clone();
            match grab_banner(addr, port, move |e| emit(e)).await {
                Some(banner) => {
                    let emit = ctx.emit.clone();
                    guess_os_from_banner(addr, &banner, move |e| emit(e));
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk smtp: {banner}"),
                    });
                }
                None => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk smtp: empty banner".into(),
                    });
                }
            }
        }
        _ => unreachable!("core dispatcher got {proto}"),
    }
    Ok(())
}
