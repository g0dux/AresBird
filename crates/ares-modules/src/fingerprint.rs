use ares_net::resolve::resolve_targets;
use ares_plugin_api::{BoxFuture, Capability, Module, ModuleCtx, Permissions};
use ares_probe::detect_service_ex;

/// Fingerprint: service banners + TLS cert/version/OS hints on selected ports.
pub struct FingerprintModule;

impl Module for FingerprintModule {
    fn name(&self) -> &str {
        "fingerprint"
    }
    fn description(&self) -> &str {
        "TLS + HTTPS + service fingerprint and soft OS hints"
    }
    fn capabilities(&self) -> &[Capability] {
        &[Capability::Passive, Capability::Interact]
    }
    fn permissions(&self) -> Permissions {
        Permissions {
            outbound_http: true,
            dns: true,
            ..Permissions::default()
        }
    }
    fn run(&self, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let ports = if ctx.ports.is_empty() {
                vec![22, 80, 443, 445, 8443]
            } else {
                ctx.ports.clone()
            };
            let resolved = resolve_targets(&ctx.targets)?;
            for t in resolved {
                if ctx.is_cancelled() {
                    break;
                }
                let sni = {
                    let orig = t.original.as_str();
                    if orig.contains('/') || orig.parse::<std::net::IpAddr>().is_ok() {
                        None
                    } else {
                        let host = orig
                            .rsplit_once(':')
                            .and_then(|(h, p)| {
                                if p.parse::<u16>().is_ok() {
                                    Some(h)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(orig);
                        if host.parse::<std::net::IpAddr>().is_ok() {
                            None
                        } else {
                            Some(host.to_string())
                        }
                    }
                };
                for &port in &ports {
                    if ctx.is_cancelled() {
                        break;
                    }
                    let ttl = {
                        let graph = ctx.graph.lock();
                        graph.hosts.get(&t.addr).and_then(|h| h.observed_ttl)
                    };
                    let emit = ctx.emit.clone();
                    detect_service_ex(t.addr, port, sni.as_deref(), ttl, move |e| emit(e)).await;
                }
            }
            Ok(())
        })
    }
}
