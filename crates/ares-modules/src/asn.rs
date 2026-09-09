use ares_plugin_api::{BoxFuture, Capability, Module, ModuleCtx, Permissions};
use ares_proto::asn::AsnEngine;

pub struct AsnModule;

impl Module for AsnModule {
    fn name(&self) -> &str {
        "asn"
    }
    fn description(&self) -> &str {
        "ASN/org lookup (Team Cymru DNS) + PTR/CDN hints"
    }
    fn capabilities(&self) -> &[Capability] {
        &[Capability::Discover, Capability::Passive]
    }
    fn permissions(&self) -> Permissions {
        Permissions {
            dns: true,
            ..Default::default()
        }
    }
    fn run(&self, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let engine = AsnEngine::system()?;
            for target in &ctx.targets {
                if ctx.is_cancelled() {
                    break;
                }
                if let Ok(addr) = target.parse::<std::net::IpAddr>() {
                    let emit = ctx.emit.clone();
                    engine.enrich_host(addr, move |e| emit(e)).await;
                } else {
                    // Treat as hostname — resolve first then enrich
                    if let Ok(iter) = tokio::net::lookup_host((target.as_str(), 0)).await {
                        for sa in iter {
                            if ctx.is_cancelled() {
                                break;
                            }
                            AsnEngine::emit_cdn_for_name(Some(sa.ip()), target, |e| ctx.emit(e));
                            let emit = ctx.emit.clone();
                            engine.enrich_host(sa.ip(), move |e| emit(e)).await;
                        }
                    }
                }
            }
            Ok(())
        })
    }
}
