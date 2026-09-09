use ares_net::resolve::resolve_targets;
use ares_net::traceroute;
use ares_plugin_api::{BoxFuture, Capability, Module, ModuleCtx, Permissions};

pub struct PathModule;

impl Module for PathModule {
    fn name(&self) -> &str {
        "path"
    }
    fn description(&self) -> &str {
        "Traceroute / path discovery to targets"
    }
    fn capabilities(&self) -> &[Capability] {
        &[Capability::Discover, Capability::Passive]
    }
    fn permissions(&self) -> Permissions {
        Permissions::default()
    }
    fn run(&self, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let max_hops = ctx
                .extra
                .get("max_hops")
                .and_then(|v| v.as_u64())
                .unwrap_or(30) as u8;
            let resolved = resolve_targets(&ctx.targets)?;
            for t in resolved {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                traceroute::traceroute(t.addr, max_hops, ctx.cancel.clone(), move |e| emit(e))
                    .await?;
            }
            Ok(())
        })
    }
}
