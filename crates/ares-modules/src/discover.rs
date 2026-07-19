use ares_core::Event;
use ares_net::discover::host_discover_opts;
use ares_net::resolve::resolve_targets;
use ares_plugin_api::{BoxFuture, Capability, Module, ModuleCtx, Permissions};
use ares_probe::guess_os_from_ttl_rtt;

pub struct DiscoverModule;

impl Module for DiscoverModule {
    fn name(&self) -> &str {
        "discover"
    }
    fn description(&self) -> &str {
        "Host discovery (ICMP/TCP; optional ARP with Linux+raw)"
    }
    fn capabilities(&self) -> &[Capability] {
        &[Capability::Discover]
    }
    fn permissions(&self) -> Permissions {
        Permissions {
            raw_socket: true,
            ..Permissions::default()
        }
    }
    fn run(&self, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let resolved = resolve_targets(&ctx.targets)?;
            let addrs: Vec<_> = resolved.iter().map(|t| t.addr).collect();
            let timing = ctx.mode.profile();
            let timeout_ms = timing.timeout.as_millis() as u64;
            let jitter_ms = timing.jitter_ms;
            let shuffle = timing.shuffle;
            let rate_pps = timing.rate_pps;
            let concurrency = timing.concurrency;
            let prefer_arp = ctx
                .extra
                .get("arp")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let probe_ports = if ctx.ports.is_empty() {
                Vec::new()
            } else {
                ctx.ports.clone()
            };
            let emit = ctx.emit.clone();
            host_discover_opts(
                &addrs,
                &probe_ports,
                timeout_ms,
                prefer_arp,
                jitter_ms,
                shuffle,
                rate_pps,
                concurrency,
                ctx.cancel.clone(),
                move |e| {
                    if let Event::HostUp {
                        addr, latency_ms, ..
                    } = &e
                    {
                        let emit_os = emit.clone();
                        guess_os_from_ttl_rtt(*addr, *latency_ms, move |oe| emit_os(oe));
                    }
                    emit(e);
                },
            )
            .await;
            Ok(())
        })
    }
}
