use ares_core::model::PortState;
use ares_plugin_api::{BoxFuture, Capability, Module, ModuleCtx, Permissions};
use ares_probe::detect_service_ex;

pub struct ServiceModule;

impl Module for ServiceModule {
    fn name(&self) -> &str {
        "service"
    }
    fn description(&self) -> &str {
        "Service detection / banner grabbing on open ports"
    }
    fn capabilities(&self) -> &[Capability] {
        &[Capability::Passive, Capability::Interact]
    }
    fn permissions(&self) -> Permissions {
        Permissions::default()
    }
    fn run(&self, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let open: Vec<(std::net::IpAddr, u16)> = {
                let graph = ctx.graph.lock();
                graph
                    .hosts
                    .iter()
                    .flat_map(|(addr, host)| {
                        host.ports.iter().filter_map(move |(port, p)| {
                            if p.state == PortState::Open {
                                Some((*addr, *port))
                            } else {
                                None
                            }
                        })
                    })
                    .collect()
            };

            let targets = if open.is_empty() {
                let resolved = ares_net::resolve_targets(&ctx.targets)?;
                let ports = if ctx.ports.is_empty() {
                    vec![22, 80, 443, 21, 25, 3306, 8080]
                } else {
                    ctx.ports.clone()
                };
                resolved
                    .into_iter()
                    .flat_map(|t| ports.iter().map(move |p| (t.addr, *p)))
                    .collect::<Vec<_>>()
            } else if ctx.ports.is_empty() {
                open
            } else {
                // open ∩ requested ports (pipeline `ports: open:web` etc.)
                open
                    .into_iter()
                    .filter(|(_, p)| ctx.ports.contains(p))
                    .collect()
            };

            for (addr, port) in targets {
                if ctx.is_cancelled() {
                    break;
                }
                let ttl = {
                    let graph = ctx.graph.lock();
                    graph.hosts.get(&addr).and_then(|h| h.observed_ttl)
                };
                let emit = ctx.emit.clone();
                detect_service_ex(addr, port, None, ttl, move |e| emit(e)).await;
            }
            Ok(())
        })
    }
}
