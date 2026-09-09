//! Active misconfiguration checks (safe, non-exploiting observe probes).

mod http;
mod services;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use ares_plugin_api::{BoxFuture, Capability, Module, ModuleCtx, Permissions};
use ares_proto::http::HttpEngine;

use self::http::build_path_list;

/// Active misconfiguration checks (safe, non-exploiting observe probes).
pub struct ActiveMisconfigModule;

#[derive(Clone)]
struct TargetPort {
    host: String,
    addrs: Vec<IpAddr>,
    port: u16,
}

impl Module for ActiveMisconfigModule {
    fn name(&self) -> &str {
        "active-misconfig"
    }
    fn description(&self) -> &str {
        "Misconfig checks: HTTP/TLS headers+cookies/CORS, path hints, exposed data stores & messaging"
    }
    fn capabilities(&self) -> &[Capability] {
        &[Capability::ActiveTest]
    }
    fn permissions(&self) -> Permissions {
        Permissions {
            outbound_http: true,
            ..Default::default()
        }
    }
    fn run(&self, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let _ = ctx.active_allowed;

            let open: Vec<TargetPort> = {
                let g = ctx.graph.lock();
                let mut grouped: HashMap<(String, u16), Vec<IpAddr>> = HashMap::new();
                for (a, p, _) in g.open_services() {
                    grouped.entry((a.to_string(), p)).or_default().push(a);
                }
                if grouped.is_empty() {
                    let ports = if ctx.ports.is_empty() {
                        vec![
                            21, 80, 88, 161, 389, 443, 1433, 1521, 1883, 2181, 2375, 2379, 3000,
                            3389, 4222, 5601, 5672, 5900, 5984, 5985, 5986, 6379, 6443, 7474, 7687,
                            8080, 8086, 8123, 8200, 8443, 8500, 8983, 9000, 9042, 9090, 9092, 9200,
                            10000, 11211, 15672, 27017, 28015, 4646, 50051, 5701,
                        ]
                    } else {
                        ctx.ports.clone()
                    };
                    for target in &ctx.targets {
                        let host = target
                            .split_once(':')
                            .map(|(h, _)| h.to_string())
                            .unwrap_or_else(|| target.clone());
                        let resolved = ares_net::resolve_targets(std::slice::from_ref(target))?;
                        for t in resolved {
                            for p in &ports {
                                grouped.entry((host.clone(), *p)).or_default().push(t.addr);
                            }
                        }
                    }
                } else if !ctx.ports.is_empty() {
                    // Prefer open ∩ ctx.ports when the pipeline passed a filter.
                    grouped.retain(|(_, p), _| ctx.ports.contains(p));
                }
                let mut v: Vec<TargetPort> = grouped
                    .into_iter()
                    .map(|((host, port), mut addrs)| {
                        let mut seen = HashSet::new();
                        addrs.retain(|a| seen.insert(*a));
                        TargetPort { host, addrs, port }
                    })
                    .collect();
                v.sort_by(|a, b| a.host.cmp(&b.host).then(a.port.cmp(&b.port)));
                v
            };

            let path_gap = Duration::from_millis(
                ctx.extra
                    .get("path_delay_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_else(|| ctx.mode.profile().path_delay_ms),
            );
            let do_paths = ctx
                .extra
                .get("path_probes")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let mut path_list = build_path_list(&ctx)?;
            if ctx.mode.profile().shuffle {
                ares_core::shuffle_inplace(&mut path_list);
            }

            let ua = ctx.mode.http_user_agent().to_string();
            let engine = HttpEngine {
                timeout: Duration::from_secs(8),
                user_agent: ua.clone(),
                ..Default::default()
            };
            // Path probes must not follow redirects (avoids soft-404 false positives).
            let path_engine = HttpEngine {
                timeout: Duration::from_secs(6),
                max_redirects: 0,
                user_agent: ua,
            };

            for tp in open {
                if ctx.is_cancelled() {
                    break;
                }
                let TargetPort { host, addrs, port } = tp;
                if http::check_ports(
                    port,
                    &host,
                    &addrs,
                    &engine,
                    &path_engine,
                    do_paths,
                    &path_list,
                    path_gap,
                    &ctx,
                )
                .await
                {
                    continue;
                }
                let _ = services::check_ports(
                    port,
                    &host,
                    &addrs,
                    &engine,
                    &path_engine,
                    do_paths,
                    &path_list,
                    path_gap,
                    &ctx,
                )
                .await;
            }
            Ok(())
        })
    }
}
