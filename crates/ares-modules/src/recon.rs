use ares_net::connect::{ConnectScanner, ScanConfig};
use ares_plugin_api::{BoxFuture, Capability, Module, ModuleCtx, Permissions};
use ares_probe::detect_service;
use ares_proto::asn::AsnEngine;
use ares_proto::dns::DnsEngine;

pub struct ReconModule;

impl Module for ReconModule {
    fn name(&self) -> &str {
        "recon"
    }
    fn description(&self) -> &str {
        "DNS enrichment + subdomain enum + ASN/CDN + optional port skim"
    }
    fn capabilities(&self) -> &[Capability] {
        &[Capability::Discover, Capability::Scan]
    }
    fn permissions(&self) -> Permissions {
        Permissions {
            dns: true,
            ..Default::default()
        }
    }
    fn run(&self, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let dns = DnsEngine::system()?;
            let asn_engine = AsnEngine::system()?;
            let emit = ctx.emit.clone();
            let mut all_ips = Vec::new();

            for target in &ctx.targets {
                if ctx.is_cancelled() {
                    break;
                }
                if let Ok(addr) = target.parse::<std::net::IpAddr>() {
                    all_ips.push(addr);
                    continue;
                }
                AsnEngine::emit_cdn_for_name(None, target, |e| emit(e));
                let emit2 = emit.clone();
                let ips = dns.enrich_domain(target, move |e| emit2(e)).await;
                all_ips.extend(ips);
            }

            all_ips.sort();
            all_ips.dedup();

            // ASN/CDN for each discovered IP
            for &addr in &all_ips {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                asn_engine.enrich_host(addr, move |e| emit(e)).await;
            }

            // CDN from DNS records already in graph
            {
                let g = ctx.graph.lock();
                for (name, values) in &g.dns {
                    for v in values {
                        AsnEngine::emit_cdn_for_name(None, name, |e| ctx.emit(e));
                        AsnEngine::emit_cdn_for_name(None, v, |e| ctx.emit(e));
                    }
                }
            }

            let skim = ctx
                .extra
                .get("skim_ports")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            if skim && !all_ips.is_empty() && !ctx.is_cancelled() {
                let ports = if ctx.ports.is_empty() {
                    ares_core::TOP100.to_vec()
                } else {
                    ctx.ports.clone()
                };
                let pairs: Vec<_> = all_ips
                    .iter()
                    .flat_map(|a| ports.iter().map(move |p| (*a, *p)))
                    .collect();
                let scanner = ConnectScanner::new(ScanConfig::from_timing(ctx.mode.profile()));
                let emit = ctx.emit.clone();
                scanner
                    .scan_emit(&pairs, ctx.cancel.clone(), move |e| emit(e))
                    .await;

                let open = {
                    let g = ctx.graph.lock();
                    g.open_services()
                        .into_iter()
                        .map(|(a, p, _)| (a, p))
                        .collect::<Vec<_>>()
                };
                for (addr, port) in open {
                    if ctx.is_cancelled() {
                        break;
                    }
                    let emit = ctx.emit.clone();
                    detect_service(addr, port, move |e| emit(e)).await;
                }
            }
            Ok(())
        })
    }
}
