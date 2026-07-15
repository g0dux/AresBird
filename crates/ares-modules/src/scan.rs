use ares_net::discover::host_discover_opts;
use ares_net::resolve::resolve_targets;
use ares_net::udp::{UdpScanner, UDP_TOP};
use ares_net::{scan_with_engine, ScanEngineKind};
use ares_plugin_api::{BoxFuture, Capability, Module, ModuleCtx};
use std::collections::HashSet;
use std::net::IpAddr;

pub struct ScanModule;

impl Module for ScanModule {
    fn name(&self) -> &str {
        "scan"
    }
    fn description(&self) -> &str {
        "High-performance TCP port scanner (connect; SYN when raw/linux)"
    }
    fn capabilities(&self) -> &[Capability] {
        &[Capability::Scan]
    }
    fn run(&self, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let resolved = resolve_targets(&ctx.targets)?;
            let mut addrs: Vec<_> = resolved.iter().map(|t| t.addr).collect();
            let ports = if ctx.ports.is_empty() {
                ares_core::TOP100.to_vec()
            } else {
                ctx.ports.clone()
            };

            let timing = ctx.mode.profile();
            let do_discover = ctx
                .extra
                .get("discover")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let pn = ctx
                .extra
                .get("pn")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if do_discover && !pn && !ctx.is_cancelled() {
                ctx.emit(ares_core::Event::Log {
                    level: "info".into(),
                    message: format!(
                        "scan --discover: probing {} address(es) before port scan",
                        addrs.len()
                    ),
                });
                let emit = ctx.emit.clone();
                let probe_ports: Vec<u16> = ctx
                    .extra
                    .get("probe_ports")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_u64().map(|n| n as u16))
                            .collect()
                    })
                    .unwrap_or_else(|| {
                        // Prefer common ports from the scan set so we don't rely only on defaults.
                        ports
                            .iter()
                            .copied()
                            .filter(|p| matches!(p, 22 | 80 | 135 | 443 | 445 | 3389 | 8080))
                            .collect()
                    });
                let up = host_discover_opts(
                    &addrs,
                    &probe_ports,
                    timing.timeout.as_millis() as u64,
                    false,
                    timing.jitter_ms,
                    timing.shuffle,
                    timing.rate_pps,
                    timing.concurrency,
                    ctx.cancel.clone(),
                    move |e| emit(e),
                )
                .await;
                if up.is_empty() {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "discover found no live hosts — nothing to scan (use --pn to scan anyway)"
                            .into(),
                    });
                    return Ok(());
                }
                ctx.emit(ares_core::Event::Log {
                    level: "info".into(),
                    message: format!("discover: {} live host(s); starting port scan", up.len()),
                });
                addrs = up;
            }

            let skip: HashSet<(IpAddr, u16)> = ctx
                .extra
                .get("skip_pairs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| {
                            let a = item.get("addr")?.as_str()?.parse().ok()?;
                            let p = item.get("port")?.as_u64()? as u16;
                            Some((a, p))
                        })
                        .collect()
                })
                .unwrap_or_default();

            let mut pairs = Vec::with_capacity(addrs.len() * ports.len());
            for a in &addrs {
                for p in &ports {
                    if !skip.contains(&(*a, *p)) {
                        pairs.push((*a, *p));
                    }
                }
            }

            if !skip.is_empty() {
                ctx.emit(ares_core::Event::Log {
                    level: "info".into(),
                    message: format!(
                        "resume: skipping {} already-scanned pairs; {} remaining",
                        skip.len(),
                        pairs.len()
                    ),
                });
            }

            if timing.shuffle || timing.jitter_ms > 0 || timing.adaptive {
                ctx.emit(ares_core::Event::Log {
                    level: "info".into(),
                    message: format!(
                        "timing {:?}: shuffle={} jitter≤{}ms concurrency={} pps={:?} adaptive={}",
                        ctx.mode,
                        timing.shuffle,
                        timing.jitter_ms,
                        timing.concurrency,
                        timing.rate_pps,
                        timing.adaptive
                    ),
                });
            }
            let show_closed = ctx
                .extra
                .get("show_closed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let show_filtered = ctx
                .extra
                .get("show_filtered")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let want_syn = ctx
                .extra
                .get("syn")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let kind = ScanEngineKind::resolve(want_syn);
            let emit = ctx.emit.clone();
            emit(ares_core::Event::Log {
                level: "info".into(),
                message: format!("scan engine: {}", kind.as_str()),
            });
            if matches!(kind, ScanEngineKind::SynCompat) {
                emit(ares_core::Event::Log {
                    level: "info".into(),
                    message: "note: --syn on this platform uses syn-compat (aggressive TCP connect), not half-open SYN"
                        .into(),
                });
            }
            scan_with_engine(
                kind,
                &pairs,
                timing.clone(),
                show_closed,
                show_filtered,
                ctx.cancel.clone(),
                move |e| emit(e),
            )
            .await;

            let do_udp = ctx
                .extra
                .get("udp")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if do_udp && !ctx.is_cancelled() {
                ctx.emit(ares_core::Event::Log {
                    level: "info".into(),
                    message: "udp: timeout with no reply = open|filtered (no ICMP unreachable on userspace Windows)"
                        .into(),
                });
                let udp_ports: Vec<u16> = ctx
                    .extra
                    .get("udp_ports")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_u64().map(|n| n as u16))
                            .collect()
                    })
                    .unwrap_or_else(|| UDP_TOP.to_vec());
                let udp = UdpScanner::new(timing);
                let emit = ctx.emit.clone();
                udp.scan_emit(&addrs, &udp_ports, ctx.cancel.clone(), move |e| emit(e))
                    .await;
            }

            Ok(())
        })
    }
}
