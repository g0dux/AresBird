use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use ares_core::event::Event;
use ares_plugin_api::{BoxFuture, Capability, Module, ModuleCtx, Permissions};
use ares_proto::http::{assess_security_headers, HttpEngine, HttpResponse};
use ares_proto::tls_observe::observe_tls_preview;
use tokio::time::sleep;

use crate::paths::{self, PathProfile};

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
                    grouped
                        .entry((a.to_string(), p))
                        .or_default()
                        .push(a);
                }
                if grouped.is_empty() {
                    let ports = if ctx.ports.is_empty() {
                        vec![
                            21, 80, 88, 161, 389, 443, 1433, 1521, 1883, 2181, 2375, 2379, 3000,
                            3389, 4222, 5601, 5672, 5900, 5984, 5985, 5986, 6379, 6443, 7474, 7687,
                            8080, 8123, 8443, 8500, 9000, 9042, 9090, 9092, 9200, 11211, 15672,
                            27017,
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
                                grouped
                                    .entry((host.clone(), *p))
                                    .or_default()
                                    .push(t.addr);
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
                ..Default::default()
            };

            for tp in open {
                if ctx.is_cancelled() {
                    break;
                }
                let TargetPort { host, addrs, port } = tp;
                match port {
                    80 | 8000 | 8888 | 8008 | 5000 | 81 => {
                        let mut done = false;
                        for addr in &addrs {
                            if ctx.is_cancelled() || done {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(resp) =
                                engine.get(*addr, port, &host, "/", move |e| emit(e)).await
                            {
                                assess_http_surface(
                                    *addr,
                                    port,
                                    false,
                                    &host,
                                    &resp,
                                    &path_engine,
                                    do_paths,
                                    &path_list,
                                    path_gap,
                                    &ctx,
                                )
                                .await;
                                done = true;
                            }
                        }
                    }
                    8080 => {
                        let mut done = false;
                        for addr in &addrs {
                            if ctx.is_cancelled() || done {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_jenkins(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!("Jenkins exposed ({detail})"),
                                    severity: "medium".into(),
                                });
                                done = true;
                            } else {
                            let emit_http = ctx.emit.clone();
                            if let Ok(resp) = engine
                                .get(*addr, port, &host, "/", move |e| emit_http(e))
                                .await
                            {
                                assess_http_surface(
                                    *addr,
                                    port,
                                    false,
                                    &host,
                                    &resp,
                                    &path_engine,
                                    do_paths,
                                    &path_list,
                                    path_gap,
                                    &ctx,
                                )
                                .await;
                                done = true;
                            }
                            }
                        }
                    }
                    443 | 8443 => {
                        let mut done = false;
                        for addr in &addrs {
                            if ctx.is_cancelled() || done {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            let _ = observe_tls_preview(*addr, port, move |e| emit(e)).await;

                            let sni = if host.parse::<IpAddr>().is_ok() {
                                None
                            } else {
                                Some(host.as_str())
                            };
                            let emit = ctx.emit.clone();
                            match engine
                                .get_tls(*addr, port, &host, "/", sni, move |e| emit(e))
                                .await
                            {
                                Ok(resp) => {
                                    assess_http_surface(
                                        *addr,
                                        port,
                                        true,
                                        &host,
                                        &resp,
                                        &path_engine,
                                        do_paths,
                                        &path_list,
                                        path_gap,
                                        &ctx,
                                    )
                                    .await;
                                    done = true;
                                }
                                Err(e) => {
                                    ctx.emit(Event::Log {
                                        level: "info".into(),
                                        message: format!(
                                            "{host}/{addr}:{port} HTTPS GET failed ({e}), trying next peer…"
                                        ),
                                    });
                                }
                            }
                        }
                        if !done {
                            ctx.emit(Event::Log {
                                level: "warn".into(),
                                message: format!(
                                    "{host}:{port} HTTPS GET failed on all {} peer(s)",
                                    addrs.len()
                                ),
                            });
                        }
                    }
                    21 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Some(banner) =
                                ares_probe::grab_banner(*addr, port, move |e| emit(e)).await
                            {
                                let b = banner.to_lowercase();
                                if b.contains("ftp") || banner.starts_with("220") {
                                    ctx.emit(Event::MisconfigFinding {
                                        addr: *addr,
                                        port: Some(port),
                                        finding: format!(
                                            "FTP service exposed — verify anonymous access policy ({banner})"
                                        ),
                                        severity: "low".into(),
                                    });
                                }
                                break;
                            }
                        }
                    }
                    6379 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_redis(*addr, port, move |e| emit(e)).await
                            {
                                if detail.to_ascii_uppercase().contains("PONG")
                                    || detail.to_ascii_lowercase().contains("redis_version")
                                {
                                    ctx.emit(Event::MisconfigFinding {
                                        addr: *addr,
                                        port: Some(port),
                                        finding: format!(
                                            "Redis responds without AUTH ({detail})"
                                        ),
                                        severity: "high".into(),
                                    });
                                } else if detail.contains("NOAUTH") {
                                    ctx.emit(Event::MisconfigFinding {
                                        addr: *addr,
                                        port: Some(port),
                                        finding: "Redis requires AUTH (exposed to network)"
                                            .into(),
                                        severity: "medium".into(),
                                    });
                                }
                                break;
                            }
                        }
                    }
                    9200 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_elasticsearch(*addr, port, move |e| emit(e))
                                    .await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "Elasticsearch API reachable without auth ({detail})"
                                    ),
                                    severity: "high".into(),
                                });
                                break;
                            }
                        }
                    }
                    11211 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_memcached(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "Memcached responds without auth ({detail})"
                                    ),
                                    severity: "high".into(),
                                });
                                break;
                            }
                        }
                    }
                    27017 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_mongodb(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "MongoDB wire protocol reachable ({detail}) — verify auth"
                                    ),
                                    severity: "medium".into(),
                                });
                                break;
                            }
                        }
                    }
                    9092 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_kafka(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "Kafka broker ApiVersions reachable without auth ({detail})"
                                    ),
                                    severity: "medium".into(),
                                });
                                break;
                            }
                        }
                    }
                    5672 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_amqp(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "AMQP/RabbitMQ Connection.Start reachable ({detail}) — verify auth"
                                    ),
                                    severity: "medium".into(),
                                });
                                break;
                            }
                        }
                    }
                    1883 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_mqtt(*addr, port, move |e| emit(e)).await
                            {
                                let sev = if detail.to_ascii_lowercase().contains("accepted") {
                                    "high"
                                } else {
                                    "medium"
                                };
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "MQTT broker reachable ({detail}) — verify auth/ACLs"
                                    ),
                                    severity: sev.into(),
                                });
                                break;
                            }
                        }
                    }
                    4222 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_nats(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "NATS INFO greeting reachable ({detail}) — verify auth"
                                    ),
                                    severity: "medium".into(),
                                });
                                break;
                            }
                        }
                    }
                    161 => {
                        // SNMP is UDP; still probe from the configured port list.
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_snmp(*addr, port, "public", move |e| emit(e))
                                    .await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "SNMP responds to community `public` ({detail})"
                                    ),
                                    severity: "high".into(),
                                });
                                break;
                            }
                        }
                    }
                    389 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_ldap(*addr, port, move |e| emit(e)).await
                            {
                                let sev = if detail.to_ascii_lowercase().contains("microsoft")
                                    || detail.to_ascii_lowercase().contains("naming")
                                {
                                    "medium"
                                } else {
                                    "low"
                                };
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "LDAP RootDSE reachable anonymously ({detail})"
                                    ),
                                    severity: sev.into(),
                                });
                                break;
                            }
                        }
                    }
                    88 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let realm = host
                                .split('.')
                                .skip(1)
                                .collect::<Vec<_>>()
                                .join(".")
                                .to_ascii_uppercase();
                            let realm = if realm.is_empty() { None } else { Some(realm) };
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) = ares_proto::observe_kerberos(
                                *addr,
                                port,
                                realm.as_deref(),
                                move |e| emit(e),
                            )
                            .await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "Kerberos KDC reachable ({detail})"
                                    ),
                                    severity: "info".into(),
                                });
                                break;
                            }
                        }
                    }
                    5900 | 5901 | 5902 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_vnc(*addr, port, move |e| emit(e)).await
                            {
                                let d = detail.to_ascii_lowercase();
                                let sev = if d.contains("none") {
                                    "high"
                                } else {
                                    "medium"
                                };
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "VNC/RFB service exposed ({detail})"
                                    ),
                                    severity: sev.into(),
                                });
                                break;
                            }
                        }
                    }
                    5985 | 5986 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_winrm(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "WinRM /wsman reachable ({detail}) — verify network exposure"
                                    ),
                                    severity: "medium".into(),
                                });
                                break;
                            }
                        }
                    }
                    2375 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_docker(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "Docker Engine API reachable without TLS/auth ({detail})"
                                    ),
                                    severity: "high".into(),
                                });
                                break;
                            }
                        }
                    }
                    2379 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_etcd(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "etcd HTTP API reachable without auth ({detail})"
                                    ),
                                    severity: "high".into(),
                                });
                                break;
                            }
                        }
                    }
                    8500 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_consul(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "Consul HTTP API reachable without auth ({detail})"
                                    ),
                                    severity: "high".into(),
                                });
                                break;
                            }
                        }
                    }
                    1433 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_mssql(*addr, port, move |e| emit(e)).await
                            {
                                let sev = if detail.contains("encrypt=off")
                                    || detail.contains("encrypt=not_supported")
                                {
                                    "medium"
                                } else {
                                    "low"
                                };
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "MSSQL/TDS service exposed ({detail})"
                                    ),
                                    severity: sev.into(),
                                });
                                break;
                            }
                        }
                    }
                    6443 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let sni = if host.parse::<IpAddr>().is_ok() {
                                None
                            } else {
                                Some(host.as_str())
                            };
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) = ares_proto::observe_kubernetes(
                                *addr,
                                port,
                                sni,
                                move |e| emit(e),
                            )
                            .await
                            {
                                let sev = if detail.contains("auth required") {
                                    "medium"
                                } else {
                                    "high"
                                };
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "Kubernetes API reachable ({detail})"
                                    ),
                                    severity: sev.into(),
                                });
                                break;
                            }
                        }
                    }
                    1521 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_oracle(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "Oracle TNS listener exposed ({detail})"
                                    ),
                                    severity: "medium".into(),
                                });
                                break;
                            }
                        }
                    }
                    5984 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_couchdb(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "CouchDB API reachable without auth ({detail})"
                                    ),
                                    severity: "high".into(),
                                });
                                break;
                            }
                        }
                    }
                    2181 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_zookeeper(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "ZooKeeper four-letter cmds open ({detail})"
                                    ),
                                    severity: "high".into(),
                                });
                                break;
                            }
                        }
                    }
                    9042 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_cassandra(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "Cassandra native protocol exposed ({detail})"
                                    ),
                                    severity: "medium".into(),
                                });
                                break;
                            }
                        }
                    }
                    3389 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_rdp(*addr, port, move |e| emit(e)).await
                            {
                                let sev = if detail.contains("NLA") {
                                    "medium"
                                } else {
                                    "high"
                                };
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!("RDP service exposed ({detail})"),
                                    severity: sev.into(),
                                });
                                break;
                            }
                        }
                    }
                    7474 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_neo4j(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "Neo4j HTTP API reachable ({detail})"
                                    ),
                                    severity: "high".into(),
                                });
                                break;
                            }
                        }
                    }
                    8123 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_clickhouse(*addr, port, move |e| emit(e)).await
                            {
                                let sev = if detail != "ClickHouse HTTP" {
                                    "high" // anonymous version() likely worked
                                } else {
                                    "medium"
                                };
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "ClickHouse HTTP exposed ({detail})"
                                    ),
                                    severity: sev.into(),
                                });
                                break;
                            }
                        }
                    }
                    9000 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_minio(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "MinIO/S3 API reachable ({detail})"
                                    ),
                                    severity: "medium".into(),
                                });
                                break;
                            }
                        }
                    }
                    7687 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_bolt(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "Neo4j Bolt exposed ({detail})"
                                    ),
                                    severity: "medium".into(),
                                });
                                break;
                            }
                        }
                    }
                    15672 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_rabbitmq(*addr, port, move |e| emit(e)).await
                            {
                                let sev = if detail.contains("Management ")
                                    && detail != "RabbitMQ Management UI"
                                    && detail != "RabbitMQ Management API"
                                {
                                    "high" // anonymous overview with version
                                } else {
                                    "medium"
                                };
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!(
                                        "RabbitMQ Management exposed ({detail})"
                                    ),
                                    severity: sev.into(),
                                });
                                break;
                            }
                        }
                    }
                    3000 => {
                        let mut done = false;
                        for addr in &addrs {
                            if ctx.is_cancelled() || done {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_grafana(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!("Grafana exposed ({detail})"),
                                    severity: "medium".into(),
                                });
                                done = true;
                            } else {
                            // Not Grafana — still assess as generic HTTP.
                            let emit_http = ctx.emit.clone();
                            if let Ok(resp) = engine
                                .get(*addr, port, &host, "/", move |e| emit_http(e))
                                .await
                            {
                                assess_http_surface(
                                    *addr,
                                    port,
                                    false,
                                    &host,
                                    &resp,
                                    &path_engine,
                                    do_paths,
                                    &path_list,
                                    path_gap,
                                    &ctx,
                                )
                                .await;
                                done = true;
                            }
                            }
                        }
                    }
                    5601 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_kibana(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!("Kibana exposed ({detail})"),
                                    severity: "medium".into(),
                                });
                                break;
                            }
                        }
                    }
                    9090 => {
                        for addr in &addrs {
                            if ctx.is_cancelled() {
                                break;
                            }
                            let emit = ctx.emit.clone();
                            if let Ok(Some(detail)) =
                                ares_proto::observe_prometheus(*addr, port, move |e| emit(e)).await
                            {
                                ctx.emit(Event::MisconfigFinding {
                                    addr: *addr,
                                    port: Some(port),
                                    finding: format!("Prometheus exposed ({detail})"),
                                    severity: "high".into(),
                                });
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        })
    }
}

async fn assess_http_surface(
    addr: IpAddr,
    port: u16,
    https: bool,
    host: &str,
    resp: &HttpResponse,
    path_engine: &HttpEngine,
    do_paths: bool,
    paths: &[String],
    path_gap: Duration,
    ctx: &ModuleCtx,
) {
    emit_header_findings(addr, port, https, &resp.headers, ctx);
    if let Some((_, server)) = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("server"))
    {
        if looks_versioned_disclosure(server) {
            ctx.emit(Event::MisconfigFinding {
                addr,
                port: Some(port),
                finding: format!("Server version disclosed: {server}"),
                severity: "info".into(),
            });
        }
    }
    if resp.body_preview.to_lowercase().contains("index of /") {
        ctx.emit(Event::MisconfigFinding {
            addr,
            port: Some(port),
            finding: "Possible directory listing enabled".into(),
            severity: "medium".into(),
        });
    }

    if !do_paths || !should_probe_paths(&resp.status_line) {
        if do_paths {
            ctx.emit(Event::Log {
                level: "info".into(),
                message: format!(
                    "{host}:{port} skip path probes (root status: {})",
                    resp.status_line.chars().take(40).collect::<String>()
                ),
            });
        }
        return;
    }

    ctx.emit(Event::Log {
        level: "info".into(),
        message: format!("{host}:{port} path probes: {} path(s)", paths.len()),
    });

    for path in paths {
        if ctx.is_cancelled() {
            break;
        }
        sleep(path_gap).await;
        let emit = ctx.emit.clone();
        let result = if https {
            let sni = if host.parse::<IpAddr>().is_ok() {
                None
            } else {
                Some(host)
            };
            path_engine
                .get_tls(addr, port, host, path, sni, move |e| emit(e))
                .await
        } else {
            path_engine
                .get(addr, port, host, path, move |e| emit(e))
                .await
        };
        match result {
            Ok(r) => {
                if paths::sensitive_path_hit(path, &r.status_line, &r.body_preview) {
                    let sev = paths::path_severity(path);
                    ctx.emit(Event::MisconfigFinding {
                        addr,
                        port: Some(port),
                        finding: format!(
                            "Sensitive path may be exposed: {path} ({})",
                            r.status_line.chars().take(48).collect::<String>()
                        ),
                        severity: sev.into(),
                    });
                }
                if r.status_line.contains("403")
                    || r.status_line.contains("429")
                    || r.status_line.contains("503")
                {
                    ctx.emit(Event::Log {
                        level: "info".into(),
                        message: format!("{host}:{port} stop path probes after {}", r.status_line),
                    });
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn build_path_list(ctx: &ModuleCtx) -> anyhow::Result<Vec<String>> {
    let profile = ctx
        .extra
        .get("path_profile")
        .and_then(|v| v.as_str())
        .and_then(PathProfile::parse)
        .unwrap_or(PathProfile::Default);

    let mut list: Vec<String> = profile.paths().into_iter().map(|s| s.to_string()).collect();

    if let Some(file) = ctx.extra.get("paths_file").and_then(|v| v.as_str()) {
        let extra = paths::load_paths_file(std::path::Path::new(file))?;
        for p in extra {
            if !list.contains(&p) {
                list.push(p);
            }
        }
    }

    if let Some(arr) = ctx.extra.get("paths").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(s) = v.as_str() {
                let p = if s.starts_with('/') {
                    s.to_string()
                } else {
                    format!("/{s}")
                };
                if !list.contains(&p) {
                    list.push(p);
                }
            }
        }
    }

    Ok(list)
}

fn should_probe_paths(status_line: &str) -> bool {
    status_line.contains("200")
        || status_line.contains("301")
        || status_line.contains("302")
        || status_line.contains("304")
}

fn emit_header_findings(
    addr: IpAddr,
    port: u16,
    https: bool,
    headers: &[(String, String)],
    ctx: &ModuleCtx,
) {
    for finding in assess_security_headers(headers, https) {
        ctx.emit(Event::MisconfigFinding {
            addr,
            port: Some(port),
            finding: finding.message,
            severity: finding.severity.into(),
        });
    }
}

fn looks_versioned_disclosure(server: &str) -> bool {
    let s = server.to_lowercase();
    s.contains('/')
        && (s.contains("apache")
            || s.contains("nginx")
            || s.contains("iis")
            || s.contains("tomcat")
            || s.contains("jetty")
            || s.contains("openresty"))
}
