//! Non-HTTP service misconfig observes (data stores, messaging, infra).

use std::net::IpAddr;
use std::time::Duration;

use ares_core::event::Event;
use ares_plugin_api::ModuleCtx;
use ares_proto::http::HttpEngine;

use super::http::assess_http_surface;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn check_ports(
    port: u16,
    host: &str,
    addrs: &[IpAddr],
    engine: &HttpEngine,
    path_engine: &HttpEngine,
    do_paths: bool,
    path_list: &[String],
    path_gap: Duration,
    ctx: &ModuleCtx,
) -> bool {
    match port {
        21 => {
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Some(banner) = ares_probe::grab_banner(*addr, port, move |e| emit(e)).await {
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
            for addr in addrs {
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
                            finding: format!("Redis responds without AUTH ({detail})"),
                            severity: "high".into(),
                        });
                    } else if detail.contains("NOAUTH") {
                        ctx.emit(Event::MisconfigFinding {
                            addr: *addr,
                            port: Some(port),
                            finding: "Redis requires AUTH (exposed to network)".into(),
                            severity: "medium".into(),
                        });
                    }
                    break;
                }
            }
        }
        9200 => {
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_elasticsearch(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("Elasticsearch API reachable without auth ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_opensearch(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("OpenSearch API reachable without auth ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        11211 => {
            for addr in addrs {
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
                        finding: format!("Memcached responds without auth ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        27017 => {
            for addr in addrs {
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
            for addr in addrs {
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
            for addr in addrs {
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
            for addr in addrs {
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
                        finding: format!("MQTT broker reachable ({detail}) — verify auth/ACLs"),
                        severity: sev.into(),
                    });
                    break;
                }
            }
        }
        4222 => {
            for addr in addrs {
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
                        finding: format!("NATS INFO greeting reachable ({detail}) — verify auth"),
                        severity: "medium".into(),
                    });
                    break;
                }
            }
        }
        161 => {
            // SNMP is UDP; still probe from the configured port list.
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_snmp(*addr, port, "public", move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("SNMP responds to community `public` ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        389 => {
            for addr in addrs {
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
                        finding: format!("LDAP RootDSE reachable anonymously ({detail})"),
                        severity: sev.into(),
                    });
                    break;
                }
            }
        }
        88 => {
            for addr in addrs {
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
                if let Ok(Some(detail)) =
                    ares_proto::observe_kerberos(*addr, port, realm.as_deref(), move |e| emit(e))
                        .await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("Kerberos KDC reachable ({detail})"),
                        severity: "info".into(),
                    });
                    break;
                }
            }
        }
        5900..=5902 => {
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_vnc(*addr, port, move |e| emit(e)).await
                {
                    let d = detail.to_ascii_lowercase();
                    let sev = if d.contains("none") { "high" } else { "medium" };
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("VNC/RFB service exposed ({detail})"),
                        severity: sev.into(),
                    });
                    break;
                }
            }
        }
        5985 | 5986 => {
            for addr in addrs {
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
            for addr in addrs {
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
                        finding: format!("Docker Engine API reachable without TLS/auth ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        2379 => {
            for addr in addrs {
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
                        finding: format!("etcd HTTP API reachable without auth ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        8500 => {
            for addr in addrs {
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
                        finding: format!("Consul HTTP API reachable without auth ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        1433 => {
            for addr in addrs {
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
                        finding: format!("MSSQL/TDS service exposed ({detail})"),
                        severity: sev.into(),
                    });
                    break;
                }
            }
        }
        6443 => {
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let sni = if host.parse::<IpAddr>().is_ok() {
                    None
                } else {
                    Some(host)
                };
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_kubernetes(*addr, port, sni, move |e| emit(e)).await
                {
                    let sev = if detail.contains("auth required") {
                        "medium"
                    } else {
                        "high"
                    };
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("Kubernetes API reachable ({detail})"),
                        severity: sev.into(),
                    });
                    break;
                }
            }
        }
        1521 => {
            for addr in addrs {
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
                        finding: format!("Oracle TNS listener exposed ({detail})"),
                        severity: "medium".into(),
                    });
                    break;
                }
            }
        }
        5984 => {
            for addr in addrs {
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
                        finding: format!("CouchDB API reachable without auth ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        2181 => {
            for addr in addrs {
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
                        finding: format!("ZooKeeper four-letter cmds open ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        9042 => {
            for addr in addrs {
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
                        finding: format!("Cassandra native protocol exposed ({detail})"),
                        severity: "medium".into(),
                    });
                    break;
                }
            }
        }
        3389 => {
            for addr in addrs {
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
            for addr in addrs {
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
                        finding: format!("Neo4j HTTP API reachable ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        8123 => {
            for addr in addrs {
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
                        finding: format!("ClickHouse HTTP exposed ({detail})"),
                        severity: sev.into(),
                    });
                    break;
                }
            }
        }
        9000 => {
            for addr in addrs {
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
                        finding: format!("MinIO/S3 API reachable ({detail})"),
                        severity: "medium".into(),
                    });
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_portainer(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("Portainer exposed ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_sonarqube(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("SonarQube exposed ({detail})"),
                        severity: "medium".into(),
                    });
                    break;
                }
            }
        }
        7687 => {
            for addr in addrs {
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
                        finding: format!("Neo4j Bolt exposed ({detail})"),
                        severity: "medium".into(),
                    });
                    break;
                }
            }
        }
        15672 => {
            for addr in addrs {
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
                        finding: format!("RabbitMQ Management exposed ({detail})"),
                        severity: sev.into(),
                    });
                    break;
                }
            }
        }
        3000 => {
            let mut done = false;
            for addr in addrs {
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
                        .get(*addr, port, host, "/", move |e| emit_http(e))
                        .await
                    {
                        assess_http_surface(
                            *addr,
                            port,
                            false,
                            host,
                            &resp,
                            path_engine,
                            do_paths,
                            path_list,
                            path_gap,
                            ctx,
                        )
                        .await;
                        done = true;
                    }
                }
            }
        }
        5601 => {
            for addr in addrs {
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
            for addr in addrs {
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
        8086 => {
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_influxdb(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("InfluxDB exposed ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        28015 => {
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_rethinkdb(*addr, port, move |e| emit(e)).await
                {
                    let sev = if detail.to_ascii_lowercase().contains("auth") {
                        "medium"
                    } else {
                        "high"
                    };
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("RethinkDB exposed ({detail})"),
                        severity: sev.into(),
                    });
                    break;
                }
            }
        }
        10000 => {
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_scylla(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("ScyllaDB REST API exposed ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        8200 => {
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_vault(*addr, port, move |e| emit(e)).await
                {
                    let sev = if detail.to_ascii_lowercase().contains("sealed") {
                        "medium"
                    } else {
                        "high"
                    };
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("Vault exposed ({detail})"),
                        severity: sev.into(),
                    });
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_elastic_apm(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("Elastic APM Server exposed ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        4646 => {
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_nomad(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("Nomad API exposed ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        8983 => {
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_solr(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("Solr admin exposed ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        5701 => {
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_hazelcast(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("Hazelcast REST exposed ({detail})"),
                        severity: "high".into(),
                    });
                    break;
                }
            }
        }
        50051 => {
            for addr in addrs {
                if ctx.is_cancelled() {
                    break;
                }
                let emit = ctx.emit.clone();
                if let Ok(Some(detail)) =
                    ares_proto::observe_grpc(*addr, port, move |e| emit(e)).await
                {
                    ctx.emit(Event::MisconfigFinding {
                        addr: *addr,
                        port: Some(port),
                        finding: format!("gRPC endpoint exposed ({detail})"),
                        severity: "medium".into(),
                    });
                    break;
                }
            }
        }
        _ => return false,
    }
    true
}
