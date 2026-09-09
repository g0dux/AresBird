//! Interact module — talk to network services by protocol.

mod core;
mod http;
mod services;

use std::net::IpAddr;

use ares_plugin_api::{BoxFuture, Capability, Module, ModuleCtx, Permissions};

pub struct TalkModule;

impl Module for TalkModule {
    fn name(&self) -> &str {
        "talk"
    }
    fn description(&self) -> &str {
        "Interact with network services (HTTP/app observes: Kafka/AMQP/ES/DBs/…)"
    }
    fn capabilities(&self) -> &[Capability] {
        &[Capability::Interact]
    }
    fn permissions(&self) -> Permissions {
        Permissions {
            dns: true,
            outbound_http: true,
            ..Default::default()
        }
    }
    fn run(&self, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let proto = ctx
                .extra
                .get("proto")
                .and_then(|v| v.as_str())
                .unwrap_or("auto")
                .to_string();
            let target = ctx
                .targets
                .first()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("talk requires a target"))?;

            match proto.as_str() {
                "dns" | "ssh" | "tls" | "h2" | "http2" | "smb" | "ftp" | "smtp" => {
                    core::run(proto.as_str(), &ctx, &target).await?;
                }
                "http" | "auto" => {
                    http::run(&ctx, &target).await?;
                }
                "redis"
                | "mysql"
                | "mariadb"
                | "postgres"
                | "postgresql"
                | "pgsql"
                | "imap"
                | "pop3"
                | "pop"
                | "mongo"
                | "mongodb"
                | "es"
                | "elastic"
                | "elasticsearch"
                | "memcache"
                | "memcached"
                | "kafka"
                | "amqp"
                | "rabbit"
                | "mqtt"
                | "nats"
                | "ldap"
                | "kerberos"
                | "krb5"
                | "krb"
                | "vnc"
                | "rfb"
                | "winrm"
                | "wsman"
                | "snmp"
                | "docker"
                | "etcd"
                | "consul"
                | "mssql"
                | "sqlserver"
                | "k8s"
                | "kubernetes"
                | "oracle"
                | "tns"
                | "couchdb"
                | "couch"
                | "zookeeper"
                | "zk"
                | "cassandra"
                | "cql"
                | "rdp"
                | "mstsc"
                | "neo4j"
                | "clickhouse"
                | "ch"
                | "minio"
                | "s3"
                | "bolt"
                | "rabbitmq"
                | "rmq"
                | "rabbitmq-mgmt"
                | "grafana"
                | "kibana"
                | "prometheus"
                | "prom"
                | "jenkins"
                | "keycloak"
                | "portainer"
                | "argocd"
                | "argo"
                | "sonarqube"
                | "sonar"
                | "influxdb"
                | "influx"
                | "rethinkdb"
                | "rethink"
                | "scylla"
                | "scylladb"
                | "elastic-apm"
                | "apm"
                | "grpc"
                | "vault"
                | "nomad"
                | "solr"
                | "hazelcast"
                | "opensearch" => {
                    services::run(proto.as_str(), &ctx, &target).await?;
                }
                other => anyhow::bail!(
                    "unknown talk proto: {other} (try auto|dns|http|h2|ssh|tls|smb|ftp|smtp|redis|mysql|postgres|mongodb|elasticsearch|memcached|kafka|amqp|mqtt|nats|ldap|kerberos|vnc|winrm|snmp|docker|etcd|consul|mssql|kubernetes|oracle|couchdb|zookeeper|cassandra|rdp|neo4j|clickhouse|minio|bolt|rabbitmq|grafana|kibana|prometheus|jenkins|keycloak|portainer|argocd|sonarqube|imap|pop3)"
                ),
            }
            Ok(())
        })
    }
}

/// `dc.corp.local` → `CORP.LOCAL`; bare IP → None.
pub(crate) fn realm_from_target(target: &str) -> Option<String> {
    let host = target
        .rsplit_once(':')
        .and_then(|(h, p)| {
            if p.parse::<u16>().is_ok() {
                Some(h)
            } else {
                None
            }
        })
        .unwrap_or(target);
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        Some(parts[1..].join(".").to_ascii_uppercase())
    } else {
        None
    }
}

pub(crate) fn sni_name_from_target(target: &str) -> Option<String> {
    let host = if let Some((h, p)) = target.rsplit_once(':') {
        if p.parse::<u16>().is_ok() {
            h
        } else {
            target
        }
    } else {
        target
    };
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.parse::<IpAddr>().is_ok() || host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

pub(crate) fn parse_host_port(s: &str, default_port: u16) -> anyhow::Result<(IpAddr, u16)> {
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Ok((sa.ip(), sa.port()));
    }
    if let Some((h, p)) = s.rsplit_once(':') {
        if let (Ok(addr), Ok(port)) = (h.parse::<IpAddr>(), p.parse::<u16>()) {
            return Ok((addr, port));
        }
        let port: u16 = p.parse()?;
        let addr = std::net::ToSocketAddrs::to_socket_addrs(&(h, port))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("resolve failed"))?
            .ip();
        return Ok((addr, port));
    }
    if let Ok(addr) = s.parse::<IpAddr>() {
        return Ok((addr, default_port));
    }
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&(s, default_port))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("resolve failed"))?
        .ip();
    Ok((addr, default_port))
}

pub(crate) async fn resolve_one(host: &str) -> anyhow::Result<IpAddr> {
    if let Ok(ip) = host.parse() {
        return Ok(ip);
    }
    let addr = tokio::net::lookup_host((host, 0u16))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address for {host}"))?
        .ip();
    Ok(addr)
}
