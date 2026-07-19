use std::net::IpAddr;

use ares_core::event::Event;
use ares_core::model::ServiceInfo;
use ares_proto::apps::{
    observe_amqp, observe_bolt, observe_cassandra, observe_clickhouse, observe_consul,
    observe_couchdb, observe_docker, observe_elasticsearch, observe_etcd, observe_grafana,
    observe_imap, observe_jenkins, observe_kafka, observe_kerberos, observe_kibana,
    observe_kubernetes, observe_ldap, observe_memcached, observe_minio, observe_mongodb,
    observe_mqtt, observe_mssql, observe_mysql, observe_nats, observe_neo4j, observe_oracle,
    observe_pop3, observe_postgres, observe_prometheus, observe_rabbitmq, observe_rdp,
    observe_redis, observe_vnc, observe_winrm, observe_zookeeper,
};
use ares_proto::http::HttpEngine;
use ares_proto::smb::smb_negotiate;
use ares_proto::ssh::SshBanner;
use ares_proto::tls_observe::{observe_tls, observe_tls_preview};
use regex::Regex;

use crate::banner::grab_banner;
use crate::fingerprint::{guess_os_correlated, guess_os_from_banner, guess_os_from_smb};

/// Detect service on an open TCP port using banners + protocol probes.
pub async fn detect_service(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event) + Send + Sync + Clone + 'static,
) {
    detect_service_ex(addr, port, None, None, emit).await;
}

/// Like [`detect_service`], with optional TLS SNI hostname and observed IP TTL.
pub async fn detect_service_ex(
    addr: IpAddr,
    port: u16,
    sni: Option<&str>,
    observed_ttl: Option<u8>,
    emit: impl Fn(Event) + Send + Sync + Clone + 'static,
) {
    match port {
        22 => {
            let emit2 = emit.clone();
            if let Ok(banner) = SshBanner::grab(addr, port, emit2).await {
                guess_os_from_banner(addr, &banner, |e| emit(e));
            }
            return;
        }
        80 | 8000 | 8888 | 8008 | 5000 | 81 => {
            let engine = HttpEngine::default();
            let emit2 = emit.clone();
            let host_hdr = sni.unwrap_or(&addr.to_string()).to_string();
            if let Ok(resp) = engine.get(addr, port, &host_hdr, "/", emit2).await {
                let server = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                    .map(|(_, v)| v.clone());
                if let Some(ref s) = server {
                    guess_os_from_banner(addr, s, |e| emit(e));
                }
                emit(Event::ServiceDetected {
                    addr,
                    port,
                    service: ServiceInfo {
                        name: "http".into(),
                        product: server,
                        version: None,
                        extra: Some(resp.status_line),
                        confidence: 0.9,
                    },
                });
            }
            return;
        }
        8080 => {
            let emit2 = emit.clone();
            if let Ok(Some(_)) = observe_jenkins(addr, port, emit2).await {
                return;
            }
            let engine = HttpEngine::default();
            let emit_http = emit.clone();
            let host_hdr = sni.unwrap_or(&addr.to_string()).to_string();
            if let Ok(resp) = engine.get(addr, port, &host_hdr, "/", emit_http).await {
                let server = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                    .map(|(_, v)| v.clone());
                if let Some(ref s) = server {
                    guess_os_from_banner(addr, s, |e| emit(e));
                }
                emit(Event::ServiceDetected {
                    addr,
                    port,
                    service: ServiceInfo {
                        name: "http".into(),
                        product: server,
                        version: None,
                        extra: Some(resp.status_line),
                        confidence: 0.85,
                    },
                });
            }
            return;
        }
        443 | 8443 => {
            let emit2 = emit.clone();
            if let Some(name) = sni {
                let _ = observe_tls(addr, port, Some(name), emit2).await;
            } else {
                let _ = observe_tls_preview(addr, port, emit2).await;
            }
            // Follow with HTTP/1.1 over TLS for Server / title / security headers
            let host = sni
                .map(|s| s.to_string())
                .unwrap_or_else(|| addr.to_string());
            let engine = HttpEngine::default();
            let emit_https = emit.clone();
            if let Ok(resp) = engine
                .get_tls(addr, port, &host, "/", sni, emit_https)
                .await
            {
                let server = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                    .map(|(_, v)| v.clone());
                if let Some(ref s) = server {
                    guess_os_from_banner(addr, s, |e| emit(e));
                }
                if let Some(ref powered) = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("x-powered-by"))
                    .map(|(_, v)| v.clone())
                {
                    guess_os_from_banner(addr, powered, |e| emit(e));
                }
                for finding in ares_proto::assess_security_headers(&resp.headers, true) {
                    emit(Event::MisconfigFinding {
                        addr,
                        port: Some(port),
                        finding: finding.message,
                        severity: finding.severity.into(),
                    });
                }
            }
            return;
        }
        445 => {
            let emit2 = emit.clone();
            if let Ok(dialect) = smb_negotiate(addr, port, emit2).await {
                if let Some(d) = dialect {
                    guess_os_from_smb(addr, &d, |e| emit(e));
                }
            }
            return;
        }
        6379 => {
            let emit2 = emit.clone();
            let _ = observe_redis(addr, port, emit2).await;
            return;
        }
        3306 => {
            let emit2 = emit.clone();
            let _ = observe_mysql(addr, port, emit2).await;
            return;
        }
        5432 => {
            let emit2 = emit.clone();
            let _ = observe_postgres(addr, port, emit2).await;
            return;
        }
        143 => {
            let emit2 = emit.clone();
            let _ = observe_imap(addr, port, emit2).await;
            return;
        }
        110 => {
            let emit2 = emit.clone();
            let _ = observe_pop3(addr, port, emit2).await;
            return;
        }
        27017 => {
            let emit2 = emit.clone();
            if let Ok(Some(detail)) = observe_mongodb(addr, port, emit2).await {
                guess_os_from_banner(addr, &detail, |e| emit(e));
            }
            return;
        }
        9200 => {
            let emit2 = emit.clone();
            if let Ok(Some(detail)) = observe_elasticsearch(addr, port, emit2).await {
                guess_os_from_banner(addr, &detail, |e| emit(e));
            }
            return;
        }
        2375 => {
            let emit2 = emit.clone();
            let _ = observe_docker(addr, port, emit2).await;
            return;
        }
        2379 => {
            let emit2 = emit.clone();
            let _ = observe_etcd(addr, port, emit2).await;
            return;
        }
        8500 => {
            let emit2 = emit.clone();
            let _ = observe_consul(addr, port, emit2).await;
            return;
        }
        1433 => {
            let emit2 = emit.clone();
            let _ = observe_mssql(addr, port, emit2).await;
            return;
        }
        6443 => {
            let emit2 = emit.clone();
            let _ = observe_kubernetes(addr, port, sni, emit2).await;
            return;
        }
        1521 => {
            let emit2 = emit.clone();
            let _ = observe_oracle(addr, port, emit2).await;
            return;
        }
        5984 => {
            let emit2 = emit.clone();
            let _ = observe_couchdb(addr, port, emit2).await;
            return;
        }
        2181 => {
            let emit2 = emit.clone();
            let _ = observe_zookeeper(addr, port, emit2).await;
            return;
        }
        9042 => {
            let emit2 = emit.clone();
            let _ = observe_cassandra(addr, port, emit2).await;
            return;
        }
        3389 => {
            let emit2 = emit.clone();
            if let Ok(Some(_)) = observe_rdp(addr, port, emit2).await {
                emit(Event::OsGuess {
                    addr,
                    os: "Windows family (RDP/3389)".into(),
                    confidence: 0.55,
                    observed_ttl: None,
                });
            }
            return;
        }
        7474 => {
            let emit2 = emit.clone();
            let _ = observe_neo4j(addr, port, emit2).await;
            return;
        }
        8123 => {
            let emit2 = emit.clone();
            let _ = observe_clickhouse(addr, port, emit2).await;
            return;
        }
        9000 => {
            let emit2 = emit.clone();
            let _ = observe_minio(addr, port, emit2).await;
            return;
        }
        7687 => {
            let emit2 = emit.clone();
            let _ = observe_bolt(addr, port, emit2).await;
            return;
        }
        15672 => {
            let emit2 = emit.clone();
            let _ = observe_rabbitmq(addr, port, emit2).await;
            return;
        }
        3000 => {
            let emit2 = emit.clone();
            if let Ok(Some(_)) = observe_grafana(addr, port, emit2).await {
                return;
            }
            // Fall back to generic HTTP (many apps use :3000).
            let engine = HttpEngine::default();
            let emit_http = emit.clone();
            let host_hdr = sni.unwrap_or(&addr.to_string()).to_string();
            if let Ok(resp) = engine.get(addr, port, &host_hdr, "/", emit_http).await {
                let server = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                    .map(|(_, v)| v.clone());
                if let Some(ref s) = server {
                    guess_os_from_banner(addr, s, |e| emit(e));
                }
                emit(Event::ServiceDetected {
                    addr,
                    port,
                    service: ServiceInfo {
                        name: "http".into(),
                        product: server,
                        version: None,
                        extra: Some(resp.status_line),
                        confidence: 0.85,
                    },
                });
            }
            return;
        }
        5601 => {
            let emit2 = emit.clone();
            let _ = observe_kibana(addr, port, emit2).await;
            return;
        }
        9090 => {
            let emit2 = emit.clone();
            let _ = observe_prometheus(addr, port, emit2).await;
            return;
        }
        11211 => {
            let emit2 = emit.clone();
            if let Ok(Some(detail)) = observe_memcached(addr, port, emit2).await {
                guess_os_from_banner(addr, &detail, |e| emit(e));
            }
            return;
        }
        9092 => {
            let emit2 = emit.clone();
            if let Ok(Some(detail)) = observe_kafka(addr, port, emit2).await {
                guess_os_from_banner(addr, &detail, |e| emit(e));
            }
            return;
        }
        5672 => {
            let emit2 = emit.clone();
            if let Ok(Some(detail)) = observe_amqp(addr, port, emit2).await {
                guess_os_from_banner(addr, &detail, |e| emit(e));
            }
            return;
        }
        1883 => {
            let emit2 = emit.clone();
            let _ = observe_mqtt(addr, port, emit2).await;
            return;
        }
        4222 => {
            let emit2 = emit.clone();
            if let Ok(Some(detail)) = observe_nats(addr, port, emit2).await {
                guess_os_from_banner(addr, &detail, |e| emit(e));
            }
            return;
        }
        389 => {
            let emit2 = emit.clone();
            if let Ok(Some(detail)) = observe_ldap(addr, port, emit2).await {
                guess_os_from_banner(addr, &detail, |e| emit(e));
            }
            return;
        }
        636 => {
            // LDAPS — TLS observe only (no cleartext RootDSE).
            let emit2 = emit.clone();
            let _ = observe_tls_preview(addr, port, emit2).await;
            return;
        }
        88 => {
            let emit2 = emit.clone();
            if let Ok(Some(detail)) = observe_kerberos(addr, port, None, emit2).await {
                guess_os_from_banner(addr, &detail, |e| emit(e));
            }
            return;
        }
        5900 | 5901 | 5902 => {
            let emit2 = emit.clone();
            let _ = observe_vnc(addr, port, emit2).await;
            return;
        }
        5985 | 5986 => {
            let emit2 = emit.clone();
            if let Ok(Some(detail)) = observe_winrm(addr, port, emit2).await {
                guess_os_from_banner(addr, &detail, |e| emit(e));
            }
            return;
        }
        993 | 995 => {
            // IMAPS / POP3S — TLS observe only (no cleartext greeting).
            let emit2 = emit.clone();
            let _ = observe_tls_preview(addr, port, emit2).await;
            return;
        }
        _ => {}
    }

    if let Some(banner) = grab_banner(addr, port, emit.clone()).await {
        guess_os_correlated(addr, Some(&banner), observed_ttl, |e| emit(e));
        let service = classify_banner(port, &banner);
        emit(Event::ServiceDetected {
            addr,
            port,
            service,
        });
    } else if port != 3389 {
        if let Some(ttl) = observed_ttl {
            guess_os_correlated(addr, None, Some(ttl), |e| emit(e));
        }
        let name = well_known(port).unwrap_or("unknown");
        emit(Event::ServiceDetected {
            addr,
            port,
            service: ServiceInfo {
                name: name.into(),
                product: None,
                version: None,
                extra: None,
                confidence: 0.3,
            },
        });
    }
}

fn classify_banner(port: u16, banner: &str) -> ServiceInfo {
    let b = banner.to_lowercase();
    let (name, product, version, conf) = if b.contains("ssh-") {
        ("ssh", Some(banner.to_string()), None, 0.95)
    } else if b.contains("ftp") || b.starts_with("220") && port == 21 {
        ("ftp", Some(banner.to_string()), extract_version(&b), 0.85)
    } else if b.contains("smtp") || b.contains("esmtp") {
        ("smtp", Some(banner.to_string()), extract_version(&b), 0.85)
    } else if b.contains("http/") {
        ("http", extract_server(banner), extract_version(&b), 0.8)
    } else if b.contains("mysql") || b.contains("mariadb") {
        ("mysql", Some(banner.to_string()), extract_version(&b), 0.8)
    } else if b.contains("redis") {
        ("redis", Some(banner.to_string()), extract_version(&b), 0.85)
    } else if b.contains("mongodb") {
        (
            "mongodb",
            Some(banner.to_string()),
            extract_version(&b),
            0.85,
        )
    } else if b.contains("elasticsearch") {
        (
            "elasticsearch",
            Some(banner.to_string()),
            extract_version(&b),
            0.85,
        )
    } else if b.contains("memcached") {
        (
            "memcached",
            Some(banner.to_string()),
            extract_version(&b),
            0.85,
        )
    } else if b.contains("kafka") {
        ("kafka", Some(banner.to_string()), None, 0.85)
    } else if b.contains("rabbitmq") || b.contains("amqp") {
        ("amqp", Some(banner.to_string()), extract_version(&b), 0.85)
    } else if b.contains("mqtt") {
        ("mqtt", Some(banner.to_string()), None, 0.85)
    } else if b.contains("nats") {
        ("nats", Some(banner.to_string()), extract_version(&b), 0.85)
    } else if b.contains("ldap") || b.contains("namingcontexts") {
        ("ldap", Some(banner.to_string()), None, 0.85)
    } else if b.contains("kerberos") {
        ("kerberos", Some(banner.to_string()), None, 0.85)
    } else if b.starts_with("rfb ") || b.contains("vnc") {
        ("vnc", Some(banner.to_string()), None, 0.85)
    } else if b.contains("winrm") || b.contains("ws-management") || b.contains("microsoft-httpapi")
    {
        ("winrm", Some(banner.to_string()), None, 0.85)
    } else if b.contains("imap") {
        ("imap", Some(banner.to_string()), None, 0.85)
    } else if b.contains("pop3") {
        ("pop3", Some(banner.to_string()), None, 0.85)
    } else {
        (
            well_known(port).unwrap_or("unknown"),
            Some(banner.to_string()),
            None,
            0.5,
        )
    };

    ServiceInfo {
        name: name.into(),
        product,
        version,
        extra: None,
        confidence: conf,
    }
}

fn extract_version(s: &str) -> Option<String> {
    let re = Regex::new(r"(\d+\.\d+(?:\.\d+)?)").ok()?;
    re.find(s).map(|m| m.as_str().to_string())
}

fn extract_server(banner: &str) -> Option<String> {
    for line in banner.lines() {
        if let Some(rest) = line.strip_prefix("Server:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn well_known(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        88 => "kerberos",
        110 => "pop3",
        143 => "imap",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        636 => "ldaps",
        1433 => "ms-sql-s",
        1521 => "oracle",
        1883 => "mqtt",
        2181 => "zookeeper",
        2375 => "docker",
        2379 => "etcd",
        3000 => "grafana",
        3306 => "mysql",
        3389 => "rdp",
        4222 => "nats",
        5432 => "postgresql",
        5601 => "kibana",
        5672 => "amqp",
        5900 => "vnc",
        5984 => "couchdb",
        5985 => "winrm",
        5986 => "winrm-https",
        6379 => "redis",
        6443 => "kubernetes",
        7474 => "neo4j",
        7687 => "bolt",
        8080 => "jenkins-or-http",
        8123 => "clickhouse",
        8500 => "consul",
        9000 => "minio",
        9042 => "cassandra",
        9090 => "prometheus",
        9092 => "kafka",
        9200 => "elasticsearch",
        11211 => "memcached",
        15672 => "rabbitmq-mgmt",
        27017 => "mongodb",
        _ => return None,
    })
}
