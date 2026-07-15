use std::net::IpAddr;

use ares_plugin_api::{BoxFuture, Capability, Module, ModuleCtx, Permissions};
use ares_probe::{grab_banner, guess_os_from_banner, guess_os_from_smb};
use ares_proto::apps::{
    observe_amqp, observe_elasticsearch, observe_imap, observe_kafka, observe_kerberos,
    observe_ldap, observe_memcached, observe_mongodb, observe_mqtt, observe_mysql, observe_nats,
    observe_pop3, observe_postgres, observe_redis, observe_snmp, observe_vnc, observe_winrm,
};
use ares_proto::dns::DnsEngine;
use ares_proto::http::HttpEngine;
use ares_proto::http2::{observe_h2_alpn, observe_h2_cleartext};
use ares_proto::smb::smb_negotiate;
use ares_proto::ssh::SshBanner;
use ares_proto::tls_observe::observe_tls;
use url::Url;

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
                "dns" => {
                    let dns = DnsEngine::system()?;
                    let emit = ctx.emit.clone();
                    dns.enrich_domain(&target, move |e| emit(e)).await;
                }
                "ssh" => {
                    let (addr, port) = parse_host_port(&target, 22)?;
                    let emit = ctx.emit.clone();
                    match SshBanner::grab(addr, port, move |e| emit(e)).await {
                        Ok(banner) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &banner, move |e| emit(e));
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk ssh failed: {e}"),
                            });
                        }
                    }
                }
                "tls" => {
                    let (addr, port) = parse_host_port(&target, 443)?;
                    let sni = sni_name_from_target(&target);
                    let emit = ctx.emit.clone();
                    if let Err(e) = observe_tls(addr, port, sni.as_deref(), move |e| emit(e)).await {
                        ctx.emit(ares_core::Event::Log {
                            level: "warn".into(),
                            message: format!("talk tls failed: {e}"),
                        });
                    }
                }
                "h2" | "http2" => {
                    // Prefer TLS ALPN on 443-ish; cleartext prior-knowledge otherwise.
                    let default_port = if target.contains(":80") { 80 } else { 443 };
                    let (addr, port, sni) = if let Ok(url) = Url::parse(&target) {
                        let host = url.host_str().unwrap_or("127.0.0.1").to_string();
                        let port = url
                            .port_or_known_default()
                            .unwrap_or(if url.scheme() == "http" { 80 } else { 443 });
                        let addr = resolve_one(&host).await?;
                        let sni = if host.parse::<IpAddr>().is_ok() {
                            None
                        } else {
                            Some(host)
                        };
                        (addr, port, sni)
                    } else {
                        let (addr, port) = parse_host_port(&target, default_port)?;
                        (addr, port, None)
                    };

                    let use_tls = port == 443 || port == 8443 || target.starts_with("https://");
                    if use_tls {
                        let emit = ctx.emit.clone();
                        match observe_h2_alpn(addr, port, sni.as_deref(), move |e| emit(e)).await {
                            Ok(Some(alpn)) => {
                                ctx.emit(ares_core::Event::Log {
                                    level: "info".into(),
                                    message: format!("talk h2 ALPN={alpn}"),
                                });
                            }
                            Ok(None) => {
                                ctx.emit(ares_core::Event::Log {
                                    level: "warn".into(),
                                    message: "talk h2: no ALPN result".into(),
                                });
                            }
                            Err(e) => {
                                ctx.emit(ares_core::Event::Log {
                                    level: "warn".into(),
                                    message: format!("talk h2 failed: {e}"),
                                });
                            }
                        }
                    } else {
                        let emit = ctx.emit.clone();
                        match observe_h2_cleartext(addr, port, move |e| emit(e)).await {
                            Ok(true) => {
                                ctx.emit(ares_core::Event::Log {
                                    level: "info".into(),
                                    message: "talk h2c: SETTINGS ok".into(),
                                });
                            }
                            Ok(false) => {
                                ctx.emit(ares_core::Event::Log {
                                    level: "warn".into(),
                                    message: "talk h2c: not supported / no SETTINGS".into(),
                                });
                            }
                            Err(e) => {
                                ctx.emit(ares_core::Event::Log {
                                    level: "warn".into(),
                                    message: format!("talk h2c failed: {e}"),
                                });
                            }
                        }
                    }
                }
                "smb" => {
                    let (addr, port) = parse_host_port(&target, 445)?;
                    let emit = ctx.emit.clone();
                    match smb_negotiate(addr, port, move |e| emit(e)).await {
                        Ok(Some(dialect)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_smb(addr, &dialect, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk smb: {dialect}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk smb: no SMB dialect detected".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk smb failed: {e}"),
                            });
                        }
                    }
                }
                "ftp" => {
                    let (addr, port) = parse_host_port(&target, 21)?;
                    let emit = ctx.emit.clone();
                    match grab_banner(addr, port, move |e| emit(e)).await {
                        Some(banner) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &banner, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk ftp: {banner}"),
                            });
                        }
                        None => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk ftp: empty banner".into(),
                            });
                        }
                    }
                }
                "smtp" => {
                    let (addr, port) = parse_host_port(&target, 25)?;
                    let emit = ctx.emit.clone();
                    match grab_banner(addr, port, move |e| emit(e)).await {
                        Some(banner) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &banner, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk smtp: {banner}"),
                            });
                        }
                        None => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk smtp: empty banner".into(),
                            });
                        }
                    }
                }
                "redis" => {
                    let (addr, port) = parse_host_port(&target, 6379)?;
                    let emit = ctx.emit.clone();
                    match observe_redis(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk redis: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk redis: no response".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk redis failed: {e}"),
                            });
                        }
                    }
                }
                "mysql" | "mariadb" => {
                    let (addr, port) = parse_host_port(&target, 3306)?;
                    let emit = ctx.emit.clone();
                    match observe_mysql(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk mysql: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk mysql: no greeting".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk mysql failed: {e}"),
                            });
                        }
                    }
                }
                "postgres" | "postgresql" | "pgsql" => {
                    let (addr, port) = parse_host_port(&target, 5432)?;
                    let emit = ctx.emit.clone();
                    match observe_postgres(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk postgres: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk postgres: no reply".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk postgres failed: {e}"),
                            });
                        }
                    }
                }
                "imap" => {
                    let (addr, port) = parse_host_port(&target, 143)?;
                    let emit = ctx.emit.clone();
                    match observe_imap(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk imap: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk imap: no greeting".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk imap failed: {e}"),
                            });
                        }
                    }
                }
                "pop3" | "pop" => {
                    let (addr, port) = parse_host_port(&target, 110)?;
                    let emit = ctx.emit.clone();
                    match observe_pop3(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk pop3: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk pop3: no greeting".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk pop3 failed: {e}"),
                            });
                        }
                    }
                }
                "mongo" | "mongodb" => {
                    let (addr, port) = parse_host_port(&target, 27017)?;
                    let emit = ctx.emit.clone();
                    match observe_mongodb(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk mongodb: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk mongodb: no reply".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk mongodb failed: {e}"),
                            });
                        }
                    }
                }
                "es" | "elastic" | "elasticsearch" => {
                    let (addr, port) = parse_host_port(&target, 9200)?;
                    let emit = ctx.emit.clone();
                    match observe_elasticsearch(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk elasticsearch: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk elasticsearch: no ES reply".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk elasticsearch failed: {e}"),
                            });
                        }
                    }
                }
                "memcache" | "memcached" => {
                    let (addr, port) = parse_host_port(&target, 11211)?;
                    let emit = ctx.emit.clone();
                    match observe_memcached(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk memcached: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk memcached: no reply".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk memcached failed: {e}"),
                            });
                        }
                    }
                }
                "kafka" => {
                    let (addr, port) = parse_host_port(&target, 9092)?;
                    let emit = ctx.emit.clone();
                    match observe_kafka(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk kafka: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk kafka: no ApiVersions reply".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk kafka failed: {e}"),
                            });
                        }
                    }
                }
                "amqp" | "rabbit" => {
                    let (addr, port) = parse_host_port(&target, 5672)?;
                    let emit = ctx.emit.clone();
                    match observe_amqp(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk amqp: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk amqp: no Connection.Start".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk amqp failed: {e}"),
                            });
                        }
                    }
                }
                "mqtt" => {
                    let (addr, port) = parse_host_port(&target, 1883)?;
                    let emit = ctx.emit.clone();
                    match observe_mqtt(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk mqtt: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk mqtt: no CONNACK".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk mqtt failed: {e}"),
                            });
                        }
                    }
                }
                "nats" => {
                    let (addr, port) = parse_host_port(&target, 4222)?;
                    let emit = ctx.emit.clone();
                    match observe_nats(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk nats: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk nats: no INFO".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk nats failed: {e}"),
                            });
                        }
                    }
                }
                "ldap" => {
                    let (addr, port) = parse_host_port(&target, 389)?;
                    let emit = ctx.emit.clone();
                    match observe_ldap(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk ldap: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk ldap: no RootDSE".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk ldap failed: {e}"),
                            });
                        }
                    }
                }
                "kerberos" | "krb5" | "krb" => {
                    let (addr, port) = parse_host_port(&target, 88)?;
                    let realm_hint = realm_from_target(&target);
                    let emit = ctx.emit.clone();
                    match observe_kerberos(addr, port, realm_hint.as_deref(), move |e| emit(e)).await
                    {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk kerberos: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk kerberos: no reply".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk kerberos failed: {e}"),
                            });
                        }
                    }
                }
                "vnc" | "rfb" => {
                    let (addr, port) = parse_host_port(&target, 5900)?;
                    let emit = ctx.emit.clone();
                    match observe_vnc(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk vnc: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk vnc: no RFB banner".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk vnc failed: {e}"),
                            });
                        }
                    }
                }
                "winrm" | "wsman" => {
                    let (addr, port) = parse_host_port(&target, 5985)?;
                    let emit = ctx.emit.clone();
                    match observe_winrm(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk winrm: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk winrm: no /wsman reply".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk winrm failed: {e}"),
                            });
                        }
                    }
                }
                "snmp" => {
                    let (addr, port) = parse_host_port(&target, 161)?;
                    let community = ctx
                        .extra
                        .get("community")
                        .and_then(|v| v.as_str())
                        .unwrap_or("public")
                        .to_string();
                    let emit = ctx.emit.clone();
                    match observe_snmp(addr, port, &community, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            let emit = ctx.emit.clone();
                            guess_os_from_banner(addr, &detail, move |e| emit(e));
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk snmp: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk snmp: no reply".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk snmp failed: {e}"),
                            });
                        }
                    }
                }
                "docker" => {
                    let (addr, port) = parse_host_port(&target, 2375)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_docker(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk docker: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk docker: no API".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk docker failed: {e}"),
                            });
                        }
                    }
                }
                "etcd" => {
                    let (addr, port) = parse_host_port(&target, 2379)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_etcd(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk etcd: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk etcd: no API".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk etcd failed: {e}"),
                            });
                        }
                    }
                }
                "consul" => {
                    let (addr, port) = parse_host_port(&target, 8500)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_consul(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk consul: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk consul: no API".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk consul failed: {e}"),
                            });
                        }
                    }
                }
                "mssql" | "sqlserver" => {
                    let (addr, port) = parse_host_port(&target, 1433)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_mssql(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk mssql: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk mssql: no TDS".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk mssql failed: {e}"),
                            });
                        }
                    }
                }
                "k8s" | "kubernetes" => {
                    let (addr, port) = parse_host_port(&target, 6443)?;
                    let sni = sni_name_from_target(&target);
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_kubernetes(
                        addr,
                        port,
                        sni.as_deref(),
                        move |e| emit(e),
                    )
                    .await
                    {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk kubernetes: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk kubernetes: no API".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk kubernetes failed: {e}"),
                            });
                        }
                    }
                }
                "oracle" | "tns" => {
                    let (addr, port) = parse_host_port(&target, 1521)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_oracle(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk oracle: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk oracle: no TNS".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk oracle failed: {e}"),
                            });
                        }
                    }
                }
                "couchdb" | "couch" => {
                    let (addr, port) = parse_host_port(&target, 5984)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_couchdb(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk couchdb: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk couchdb: no API".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk couchdb failed: {e}"),
                            });
                        }
                    }
                }
                "zookeeper" | "zk" => {
                    let (addr, port) = parse_host_port(&target, 2181)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_zookeeper(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk zookeeper: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk zookeeper: no ruok".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk zookeeper failed: {e}"),
                            });
                        }
                    }
                }
                "cassandra" | "cql" => {
                    let (addr, port) = parse_host_port(&target, 9042)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_cassandra(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk cassandra: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk cassandra: no native".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk cassandra failed: {e}"),
                            });
                        }
                    }
                }
                "rdp" | "mstsc" => {
                    let (addr, port) = parse_host_port(&target, 3389)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_rdp(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk rdp: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk rdp: no X.224".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk rdp failed: {e}"),
                            });
                        }
                    }
                }
                "neo4j" => {
                    let (addr, port) = parse_host_port(&target, 7474)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_neo4j(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk neo4j: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk neo4j: no API".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk neo4j failed: {e}"),
                            });
                        }
                    }
                }
                "clickhouse" | "ch" => {
                    let (addr, port) = parse_host_port(&target, 8123)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_clickhouse(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk clickhouse: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk clickhouse: no ping".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk clickhouse failed: {e}"),
                            });
                        }
                    }
                }
                "minio" | "s3" => {
                    let (addr, port) = parse_host_port(&target, 9000)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_minio(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk minio: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk minio: no S3".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk minio failed: {e}"),
                            });
                        }
                    }
                }
                "bolt" => {
                    let (addr, port) = parse_host_port(&target, 7687)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_bolt(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk bolt: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk bolt: no handshake".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk bolt failed: {e}"),
                            });
                        }
                    }
                }
                "rabbitmq" | "rmq" | "rabbitmq-mgmt" => {
                    let (addr, port) = parse_host_port(&target, 15672)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_rabbitmq(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk rabbitmq: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk rabbitmq: no management".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk rabbitmq failed: {e}"),
                            });
                        }
                    }
                }
                "grafana" => {
                    let (addr, port) = parse_host_port(&target, 3000)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_grafana(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk grafana: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk grafana: no API".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk grafana failed: {e}"),
                            });
                        }
                    }
                }
                "kibana" => {
                    let (addr, port) = parse_host_port(&target, 5601)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_kibana(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk kibana: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk kibana: no API".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk kibana failed: {e}"),
                            });
                        }
                    }
                }
                "prometheus" | "prom" => {
                    let (addr, port) = parse_host_port(&target, 9090)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_prometheus(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk prometheus: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk prometheus: no API".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk prometheus failed: {e}"),
                            });
                        }
                    }
                }
                "jenkins" => {
                    let (addr, port) = parse_host_port(&target, 8080)?;
                    let emit = ctx.emit.clone();
                    match ares_proto::observe_jenkins(addr, port, move |e| emit(e)).await {
                        Ok(Some(detail)) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "info".into(),
                                message: format!("talk jenkins: {detail}"),
                            });
                        }
                        Ok(None) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: "talk jenkins: no UI".into(),
                            });
                        }
                        Err(e) => {
                            ctx.emit(ares_core::Event::Log {
                                level: "warn".into(),
                                message: format!("talk jenkins failed: {e}"),
                            });
                        }
                    }
                }
                "http" | "auto" => {
                    let want_session = ctx
                        .extra
                        .get("session")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let mut follow_paths: Vec<String> = ctx
                        .extra
                        .get("follow_paths")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();

                    if let Ok(url) = Url::parse(&target) {
                        let host = url.host_str().unwrap_or("127.0.0.1").to_string();
                        let port = url.port_or_known_default().unwrap_or(80);
                        let path = {
                            let p = url.path();
                            if p.is_empty() {
                                "/".to_string()
                            } else {
                                p.to_string()
                            }
                        };
                        let addr = resolve_one(&host).await?;
                        let engine = HttpEngine::default();
                        let emit = ctx.emit.clone();
                        let use_tls = url.scheme() == "https" || port == 443 || port == 8443;
                        let sni = if host.parse::<IpAddr>().is_ok() {
                            None
                        } else {
                            Some(host.as_str())
                        };

                        if want_session {
                            let mut paths = vec![path.clone()];
                            if follow_paths.is_empty() {
                                follow_paths =
                                    vec!["/robots.txt".into(), "/login".into()];
                            }
                            for p in follow_paths {
                                let p = if p.starts_with('/') {
                                    p
                                } else {
                                    format!("/{p}")
                                };
                                if !paths.iter().any(|x| x == &p) {
                                    paths.push(p);
                                }
                            }
                            match engine
                                .session_browse(
                                    addr,
                                    port,
                                    &host,
                                    &paths,
                                    use_tls,
                                    sni,
                                    move |e| emit(e),
                                )
                                .await
                            {
                                Ok((sid, jar, resps)) => {
                                    if let Some(last) = resps.last() {
                                        if let Some((_, server)) = last
                                            .headers
                                            .iter()
                                            .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                                        {
                                            let emit = ctx.emit.clone();
                                            guess_os_from_banner(addr, server, move |e| emit(e));
                                        }
                                    }
                                    ctx.emit(ares_core::Event::Log {
                                        level: "info".into(),
                                        message: format!(
                                            "session {sid}: {} path(s), {} cookie(s) — last: {}",
                                            paths.len(),
                                            jar.len(),
                                            resps
                                                .last()
                                                .map(|r| r.status_line.as_str())
                                                .unwrap_or("-")
                                        ),
                                    });
                                }
                                Err(e) => {
                                    ctx.emit(ares_core::Event::Log {
                                        level: "warn".into(),
                                        message: format!("talk http session failed: {e}"),
                                    });
                                }
                            }
                        } else {
                            let result = if use_tls {
                                engine
                                    .get_tls(addr, port, &host, &path, sni, move |e| emit(e))
                                    .await
                            } else {
                                engine.get(addr, port, &host, &path, move |e| emit(e)).await
                            };
                            match result {
                                Ok(resp) => {
                                    if let Some((_, server)) = resp
                                        .headers
                                        .iter()
                                        .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                                    {
                                        let emit = ctx.emit.clone();
                                        guess_os_from_banner(addr, server, move |e| emit(e));
                                    }
                                    ctx.emit(ares_core::Event::Log {
                                        level: "info".into(),
                                        message: format!(
                                            "{} | body preview: {}{}{}",
                                            resp.status_line,
                                            resp.body_preview.chars().take(120).collect::<String>(),
                                            if resp.redirect_chain.len() > 1 {
                                                format!(
                                                    " | redirects: {}",
                                                    resp.redirect_chain.join(" → ")
                                                )
                                            } else {
                                                String::new()
                                            },
                                            if resp.cookies.is_empty() {
                                                String::new()
                                            } else {
                                                format!(" | cookies={}", resp.cookies.len())
                                            }
                                        ),
                                    });
                                }
                                Err(e) => {
                                    ctx.emit(ares_core::Event::Log {
                                        level: "warn".into(),
                                        message: format!("talk http failed: {e}"),
                                    });
                                }
                            }
                        }
                    } else {
                        let (addr, port) = parse_host_port(&target, 80)?;
                        let engine = HttpEngine::default();
                        let emit = ctx.emit.clone();
                        let sni = sni_name_from_target(&target);
                        let host = sni
                            .clone()
                            .unwrap_or_else(|| addr.to_string());
                        let use_tls = port == 443 || port == 8443;
                        if want_session {
                            let mut paths = vec!["/".into()];
                            if follow_paths.is_empty() {
                                follow_paths =
                                    vec!["/robots.txt".into(), "/login".into()];
                            }
                            for p in follow_paths {
                                let p = if p.starts_with('/') {
                                    p
                                } else {
                                    format!("/{p}")
                                };
                                if !paths.iter().any(|x| x == &p) {
                                    paths.push(p);
                                }
                            }
                            if let Err(e) = engine
                                .session_browse(
                                    addr,
                                    port,
                                    &host,
                                    &paths,
                                    use_tls,
                                    sni.as_deref(),
                                    move |e| emit(e),
                                )
                                .await
                            {
                                ctx.emit(ares_core::Event::Log {
                                    level: "warn".into(),
                                    message: format!("talk http session failed: {e}"),
                                });
                            }
                        } else {
                            let result = if use_tls {
                                engine
                                    .get_tls(
                                        addr,
                                        port,
                                        &host,
                                        "/",
                                        sni.as_deref(),
                                        move |e| emit(e),
                                    )
                                    .await
                            } else {
                                engine.get(addr, port, &host, "/", move |e| emit(e)).await
                            };
                            if let Err(e) = result {
                                ctx.emit(ares_core::Event::Log {
                                    level: "warn".into(),
                                    message: format!("talk http failed: {e}"),
                                });
                            }
                        }
                    }
                }
                other => anyhow::bail!(
                    "unknown talk proto: {other} (try auto|dns|http|h2|ssh|tls|smb|ftp|smtp|redis|mysql|postgres|mongodb|elasticsearch|memcached|kafka|amqp|mqtt|nats|ldap|kerberos|vnc|winrm|snmp|docker|etcd|consul|mssql|kubernetes|oracle|couchdb|zookeeper|cassandra|rdp|neo4j|clickhouse|minio|bolt|rabbitmq|grafana|kibana|prometheus|jenkins|imap|pop3)"
                ),
            }
            Ok(())
        })
    }
}

/// `dc.corp.local` → `CORP.LOCAL`; bare IP → None.
fn realm_from_target(target: &str) -> Option<String> {
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

fn sni_name_from_target(target: &str) -> Option<String> {
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
    if host.parse::<IpAddr>().is_ok() {
        None
    } else if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn parse_host_port(s: &str, default_port: u16) -> anyhow::Result<(IpAddr, u16)> {
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

async fn resolve_one(host: &str) -> anyhow::Result<IpAddr> {
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
