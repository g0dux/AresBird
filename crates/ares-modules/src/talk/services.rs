//! App-service talk protocols (DB/cache/messaging/cloud/webui/…).

use ares_plugin_api::ModuleCtx;
use ares_probe::guess_os_from_banner;
use ares_proto::apps::*;

use super::{parse_host_port, realm_from_target, sni_name_from_target};

pub(crate) async fn run(proto: &str, ctx: &ModuleCtx, target: &str) -> anyhow::Result<()> {
    match proto {
        "redis" => {
            let (addr, port) = parse_host_port(target, 6379)?;
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
            let (addr, port) = parse_host_port(target, 3306)?;
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
            let (addr, port) = parse_host_port(target, 5432)?;
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
            let (addr, port) = parse_host_port(target, 143)?;
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
            let (addr, port) = parse_host_port(target, 110)?;
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
            let (addr, port) = parse_host_port(target, 27017)?;
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
            let (addr, port) = parse_host_port(target, 9200)?;
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
            let (addr, port) = parse_host_port(target, 11211)?;
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
            let (addr, port) = parse_host_port(target, 9092)?;
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
            let (addr, port) = parse_host_port(target, 5672)?;
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
            let (addr, port) = parse_host_port(target, 1883)?;
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
            let (addr, port) = parse_host_port(target, 4222)?;
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
            let (addr, port) = parse_host_port(target, 389)?;
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
            let (addr, port) = parse_host_port(target, 88)?;
            let realm_hint = realm_from_target(target);
            let emit = ctx.emit.clone();
            match observe_kerberos(addr, port, realm_hint.as_deref(), move |e| emit(e)).await {
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
            let (addr, port) = parse_host_port(target, 5900)?;
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
            let (addr, port) = parse_host_port(target, 5985)?;
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
            let (addr, port) = parse_host_port(target, 161)?;
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
            let (addr, port) = parse_host_port(target, 2375)?;
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
            let (addr, port) = parse_host_port(target, 2379)?;
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
            let (addr, port) = parse_host_port(target, 8500)?;
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
            let (addr, port) = parse_host_port(target, 1433)?;
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
            let (addr, port) = parse_host_port(target, 6443)?;
            let sni = sni_name_from_target(target);
            let emit = ctx.emit.clone();
            match ares_proto::observe_kubernetes(addr, port, sni.as_deref(), move |e| emit(e)).await
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
            let (addr, port) = parse_host_port(target, 1521)?;
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
            let (addr, port) = parse_host_port(target, 5984)?;
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
            let (addr, port) = parse_host_port(target, 2181)?;
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
            let (addr, port) = parse_host_port(target, 9042)?;
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
            let (addr, port) = parse_host_port(target, 3389)?;
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
            let (addr, port) = parse_host_port(target, 7474)?;
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
            let (addr, port) = parse_host_port(target, 8123)?;
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
            let (addr, port) = parse_host_port(target, 9000)?;
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
            let (addr, port) = parse_host_port(target, 7687)?;
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
            let (addr, port) = parse_host_port(target, 15672)?;
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
            let (addr, port) = parse_host_port(target, 3000)?;
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
            let (addr, port) = parse_host_port(target, 5601)?;
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
            let (addr, port) = parse_host_port(target, 9090)?;
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
            let (addr, port) = parse_host_port(target, 8080)?;
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
        "influxdb" | "influx" => {
            let (addr, port) = parse_host_port(target, 8086)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_influxdb(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk influxdb: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk influxdb: no markers".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk influxdb failed: {e}"),
                    });
                }
            }
        }
        "rethinkdb" | "rethink" => {
            let (addr, port) = parse_host_port(target, 28015)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_rethinkdb(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk rethinkdb: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk rethinkdb: no handshake".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk rethinkdb failed: {e}"),
                    });
                }
            }
        }
        "scylla" | "scylladb" => {
            let (addr, port) = parse_host_port(target, 10000)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_scylla(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk scylla: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk scylla: no REST".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk scylla failed: {e}"),
                    });
                }
            }
        }
        "elastic-apm" | "apm" => {
            let (addr, port) = parse_host_port(target, 8200)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_elastic_apm(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk elastic-apm: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk elastic-apm: no markers".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk elastic-apm failed: {e}"),
                    });
                }
            }
        }
        "grpc" => {
            let (addr, port) = parse_host_port(target, 50051)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_grpc(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk grpc: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk grpc: no HTTP/2/gRPC".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk grpc failed: {e}"),
                    });
                }
            }
        }
        "vault" => {
            let (addr, port) = parse_host_port(target, 8200)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_vault(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk vault: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk vault: no health".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk vault failed: {e}"),
                    });
                }
            }
        }
        "nomad" => {
            let (addr, port) = parse_host_port(target, 4646)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_nomad(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk nomad: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk nomad: no markers".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk nomad failed: {e}"),
                    });
                }
            }
        }
        "solr" => {
            let (addr, port) = parse_host_port(target, 8983)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_solr(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk solr: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk solr: no markers".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk solr failed: {e}"),
                    });
                }
            }
        }
        "hazelcast" => {
            let (addr, port) = parse_host_port(target, 5701)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_hazelcast(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk hazelcast: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk hazelcast: no REST".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk hazelcast failed: {e}"),
                    });
                }
            }
        }
        "opensearch" => {
            let (addr, port) = parse_host_port(target, 9200)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_opensearch(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk opensearch: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk opensearch: no markers".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk opensearch failed: {e}"),
                    });
                }
            }
        }
        "keycloak" => {
            let (addr, port) = parse_host_port(target, 8080)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_keycloak(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk keycloak: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk keycloak: no markers".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk keycloak failed: {e}"),
                    });
                }
            }
        }
        "portainer" => {
            let (addr, port) = parse_host_port(target, 9000)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_portainer(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk portainer: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk portainer: no markers".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk portainer failed: {e}"),
                    });
                }
            }
        }
        "argocd" | "argo" => {
            let (addr, port) = parse_host_port(target, 8080)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_argocd(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk argocd: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk argocd: no markers".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk argocd failed: {e}"),
                    });
                }
            }
        }
        "sonarqube" | "sonar" => {
            let (addr, port) = parse_host_port(target, 9000)?;
            let emit = ctx.emit.clone();
            match ares_proto::observe_sonarqube(addr, port, move |e| emit(e)).await {
                Ok(Some(detail)) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "info".into(),
                        message: format!("talk sonarqube: {detail}"),
                    });
                }
                Ok(None) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: "talk sonarqube: no markers".into(),
                    });
                }
                Err(e) => {
                    ctx.emit(ares_core::Event::Log {
                        level: "warn".into(),
                        message: format!("talk sonarqube failed: {e}"),
                    });
                }
            }
        }
        _ => unreachable!("services dispatcher got {proto}"),
    }
    Ok(())
}
