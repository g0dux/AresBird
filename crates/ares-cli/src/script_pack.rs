//! Optional NSE-style script packs (`ares scan --script-pack`, `ares scripts`).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ares_core::event::Event;
use ares_core::timing::ScanMode;
use ares_plugin_api::{
    discover_plugin_dir, script_plugin_from, DiscoveredPlugin, Module, ModuleCtx, ScriptPlugin,
};
use parking_lot::Mutex;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Deserialize)]
pub struct PackMeta {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    /// When true (default), skip scripts tagged `aggressive`.
    #[serde(default = "default_true")]
    pub safe: bool,
    /// Built-in observe probes shipped with AresBird (no shell).
    #[serde(default)]
    pub builtins: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct PackScriptInfo {
    pub pack: String,
    pub name: String,
    pub description: String,
    pub ports: Vec<u16>,
    pub kind: &'static str, // "builtin" | "script"
    pub categories: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OpenPort {
    pub addr: IpAddr,
    pub port: u16,
    pub protocol: String,
}

/// Resolve packs root: `ARES_PACKS_DIR` or `<cwd>/packs`.
pub fn resolve_packs_root() -> PathBuf {
    if let Ok(p) = std::env::var("ARES_PACKS_DIR") {
        let path = PathBuf::from(p);
        if !path.as_os_str().is_empty() {
            return path;
        }
    }
    std::env::current_dir().unwrap_or_default().join("packs")
}

pub fn list_packs(root: impl AsRef<Path>) -> Vec<(String, PackMeta)> {
    let root = root.as_ref();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if name.starts_with('_') || name.starts_with('.') {
                continue;
            }
        }
        if let Some(meta) = load_pack_meta(&path) {
            out.push((meta.id.clone(), meta));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

pub fn load_pack_meta(pack_dir: &Path) -> Option<PackMeta> {
    let text = std::fs::read_to_string(pack_dir.join("pack.json")).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn list_scripts(root: impl AsRef<Path>, pack_filter: Option<&str>) -> Vec<PackScriptInfo> {
    let root = root.as_ref();
    let mut out = Vec::new();
    for (id, meta) in list_packs(root) {
        if let Some(f) = pack_filter {
            if id != f {
                continue;
            }
        }
        let pack_dir = root.join(&id);
        for b in &meta.builtins {
            if let Some(info) = builtin_info(&id, b) {
                out.push(info);
            }
        }
        for disc in discover_plugin_dir(&pack_dir) {
            if meta.safe && is_aggressive(&disc.manifest.categories) {
                continue;
            }
            out.push(PackScriptInfo {
                pack: id.clone(),
                name: disc.manifest.name.clone(),
                description: disc.manifest.description.clone().unwrap_or_default(),
                ports: disc.manifest.default_ports.clone(),
                kind: "script",
                categories: disc.manifest.categories.clone(),
            });
        }
    }
    out
}

fn is_aggressive(categories: &[String]) -> bool {
    categories
        .iter()
        .any(|c| c.eq_ignore_ascii_case("aggressive"))
}

fn builtin_info(pack: &str, name: &str) -> Option<PackScriptInfo> {
    let (desc, ports) = match name {
        "ftp-banner" => ("FTP 220 banner observe", vec![21]),
        "ssh-banner" => ("SSH protocol banner observe", vec![22]),
        "http-server" => (
            "HTTP Server header / title observe",
            vec![80, 8080, 8000, 8888],
        ),
        "redis-info" => ("Redis PING/NOAUTH observe", vec![6379]),
        "smtp-banner" => ("SMTP greeting observe", vec![25, 587]),
        "mysql-greeting" => ("MySQL/MariaDB greeting observe", vec![3306]),
        "postgres-startup" => ("PostgreSQL SSLRequest/startup observe", vec![5432]),
        "mongodb-hello" => ("MongoDB hello/isMaster observe", vec![27017]),
        "memcached-stats" => ("Memcached version/stats observe", vec![11211]),
        "elasticsearch-root" => ("Elasticsearch cluster/version observe", vec![9200]),
        "ldap-rootdse" => ("LDAP RootDSE observe", vec![389]),
        "docker-version" => ("Docker Engine /version observe", vec![2375]),
        "etcd-version" => ("etcd /version+/health observe", vec![2379]),
        "consul-leader" => ("Consul /v1/status/leader observe", vec![8500]),
        "mqtt-connect" => ("MQTT CONNECT observe", vec![1883]),
        "amqp-start" => ("AMQP Connection.Start observe", vec![5672]),
        "nats-info" => ("NATS INFO greeting observe", vec![4222]),
        "mssql-prelogin" => ("MSSQL TDS PreLogin observe", vec![1433]),
        "rdp-negotiate" => ("RDP negotiation observe", vec![3389]),
        "vnc-rfb" => ("VNC RFB banner observe", vec![5900]),
        "grafana-health" => ("Grafana /api/health observe", vec![3000]),
        "jenkins-headers" => ("Jenkins UI markers observe", vec![8080]),
        "keycloak-realm" => ("Keycloak /realms/master observe", vec![8080]),
        "portainer-status" => ("Portainer /api/system/status observe", vec![9000]),
        "argocd-version" => ("Argo CD /api/version observe", vec![8080]),
        "sonarqube-status" => ("SonarQube system status observe", vec![9000]),
        "cassandra-options" => ("Cassandra OPTIONS observe", vec![9042]),
        "zookeeper-ruok" => ("ZooKeeper ruok/srvr observe", vec![2181]),
        "kafka-versions" => ("Kafka ApiVersions observe", vec![9092]),
        "kibana-status" => ("Kibana /api/status observe", vec![5601]),
        "prometheus-healthy" => ("Prometheus /-/healthy observe", vec![9090]),
        "couchdb-welcome" => ("CouchDB welcome JSON observe", vec![5984]),
        "neo4j-discovery" => ("Neo4j discovery JSON observe", vec![7474]),
        "clickhouse-ping" => ("ClickHouse /ping observe", vec![8123]),
        "minio-health" => ("MinIO health observe", vec![9000]),
        "rabbitmq-mgmt" => ("RabbitMQ management observe", vec![15672]),
        "kubernetes-version" => ("Kubernetes /version observe", vec![6443]),
        "imap-banner" => ("IMAP greeting observe", vec![143]),
        "pop3-banner" => ("POP3 greeting observe", vec![110]),
        "influxdb-health" => ("InfluxDB /health+/ping observe", vec![8086]),
        "rethinkdb-handshake" => ("RethinkDB V0_4 handshake observe", vec![28015]),
        "scylla-rest" => ("ScyllaDB REST release version observe", vec![10000]),
        "elastic-apm-root" => ("Elastic APM Server root observe", vec![8200]),
        "grpc-http2" => ("gRPC/HTTP/2 cleartext observe", vec![50051]),
        "vault-health" => ("Vault /v1/sys/health observe", vec![8200]),
        "nomad-agent" => ("Nomad agent/self observe", vec![4646]),
        "solr-system" => ("Solr admin/info/system observe", vec![8983]),
        "hazelcast-cluster" => ("Hazelcast REST cluster observe", vec![5701]),
        "opensearch-root" => ("OpenSearch root JSON observe", vec![9200]),
        _ => return None,
    };
    Some(PackScriptInfo {
        pack: pack.into(),
        name: name.into(),
        description: desc.into(),
        ports,
        kind: "builtin",
        categories: vec!["safe".into(), "default".into()],
    })
}

/// Run an opt-in script pack against open ports. Emits findings into `emit`.
pub async fn run_script_pack(
    pack_id: &str,
    open: &[OpenPort],
    mode: ScanMode,
    quiet: bool,
    emit: Arc<dyn Fn(Event) + Send + Sync>,
    cancel: CancellationToken,
) -> anyhow::Result<usize> {
    if open.is_empty() {
        if !quiet {
            eprintln!("[script-pack] no open ports — skipping pack `{pack_id}`");
        }
        return Ok(0);
    }

    let root = resolve_packs_root();
    let pack_dir = root.join(pack_id);
    let meta = load_pack_meta(&pack_dir).ok_or_else(|| {
        anyhow::anyhow!(
            "script pack `{pack_id}` not found under {} (set ARES_PACKS_DIR)",
            root.display()
        )
    })?;

    emit(Event::Log {
        level: "info".into(),
        message: format!(
            "script-pack `{pack_id}` starting ({} open ports, safe={})",
            open.len(),
            meta.safe
        ),
    });

    let open_csv: String = open
        .iter()
        .map(|o| format!("{}:{}/{}", o.addr, o.port, o.protocol))
        .collect::<Vec<_>>()
        .join(",");
    let open_json: Vec<serde_json::Value> = open
        .iter()
        .map(|o| {
            serde_json::json!({
                "addr": o.addr.to_string(),
                "port": o.port,
                "protocol": o.protocol,
            })
        })
        .collect();

    let mut ran = 0usize;

    // Builtins
    for name in &meta.builtins {
        if cancel.is_cancelled() {
            break;
        }
        let Some(info) = builtin_info(pack_id, name) else {
            emit(Event::Log {
                level: "warn".into(),
                message: format!("unknown builtin script `{name}` in pack `{pack_id}`"),
            });
            continue;
        };
        for op in open {
            if cancel.is_cancelled() {
                break;
            }
            if !info.ports.is_empty() && !info.ports.contains(&op.port) {
                continue;
            }
            if op.protocol.eq_ignore_ascii_case("udp") {
                continue;
            }
            ran += 1;
            run_builtin(name, op, &emit).await;
        }
    }

    // External scripts in pack dir
    for disc in discover_plugin_dir(&pack_dir) {
        if cancel.is_cancelled() {
            break;
        }
        if meta.safe && is_aggressive(&disc.manifest.categories) {
            continue;
        }
        let Some(command) = disc.manifest.resolved_command().map(str::to_string) else {
            continue;
        };
        let Some(plugin) = script_plugin_from(&disc, command) else {
            continue;
        };
        let proto = disc
            .manifest
            .protocol
            .as_deref()
            .unwrap_or("tcp")
            .to_ascii_lowercase();

        // Group matching opens by addr for efficient runs (one process per host with matching ports)
        let mut by_addr: std::collections::BTreeMap<IpAddr, Vec<u16>> =
            std::collections::BTreeMap::new();
        for op in open {
            if !proto_matches(&proto, &op.protocol) {
                continue;
            }
            if !disc.manifest.default_ports.is_empty()
                && !disc.manifest.default_ports.contains(&op.port)
            {
                continue;
            }
            by_addr.entry(op.addr).or_default().push(op.port);
        }

        for (addr, mut ports) in by_addr {
            if cancel.is_cancelled() {
                break;
            }
            ports.sort_unstable();
            let mut extra = serde_json::Map::new();
            extra.insert("pack".into(), serde_json::json!(pack_id));
            extra.insert(
                "open_ports".into(),
                serde_json::Value::Array(open_json.clone()),
            );
            extra.insert("open_ports_csv".into(), serde_json::json!(open_csv));
            let ctx = ModuleCtx {
                cancel: cancel.clone(),
                mode,
                targets: vec![addr.to_string()],
                ports,
                graph: Arc::new(Mutex::new(ares_core::AssetGraph::new())),
                emit: emit.clone(),
                active_allowed: false,
                extra,
            };
            ran += 1;
            if let Err(e) = plugin.run(ctx).await {
                emit(Event::Log {
                    level: "warn".into(),
                    message: format!("script-pack `{}` failed: {e}", plugin.name()),
                });
            }
        }
    }

    emit(Event::Log {
        level: "info".into(),
        message: format!("script-pack `{pack_id}` finished ({ran} script invocation(s))"),
    });
    Ok(ran)
}

fn proto_matches(want: &str, have: &str) -> bool {
    match want {
        "any" => true,
        "udp" => have.eq_ignore_ascii_case("udp"),
        _ => have.eq_ignore_ascii_case("tcp") || have.is_empty(),
    }
}

async fn run_builtin(name: &str, op: &OpenPort, emit: &Arc<dyn Fn(Event) + Send + Sync>) {
    match name {
        "ftp-banner" => builtin_banner(op, emit, "ftp-banner", true).await,
        "ssh-banner" => {
            let e = emit.clone();
            let _ = ares_proto::SshBanner::grab(op.addr, op.port, move |ev| e(ev)).await;
        }
        "http-server" => builtin_http_server(op, emit).await,
        "smtp-banner" => builtin_banner(op, emit, "smtp-banner", true).await,
        "redis-info" => builtin_redis(op, emit).await,
        "mysql-greeting" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "mysql-greeting",
                ares_proto::observe_mysql(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "postgres-startup" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "postgres-startup",
                ares_proto::observe_postgres(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "mongodb-hello" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "mongodb-hello",
                ares_proto::observe_mongodb(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "memcached-stats" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "memcached-stats",
                ares_proto::observe_memcached(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "elasticsearch-root" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "elasticsearch-root",
                ares_proto::observe_elasticsearch(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "ldap-rootdse" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "ldap-rootdse",
                ares_proto::observe_ldap(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "docker-version" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "docker-version",
                ares_proto::observe_docker(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "etcd-version" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "etcd-version",
                ares_proto::observe_etcd(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "consul-leader" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "consul-leader",
                ares_proto::observe_consul(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "mqtt-connect" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "mqtt-connect",
                ares_proto::observe_mqtt(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "amqp-start" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "amqp-start",
                ares_proto::observe_amqp(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "nats-info" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "nats-info",
                ares_proto::observe_nats(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "mssql-prelogin" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "mssql-prelogin",
                ares_proto::observe_mssql(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "rdp-negotiate" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "rdp-negotiate",
                ares_proto::observe_rdp(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "vnc-rfb" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "vnc-rfb",
                ares_proto::observe_vnc(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "grafana-health" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "grafana-health",
                ares_proto::observe_grafana(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "jenkins-headers" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "jenkins-headers",
                ares_proto::observe_jenkins(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "keycloak-realm" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "keycloak-realm",
                ares_proto::observe_keycloak(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "portainer-status" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "portainer-status",
                ares_proto::observe_portainer(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "argocd-version" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "argocd-version",
                ares_proto::observe_argocd(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "sonarqube-status" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "sonarqube-status",
                ares_proto::observe_sonarqube(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "cassandra-options" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "cassandra-options",
                ares_proto::observe_cassandra(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "zookeeper-ruok" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "zookeeper-ruok",
                ares_proto::observe_zookeeper(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "kafka-versions" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "kafka-versions",
                ares_proto::observe_kafka(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "kibana-status" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "kibana-status",
                ares_proto::observe_kibana(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "prometheus-healthy" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "prometheus-healthy",
                ares_proto::observe_prometheus(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "couchdb-welcome" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "couchdb-welcome",
                ares_proto::observe_couchdb(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "neo4j-discovery" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "neo4j-discovery",
                ares_proto::observe_neo4j(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "clickhouse-ping" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "clickhouse-ping",
                ares_proto::observe_clickhouse(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "minio-health" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "minio-health",
                ares_proto::observe_minio(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "rabbitmq-mgmt" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "rabbitmq-mgmt",
                ares_proto::observe_rabbitmq(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "kubernetes-version" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "kubernetes-version",
                ares_proto::observe_kubernetes(op.addr, op.port, None, move |ev| e(ev)),
            )
            .await;
        }
        "imap-banner" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "imap-banner",
                ares_proto::observe_imap(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "pop3-banner" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "pop3-banner",
                ares_proto::observe_pop3(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "influxdb-health" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "influxdb-health",
                ares_proto::observe_influxdb(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "rethinkdb-handshake" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "rethinkdb-handshake",
                ares_proto::observe_rethinkdb(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "scylla-rest" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "scylla-rest",
                ares_proto::observe_scylla(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "elastic-apm-root" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "elastic-apm-root",
                ares_proto::observe_elastic_apm(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "grpc-http2" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "grpc-http2",
                ares_proto::observe_grpc(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "vault-health" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "vault-health",
                ares_proto::observe_vault(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "nomad-agent" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "nomad-agent",
                ares_proto::observe_nomad(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "solr-system" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "solr-system",
                ares_proto::observe_solr(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "hazelcast-cluster" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "hazelcast-cluster",
                ares_proto::observe_hazelcast(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        "opensearch-root" => {
            let e = emit.clone();
            pack_observe(
                op,
                emit,
                "opensearch-root",
                ares_proto::observe_opensearch(op.addr, op.port, move |ev| e(ev)),
            )
            .await;
        }
        _ => {}
    }
}

async fn pack_observe(
    op: &OpenPort,
    emit: &Arc<dyn Fn(Event) + Send + Sync>,
    probe: &str,
    fut: impl std::future::Future<Output = anyhow::Result<Option<String>>>,
) {
    match fut.await {
        Ok(Some(detail)) => {
            emit(Event::MisconfigFinding {
                addr: op.addr,
                port: Some(op.port),
                finding: format!("{probe}: {detail}"),
                severity: "info".into(),
            });
        }
        Ok(None) => {}
        Err(err) => {
            emit(Event::Log {
                level: "debug".into(),
                message: format!("{probe} @{}:{} failed: {err}", op.addr, op.port),
            });
        }
    }
}

async fn builtin_banner(
    op: &OpenPort,
    emit: &Arc<dyn Fn(Event) + Send + Sync>,
    probe: &str,
    finding_on_banner: bool,
) {
    let sa = std::net::SocketAddr::new(op.addr, op.port);
    let Ok(Ok(mut stream)) = timeout(Duration::from_secs(3), TcpStream::connect(sa)).await else {
        return;
    };
    let mut buf = [0u8; 512];
    let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut buf)).await else {
        return;
    };
    if n == 0 {
        return;
    }
    let banner = String::from_utf8_lossy(&buf[..n])
        .trim()
        .chars()
        .take(120)
        .collect::<String>();
    if banner.is_empty() {
        return;
    }
    emit(Event::Banner {
        addr: op.addr,
        port: op.port,
        banner: banner.clone(),
    });
    emit(Event::ProbeResult {
        addr: op.addr,
        port: op.port,
        probe: probe.into(),
        detail: banner.clone(),
        confidence: 0.85,
    });
    if finding_on_banner {
        let sev = if probe.starts_with("ftp") || probe.starts_with("smtp") {
            "low"
        } else {
            "info"
        };
        emit(Event::MisconfigFinding {
            addr: op.addr,
            port: Some(op.port),
            finding: format!("{probe}: exposed service banner — {banner}"),
            severity: sev.into(),
        });
    }
}

async fn builtin_http_server(op: &OpenPort, emit: &Arc<dyn Fn(Event) + Send + Sync>) {
    let sa = std::net::SocketAddr::new(op.addr, op.port);
    let Ok(Ok(mut stream)) = timeout(Duration::from_secs(3), TcpStream::connect(sa)).await else {
        return;
    };
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: AresBird/0.1\r\nConnection: close\r\n\r\n",
        op.addr
    );
    let _ = timeout(Duration::from_secs(2), stream.write_all(req.as_bytes())).await;
    let mut buf = Vec::new();
    let _ = timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    let server = header_value(&text, "server");
    let title = extract_title(&text);
    let mut detail = String::new();
    if let Some(s) = &server {
        detail.push_str(&format!("Server={s}"));
    }
    if let Some(t) = &title {
        if !detail.is_empty() {
            detail.push(';');
        }
        detail.push_str(&format!("title={t}"));
    }
    if detail.is_empty() {
        return;
    }
    emit(Event::ProbeResult {
        addr: op.addr,
        port: op.port,
        probe: "http-server".into(),
        detail: detail.clone(),
        confidence: 0.8,
    });
    emit(Event::MisconfigFinding {
        addr: op.addr,
        port: Some(op.port),
        finding: format!("http-server: {detail}"),
        severity: "info".into(),
    });
}

async fn builtin_redis(op: &OpenPort, emit: &Arc<dyn Fn(Event) + Send + Sync>) {
    let sa = std::net::SocketAddr::new(op.addr, op.port);
    let Ok(Ok(mut stream)) = timeout(Duration::from_secs(3), TcpStream::connect(sa)).await else {
        return;
    };
    let _ = timeout(Duration::from_secs(2), stream.write_all(b"PING\r\n")).await;
    let mut buf = [0u8; 256];
    let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut buf)).await else {
        return;
    };
    let resp = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    emit(Event::ProbeResult {
        addr: op.addr,
        port: op.port,
        probe: "redis-info".into(),
        detail: resp.clone(),
        confidence: 0.9,
    });
    if resp.contains("+PONG") {
        emit(Event::MisconfigFinding {
            addr: op.addr,
            port: Some(op.port),
            finding: "redis-info: Redis answered PONG without AUTH".into(),
            severity: "high".into(),
        });
    } else if resp.contains("NOAUTH") || resp.contains("-NOAUTH") {
        emit(Event::MisconfigFinding {
            addr: op.addr,
            port: Some(op.port),
            finding: "redis-info: Redis requires AUTH (reachable)".into(),
            severity: "info".into(),
        });
    }
}

fn header_value(http: &str, name: &str) -> Option<String> {
    for line in http.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
        if line.trim().is_empty() {
            break;
        }
    }
    None
}

fn extract_title(http: &str) -> Option<String> {
    let lower = http.to_ascii_lowercase();
    let start = lower.find("<title>")? + 7;
    let end = lower[start..].find("</title>")? + start;
    let t = http[start..end].trim();
    if t.is_empty() {
        None
    } else {
        Some(t.chars().take(80).collect())
    }
}

/// Silence unused import warning when only listing.
#[allow(dead_code)]
fn _unused_disc(_: &DiscoveredPlugin, _: &ScriptPlugin) {}
