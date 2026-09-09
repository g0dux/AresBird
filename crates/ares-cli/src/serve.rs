//! Local JSON control plane — `ares serve`.
//!
//! Binds a tiny HTTP/1.1 API (default `127.0.0.1:7420`) for workspace/runs
//! inspection and background job orchestration. No new HTTP framework deps:
//! request lines are parsed by hand over tokio TCP.
//!
//! Optional HTTPS: `--tls-cert` + `--tls-key` (PEM) via rustls / tokio-rustls.
//! TLS encrypts the wire; it does **not** replace bearer auth — non-loopback
//! binds still require `--token` unless `--allow-remote-no-auth`.
//!
//! Endpoints:
//! - `GET  /healthz`
//! - `GET  /v1/info`
//! - `GET  /v1/workspace?name=`
//! - `GET  /v1/runs`
//! - `GET  /v1/runs/{id}`
//! - `POST /v1/jobs`          JSON body → spawn module job
//! - `GET  /v1/jobs`
//! - `GET  /v1/jobs/{id}`
//!
//! When `--token` / `ARES_SERVE_TOKEN` is set, requests must send
//! `Authorization: Bearer <token>` (except `/healthz` and `/v1/openapi.json`).
//! Binding a non-loopback address without a token is refused unless
//! `--allow-remote-no-auth` is set (dangerous).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ares_core::event::Event;
use ares_core::parse_ports;
use ares_core::timing::ScanMode;
use ares_core::{AssetGraph, EventCollector, Job};
use ares_modules::builtin_registry;
use ares_output::{enriched_findings, findings_to_sarif_min, RunStore};
use ares_plugin_api::{register_discovered, ModuleCtx, PluginRegistry};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::workspace;

const MAX_BODY: usize = 256 * 1024;
const MAX_JOBS: usize = 256;

#[derive(Clone)]
pub struct ServeOpts {
    pub bind: String,
    pub token: Option<String>,
    pub workspace: String,
    /// Allow non-loopback bind without a bearer token (insecure).
    pub allow_remote_no_auth: bool,
    /// PEM certificate chain for HTTPS (with `tls_key`).
    pub tls_cert: Option<PathBuf>,
    /// PEM private key for HTTPS (with `tls_cert`).
    pub tls_key: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
struct JobRecord {
    id: Uuid,
    kind: String,
    module: String,
    targets: Vec<String>,
    status: JobStatus,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    error: Option<String>,
    findings: usize,
    hosts_up: usize,
    ports_open: usize,
    run_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    findings_detail: Option<serde_json::Value>,
}

#[derive(Default)]
struct JobStore {
    jobs: HashMap<Uuid, JobRecord>,
    order: Vec<Uuid>,
}

#[derive(Clone)]
struct AppState {
    registry: Arc<PluginRegistry>,
    jobs: Arc<Mutex<JobStore>>,
    token: Option<String>,
    workspace: String,
    tls: bool,
}

#[derive(Debug, Deserialize)]
struct JobRequest {
    /// `scan` | `probe` | `test` | `module`
    #[serde(default = "default_kind")]
    kind: String,
    /// Module name when `kind=module` (default: scan)
    #[serde(default)]
    module: Option<String>,
    targets: Vec<String>,
    #[serde(default)]
    ports: Option<String>,
    /// Probe profile when `kind=probe`
    #[serde(default)]
    profile: Option<String>,
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default)]
    save: bool,
    #[serde(default)]
    ephemeral: bool,
    #[serde(default)]
    extra: serde_json::Map<String, serde_json::Value>,
}

fn default_kind() -> String {
    "scan".into()
}
fn default_mode() -> String {
    "fast".into()
}

pub async fn run(opts: ServeOpts) -> anyhow::Result<()> {
    let mut registry = builtin_registry();
    let plugins_root = ares_plugin_api::resolve_plugins_root();
    let _ = register_discovered(&mut registry, &plugins_root);

    let tls_acceptor = match (&opts.tls_cert, &opts.tls_key) {
        (Some(cert), Some(key)) => Some(load_tls_acceptor(cert, key)?),
        (None, None) => None,
        _ => anyhow::bail!("--tls-cert and --tls-key must both be set (or neither)"),
    };
    let tls = tls_acceptor.is_some();
    let scheme = if tls { "https" } else { "http" };

    let state = AppState {
        registry: Arc::new(registry),
        jobs: Arc::new(Mutex::new(JobStore::default())),
        token: opts.token.clone(),
        workspace: opts.workspace,
        tls,
    };

    let listener = TcpListener::bind(&opts.bind).await?;
    let local = listener.local_addr()?;
    if !is_loopback(&local.ip()) && state.token.is_none() && !opts.allow_remote_no_auth {
        anyhow::bail!(
            "refusing to bind {} without --token / ARES_SERVE_TOKEN \
             (non-loopback). Pass --allow-remote-no-auth to override (insecure).",
            local
        );
    }
    if !is_loopback(&local.ip()) && state.token.is_none() {
        eprintln!("WARNING: serving on {local} with auth=off — anyone on the network can run jobs");
    }

    eprintln!(
        "ares serve listening on {scheme}://{local}  (workspace={}, auth={}, tls={})",
        state.workspace,
        if state.token.is_some() {
            "bearer"
        } else {
            "off"
        },
        if tls { "on" } else { "off" }
    );
    eprintln!("  GET  /healthz");
    eprintln!("  GET  /v1/info");
    eprintln!("  GET  /v1/openapi.json");
    eprintln!("  GET  /v1/workspace");
    eprintln!("  GET  /v1/runs");
    eprintln!("  GET  /v1/metrics");
    eprintln!("  POST /v1/jobs");
    eprintln!("  GET  /v1/jobs[|/{{id}}]");

    loop {
        let (sock, peer) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let state = state.clone();
        let acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let result = async {
                if let Some(acc) = acceptor {
                    let tls_sock = acc
                        .accept(sock)
                        .await
                        .map_err(|e| anyhow::anyhow!("tls handshake failed from {peer}: {e}"))?;
                    handle_client(tls_sock, peer, state).await
                } else {
                    handle_client(sock, peer, state).await
                }
            }
            .await;
            if let Err(e) = result {
                tracing::debug!("serve client error: {e}");
            }
        });
    }
}

fn load_tls_acceptor(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsAcceptor> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| anyhow::anyhow!("read TLS cert {}: {e}", cert_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("parse TLS cert {}: {e}", cert_path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }

    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| anyhow::anyhow!("read TLS key {}: {e}", key_path.display()))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("invalid TLS cert/key pair: {e}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn openapi_doc() -> serde_json::Value {
    serde_json::json!({
        "openapi": "3.0.3",
        "info": {
            "title": "AresBird Serve API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Local JSON control plane for workspace, runs, metrics, and jobs. Optional HTTPS via --tls-cert/--tls-key (PEM)."
        },
        "paths": {
            "/healthz": { "get": { "summary": "Liveness" } },
            "/v1/info": { "get": { "summary": "Engine info + modules" } },
            "/v1/openapi.json": { "get": { "summary": "This document" } },
            "/v1/workspace": { "get": { "summary": "Living workspace graph", "parameters": [{"name":"name","in":"query"}] } },
            "/v1/runs": { "get": { "summary": "List saved runs" } },
            "/v1/runs/{id}": { "get": { "summary": "Load a saved run" } },
            "/v1/metrics": { "get": { "summary": "Finding metrics", "parameters": [{"name":"run","in":"query"},{"name":"workspace","in":"query"}] } },
            "/v1/jobs": {
                "get": { "summary": "List jobs" },
                "post": {
                    "summary": "Spawn a job",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["targets"],
                                    "properties": {
                                        "kind": { "enum": ["scan","probe","test","module"] },
                                        "module": { "type": "string" },
                                        "targets": { "type": "array", "items": { "type": "string" } },
                                        "ports": { "type": "string" },
                                        "profile": { "type": "string" },
                                        "mode": { "type": "string" },
                                        "save": { "type": "boolean" },
                                        "ephemeral": { "type": "boolean" },
                                        "extra": { "type": "object" }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/jobs/{id}": { "get": { "summary": "Job status + findings" } },
            "/v1/export/sarif": { "get": { "summary": "SARIF export of a run", "parameters": [{"name":"run","in":"query"}] } }
        },
        "components": {
            "securitySchemes": {
                "bearer": { "type": "http", "scheme": "bearer" }
            }
        }
    })
}

async fn handle_client<S>(mut sock: S, _peer: SocketAddr, state: AppState) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(Duration::from_secs(30), sock.read(&mut buf)).await??;
    if n == 0 {
        return Ok(());
    }
    let head = String::from_utf8_lossy(&buf[..n]);
    let (method, path, headers, body_start) = parse_request_head(&head)?;
    let content_len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_BODY);

    let mut body = Vec::new();
    if body_start < n {
        body.extend_from_slice(&buf[body_start..n]);
    }
    while body.len() < content_len {
        let mut chunk = vec![0u8; 4096];
        let m = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut chunk)).await??;
        if m == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..m]);
        if body.len() > MAX_BODY {
            return write_json(
                &mut sock,
                413,
                &serde_json::json!({"error":"body too large"}),
            )
            .await;
        }
    }
    body.truncate(content_len);

    // Auth (except healthz + openapi)
    let path_no_q = path
        .split_once('?')
        .map(|(p, _)| p)
        .unwrap_or(path.as_str());
    if path_no_q != "/healthz" && path_no_q != "/v1/openapi.json" {
        if let Some(ref want) = state.token {
            let ok = headers
                .get("authorization")
                .map(|v| {
                    let v = v.trim();
                    v == want
                        || v.strip_prefix("Bearer ")
                            .or_else(|| v.strip_prefix("bearer "))
                            .map(|t| t.trim() == want)
                            .unwrap_or(false)
                })
                .unwrap_or(false);
            if !ok {
                return write_json(&mut sock, 401, &serde_json::json!({"error":"unauthorized"}))
                    .await;
            }
        }
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/healthz") => {
            write_json(
                &mut sock,
                200,
                &serde_json::json!({"ok": true, "service": "ares-serve"}),
            )
            .await
        }
        ("GET", "/v1/openapi.json") | ("GET", "/openapi.json") => {
            write_json(&mut sock, 200, &openapi_doc()).await
        }
        ("GET", "/v1/info") => {
            write_json(
                &mut sock,
                200,
                &serde_json::json!({
                    "name": "AresBird",
                    "version": env!("CARGO_PKG_VERSION"),
                    "api": ares_plugin_api::API_VERSION,
                    "modules": state.registry.list().iter().map(|m| m.name()).collect::<Vec<_>>(),
                    "workspace": state.workspace,
                    "event_schema": ares_core::EVENT_SCHEMA_VERSION,
                    "tls": state.tls,
                }),
            )
            .await
        }
        ("GET", p) if p.starts_with("/v1/metrics") => {
            let store = match RunStore::open_default() {
                Ok(s) => s,
                Err(e) => {
                    return write_json(
                        &mut sock,
                        500,
                        &serde_json::json!({"error": e.to_string()}),
                    )
                    .await;
                }
            };
            let collector =
                if query_param(p, "workspace").is_some() || path_has_flag(p, "workspace") {
                    let name = query_param(p, "name").unwrap_or_else(|| state.workspace.clone());
                    match store.load_workspace(&name) {
                        Ok(g) => collector_from_hosts(&g),
                        Err(e) => {
                            return write_json(
                                &mut sock,
                                500,
                                &serde_json::json!({"error": e.to_string()}),
                            )
                            .await;
                        }
                    }
                } else {
                    let id = if let Some(r) = query_param(p, "run") {
                        match Uuid::parse_str(&r) {
                            Ok(u) => u,
                            Err(_) => {
                                return write_json(
                                    &mut sock,
                                    400,
                                    &serde_json::json!({"error":"bad run id"}),
                                )
                                .await;
                            }
                        }
                    } else {
                        match store.list(1) {
                            Ok(runs) => match runs.first() {
                                Some((id, _, _)) => *id,
                                None => {
                                    return write_json(
                                        &mut sock,
                                        404,
                                        &serde_json::json!({"error":"no runs"}),
                                    )
                                    .await;
                                }
                            },
                            Err(e) => {
                                return write_json(
                                    &mut sock,
                                    500,
                                    &serde_json::json!({"error": e.to_string()}),
                                )
                                .await;
                            }
                        }
                    };
                    match store.load(id) {
                        Ok((c, _)) => c,
                        Err(e) => {
                            return write_json(
                                &mut sock,
                                404,
                                &serde_json::json!({"error": e.to_string()}),
                            )
                            .await;
                        }
                    }
                };
            let metrics = ares_output::findings_metrics(&collector, 0);
            write_json(&mut sock, 200, &metrics).await
        }
        ("GET", p) if p.starts_with("/v1/workspace") => {
            let name = query_param(p, "name").unwrap_or_else(|| state.workspace.clone());
            match RunStore::open_default().and_then(|s| s.load_workspace(&name)) {
                Ok(graph) => {
                    write_json(
                        &mut sock,
                        200,
                        &serde_json::json!({
                            "workspace": name,
                            "hosts": graph.hosts.len(),
                            "graph": graph,
                        }),
                    )
                    .await
                }
                Err(e) => {
                    write_json(&mut sock, 500, &serde_json::json!({"error": e.to_string()})).await
                }
            }
        }
        ("GET", "/v1/runs") => match RunStore::open_default().and_then(|s| s.list(50)) {
            Ok(runs) => {
                let rows: Vec<_> = runs
                    .into_iter()
                    .map(|(id, name, created)| {
                        serde_json::json!({
                            "id": id,
                            "name": name,
                            "created_at": created,
                        })
                    })
                    .collect();
                write_json(&mut sock, 200, &serde_json::json!({"runs": rows})).await
            }
            Err(e) => {
                write_json(&mut sock, 500, &serde_json::json!({"error": e.to_string()})).await
            }
        },
        ("GET", p) if p.starts_with("/v1/runs/") => {
            let id_s = p.trim_start_matches("/v1/runs/");
            let Ok(id) = Uuid::parse_str(id_s) else {
                return write_json(&mut sock, 400, &serde_json::json!({"error":"bad run id"}))
                    .await;
            };
            match RunStore::open_default().and_then(|s| s.load(id)) {
                Ok((collector, graph)) => {
                    let findings = enriched_findings(&collector, 0);
                    write_json(
                        &mut sock,
                        200,
                        &serde_json::json!({
                            "id": id,
                            "hosts_up": collector.hosts_up().len(),
                            "ports_open": collector.open_ports().len(),
                            "findings": findings,
                            "graph": graph,
                        }),
                    )
                    .await
                }
                Err(e) => {
                    write_json(&mut sock, 404, &serde_json::json!({"error": e.to_string()})).await
                }
            }
        }
        ("GET", "/v1/jobs") => {
            let list: Vec<_> = {
                let store = state.jobs.lock();
                store
                    .order
                    .iter()
                    .rev()
                    .filter_map(|id| store.jobs.get(id).cloned())
                    .map(|mut j| {
                        j.findings_detail = None;
                        j
                    })
                    .collect()
            };
            write_json(&mut sock, 200, &serde_json::json!({"jobs": list})).await
        }
        ("GET", p) if p.starts_with("/v1/jobs/") => {
            let id_s = p.trim_start_matches("/v1/jobs/");
            let Ok(id) = Uuid::parse_str(id_s) else {
                return write_json(&mut sock, 400, &serde_json::json!({"error":"bad job id"}))
                    .await;
            };
            let job = { state.jobs.lock().jobs.get(&id).cloned() };
            match job {
                Some(j) => write_json(&mut sock, 200, &j).await,
                None => {
                    write_json(
                        &mut sock,
                        404,
                        &serde_json::json!({"error":"job not found"}),
                    )
                    .await
                }
            }
        }
        ("POST", "/v1/jobs") => {
            let req: JobRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => {
                    return write_json(
                        &mut sock,
                        400,
                        &serde_json::json!({"error": format!("bad json: {e}")}),
                    )
                    .await;
                }
            };
            if req.targets.is_empty() {
                return write_json(
                    &mut sock,
                    400,
                    &serde_json::json!({"error":"targets required"}),
                )
                .await;
            }
            match spawn_job(state.clone(), req) {
                Ok(rec) => write_json(&mut sock, 202, &rec).await,
                Err(e) => {
                    write_json(&mut sock, 400, &serde_json::json!({"error": e.to_string()})).await
                }
            }
        }
        ("GET", p) if p.starts_with("/v1/export/sarif") => {
            // Export last run (or ?run=) as SARIF.
            let store = match RunStore::open_default() {
                Ok(s) => s,
                Err(e) => {
                    return write_json(
                        &mut sock,
                        500,
                        &serde_json::json!({"error": e.to_string()}),
                    )
                    .await;
                }
            };
            let id = if let Some(r) = query_param(p, "run") {
                match Uuid::parse_str(&r) {
                    Ok(u) => u,
                    Err(_) => {
                        return write_json(
                            &mut sock,
                            400,
                            &serde_json::json!({"error":"bad run id"}),
                        )
                        .await;
                    }
                }
            } else {
                match store.list(1) {
                    Ok(runs) => match runs.first() {
                        Some((id, _, _)) => *id,
                        None => {
                            return write_json(
                                &mut sock,
                                404,
                                &serde_json::json!({"error":"no runs"}),
                            )
                            .await;
                        }
                    },
                    Err(e) => {
                        return write_json(
                            &mut sock,
                            500,
                            &serde_json::json!({"error": e.to_string()}),
                        )
                        .await;
                    }
                }
            };
            match store.load(id) {
                Ok((c, _)) => {
                    let sarif = findings_to_sarif_min(&c, 0);
                    write_raw(&mut sock, 200, "application/sarif+json", sarif.as_bytes()).await
                }
                Err(e) => {
                    write_json(&mut sock, 404, &serde_json::json!({"error": e.to_string()})).await
                }
            }
        }
        _ => {
            write_json(
                &mut sock,
                404,
                &serde_json::json!({"error":"not found","path": path}),
            )
            .await
        }
    }
}

fn spawn_job(state: AppState, req: JobRequest) -> anyhow::Result<JobRecord> {
    let (module, mut extra) = resolve_job(&req)?;
    for (k, v) in req.extra {
        extra.insert(k, v);
    }
    let mode = ScanMode::from_str_loose(&req.mode);
    let ports = match &req.ports {
        Some(p) if !p.is_empty() => parse_ports(p)?,
        _ => Vec::new(),
    };

    let id = Uuid::new_v4();
    let rec = JobRecord {
        id,
        kind: req.kind.clone(),
        module: module.clone(),
        targets: req.targets.clone(),
        status: JobStatus::Queued,
        created_at: Utc::now(),
        finished_at: None,
        error: None,
        findings: 0,
        hosts_up: 0,
        ports_open: 0,
        run_id: None,
        findings_detail: None,
    };

    {
        let mut store = state.jobs.lock();
        if store.order.len() >= MAX_JOBS {
            // Drop oldest finished jobs first.
            if let Some(old) = store.order.first().copied() {
                store.jobs.remove(&old);
                store.order.remove(0);
            }
        }
        store.jobs.insert(id, rec.clone());
        store.order.push(id);
    }

    let workspace = state.workspace.clone();
    let registry = state.registry.clone();
    let jobs = state.jobs.clone();
    let targets = req.targets;
    let save = req.save;
    let ephemeral = req.ephemeral;

    tokio::spawn(async move {
        {
            let mut store = jobs.lock();
            if let Some(j) = store.jobs.get_mut(&id) {
                j.status = JobStatus::Running;
            }
        }

        let result = run_quiet_job(
            &registry, &module, targets, ports, mode, extra, true, save, ephemeral, &workspace,
        )
        .await;

        let mut store = jobs.lock();
        if let Some(j) = store.jobs.get_mut(&id) {
            j.finished_at = Some(Utc::now());
            match result {
                Ok((collector, _graph, run_id)) => {
                    j.status = JobStatus::Completed;
                    j.findings = collector.findings().len();
                    j.hosts_up = collector.hosts_up().len();
                    j.ports_open = collector.open_ports().len();
                    j.run_id = run_id;
                    j.findings_detail = serde_json::to_value(enriched_findings(&collector, 0)).ok();
                }
                Err(e) => {
                    j.status = JobStatus::Failed;
                    j.error = Some(e.to_string());
                }
            }
        }
    });

    Ok(rec)
}

fn resolve_job(
    req: &JobRequest,
) -> anyhow::Result<(String, serde_json::Map<String, serde_json::Value>)> {
    let mut extra = serde_json::Map::new();
    match req.kind.as_str() {
        "scan" => Ok(("scan".into(), extra)),
        "test" => Ok(("active-misconfig".into(), extra)),
        "probe" => {
            // Probe is a CLI composition; approximate with discover→scan→service→active
            // by running active-misconfig after scan via a single active module when
            // ports already imply apps. For the API we expose a pipeline-like shortcut:
            // run `scan` with service follow-up encoded as module chain is heavy —
            // instead run active-misconfig which scans when graph empty.
            let profile = req.profile.as_deref().unwrap_or("quick");
            extra.insert(
                "path_profile".into(),
                serde_json::Value::String(match profile {
                    "web" => "web".into(),
                    "apps" | "infra" => "all".into(),
                    _ => "default".into(),
                }),
            );
            // Prefer scan first for probe-like behaviour when caller wants ports.
            if req.ports.is_some() {
                Ok(("scan".into(), extra))
            } else {
                let ports = match profile {
                    "web" => "web",
                    "apps" => "apps",
                    "infra" => "infra",
                    _ => "22,80,443",
                };
                extra.insert(
                    "_default_ports".into(),
                    serde_json::Value::String(ports.into()),
                );
                Ok(("active-misconfig".into(), extra))
            }
        }
        "module" => {
            let name = req.module.clone().unwrap_or_else(|| "scan".into());
            Ok((name, extra))
        }
        other => anyhow::bail!("unknown kind `{other}` — use scan|probe|test|module"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_quiet_job(
    registry: &PluginRegistry,
    name: &str,
    targets: Vec<String>,
    mut ports: Vec<u16>,
    mode: ScanMode,
    mut extra: serde_json::Map<String, serde_json::Value>,
    active_allowed: bool,
    save: bool,
    ephemeral: bool,
    workspace_id: &str,
) -> anyhow::Result<(EventCollector, AssetGraph, Option<Uuid>)> {
    if ports.is_empty() {
        if let Some(p) = extra
            .remove("_default_ports")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
        {
            ports = parse_ports(&p)?;
        }
    }

    let module = registry
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("module not found: {name}"))?;

    let graph = Arc::new(Mutex::new(AssetGraph::new()));
    let collector = Arc::new(Mutex::new(EventCollector::new()));
    let cancel = CancellationToken::new();
    let mut job = Job::new(name, mode);
    job.mark_running();
    let job_id = job.id;

    let emit_graph = graph.clone();
    let emit_collector = collector.clone();
    let emit: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(move |event: Event| {
        emit_graph.lock().apply(&event);
        emit_collector.lock().push(event);
    });

    emit(Event::JobStarted {
        job_id,
        started_at: job.started_at.unwrap_or_else(Utc::now),
    });

    let ctx = ModuleCtx {
        cancel: cancel.clone(),
        mode,
        targets,
        ports,
        graph: graph.clone(),
        emit: emit.clone(),
        active_allowed,
        extra,
    };

    let result = module.run(ctx).await;

    let status = match &result {
        Ok(()) => {
            job.mark_completed();
            "completed".to_string()
        }
        Err(e) => {
            job.mark_failed(e.to_string());
            format!("failed: {e}")
        }
    };
    emit(Event::JobFinished {
        job_id,
        finished_at: job.finished_at.unwrap_or_else(Utc::now),
        status,
    });
    result?;

    let collector_out = collector.lock().clone();
    let graph_out = graph.lock().clone();

    let mut run_id = None;
    if save {
        let store = RunStore::open_default()?;
        run_id = Some(store.save(name, &collector_out, &graph_out)?);
    }
    if !ephemeral {
        workspace::merge_and_save(workspace_id, &collector_out, &graph_out, true)?;
    }

    Ok((collector_out, graph_out, run_id))
}

trait ScanModeParse {
    fn from_str_loose(s: &str) -> ScanMode;
}
impl ScanModeParse for ScanMode {
    fn from_str_loose(s: &str) -> ScanMode {
        s.parse().unwrap_or(ScanMode::Fast)
    }
}

fn parse_request_head(
    head: &str,
) -> anyhow::Result<(String, String, HashMap<String, String>, usize)> {
    let header_end = head
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| head.find("\n\n").map(|i| i + 2))
        .ok_or_else(|| anyhow::anyhow!("incomplete HTTP headers"))?;
    let header_block = &head[..header_end];
    let mut lines = header_block.lines();
    let req = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty request"))?;
    let mut parts = req.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("no method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("no path"))?
        .to_string();
    let mut headers = HashMap::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    // body_start relative to the original buffer: headers may use \r\n or \n
    let body_start = head[..header_end].len();
    Ok((method, path, headers, body_start))
}

fn query_param(path: &str, key: &str) -> Option<String> {
    let q = path.split_once('?')?.1;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(urlencoding_decode(v));
            }
        } else if pair == key {
            return Some("1".into());
        }
    }
    None
}

fn path_has_flag(path: &str, key: &str) -> bool {
    path.split_once('?')
        .map(|(_, q)| {
            q.split('&')
                .any(|p| p == key || p.starts_with(&format!("{key}=")))
        })
        .unwrap_or(false)
}

fn collector_from_hosts(graph: &AssetGraph) -> EventCollector {
    let mut c = EventCollector::new();
    for (addr, host) in &graph.hosts {
        for f in &host.findings {
            c.push(Event::MisconfigFinding {
                addr: *addr,
                port: f.port,
                finding: f.finding.clone(),
                severity: f.severity.clone(),
            });
        }
    }
    c
}

fn urlencoding_decode(s: &str) -> String {
    // Minimal: replace %XX and +
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let h = || -> Option<u8> {
                    let a = (bytes[i + 1] as char).to_digit(16)?;
                    let b = (bytes[i + 2] as char).to_digit(16)?;
                    Some(((a << 4) | b) as u8)
                };
                if let Some(c) = h() {
                    out.push(c as char);
                    i += 3;
                } else {
                    out.push('%');
                    i += 1;
                }
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

async fn write_json<S, T: Serialize>(sock: &mut S, status: u16, body: &T) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec_pretty(body)?;
    write_raw(sock, status, "application/json; charset=utf-8", &payload).await
}

async fn write_raw<S>(
    sock: &mut S,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Access-Control-Allow-Origin: *\r\n\
         X-Ares-Serve: 1\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(body).await?;
    sock.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_get() {
        let raw = "GET /v1/info HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (m, p, h, _) = parse_request_head(raw).unwrap();
        assert_eq!(m, "GET");
        assert_eq!(p, "/v1/info");
        assert_eq!(h.get("host").map(String::as_str), Some("localhost"));
    }

    #[test]
    fn query_param_works() {
        assert_eq!(
            query_param("/v1/workspace?name=lab", "name").as_deref(),
            Some("lab")
        );
    }

    #[test]
    fn tls_load_rejects_missing_cert() {
        let result = load_tls_acceptor(
            Path::new("definitely-missing-ares-cert.pem"),
            Path::new("definitely-missing-ares-key.pem"),
        );
        assert!(result.is_err(), "expected missing cert/key to fail");
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("TLS cert") || msg.contains("No such file") || msg.contains("os error"),
            "unexpected error: {msg}"
        );
    }
}
