//! cloud service observers (shared helpers live in the parent module).

use super::*;

/// Docker Engine API (typically :2375 unencrypted) -- `/_ping` + `/version`.
pub async fn observe_docker(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, ping) = http_get_body(addr, port, "/_ping").await?;
    let ping_ok = st == 200 && ping.trim().eq_ignore_ascii_case("OK");
    if !ping_ok {
        // Some installs answer /version without /_ping
        let (st2, ver_body) = http_get_body(addr, port, "/version").await?;
        if st2 != 200
            || !(ver_body.contains("ApiVersion")
                || ver_body.contains("Version")
                || ver_body.contains("\"Os\""))
        {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "docker".into(),
                detail: format!("no Docker API markers (ping={st})"),
                confidence: 0.2,
            });
            return Ok(None);
        }
        let api = json_string_field(&ver_body, "ApiVersion");
        let ver = json_string_field(&ver_body, "Version");
        let detail = match (&api, &ver) {
            (Some(a), Some(v)) => format!("Docker Engine API {a} version={v}"),
            (Some(a), None) => format!("Docker Engine API {a}"),
            (None, Some(v)) => format!("Docker Engine version={v}"),
            _ => "Docker Engine API".into(),
        };
        emit_docker(addr, port, &detail, ver, &emit);
        return Ok(Some(detail));
    }

    let (st2, ver_body) = http_get_body(addr, port, "/version")
        .await
        .unwrap_or((0, String::new()));
    let api = json_string_field(&ver_body, "ApiVersion");
    let ver = json_string_field(&ver_body, "Version");
    let detail = match (&api, &ver) {
        (Some(a), Some(v)) => format!("Docker Engine API {a} version={v} (ping OK)"),
        (Some(a), None) => format!("Docker Engine API {a} (ping OK)"),
        _ if st2 == 200 => "Docker Engine API (/_ping OK)".into(),
        _ => "Docker Engine API (/_ping OK)".into(),
    };
    emit_docker(addr, port, &detail, ver, &emit);
    Ok(Some(detail))
}

/// etcd HTTP API -- `/version` / `/health`.
pub async fn observe_etcd(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, body) = http_get_body(addr, port, "/version").await?;
    let looks = body.contains("etcdserver")
        || body.contains("etcdcluster")
        || (body.contains("etcd") && body.contains("version"));
    if st != 200 || !looks {
        let (st2, health) = http_get_body(addr, port, "/health").await?;
        if st2 == 200 && (health.contains("true") || health.contains("\"health\"")) {
            let detail = format!(
                "etcd health reachable ({})",
                health.chars().take(60).collect::<String>()
            );
            emit_etcd(addr, port, &detail, None, &emit);
            return Ok(Some(detail));
        }
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "etcd".into(),
            detail: format!("no etcd markers (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }
    let server = json_string_field(&body, "etcdserver");
    let cluster = json_string_field(&body, "etcdcluster");
    let detail = match (&server, &cluster) {
        (Some(s), Some(c)) => format!("etcd server={s} cluster={c}"),
        (Some(s), None) => format!("etcd server={s}"),
        _ => "etcd".into(),
    };
    emit_etcd(addr, port, &detail, server, &emit);
    Ok(Some(detail))
}

/// Consul HTTP API -- `/v1/status/leader` (unauthenticated lab exposure).
pub async fn observe_consul(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, leader) = http_get_body(addr, port, "/v1/status/leader").await?;
    let leader_trim = leader.trim().trim_matches('"');
    let looks_leader = st == 200
        && !leader_trim.is_empty()
        && (leader_trim.contains(':') || leader_trim.parse::<IpAddr>().is_ok());

    if !looks_leader {
        let (st2, agent) = http_get_body(addr, port, "/v1/agent/self").await?;
        if st2 != 200
            || !(agent.contains("Config") || agent.contains("Member") || agent.contains("\"Name\""))
        {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "consul".into(),
                detail: format!("no Consul API markers (leader status={st})"),
                confidence: 0.2,
            });
            return Ok(None);
        }
        let name = json_string_field(&agent, "Name");
        let detail = name
            .as_ref()
            .map(|n| format!("Consul agent={n}"))
            .unwrap_or_else(|| "Consul agent/self reachable".into());
        emit_consul(addr, port, &detail, name, &emit);
        return Ok(Some(detail));
    }

    let detail = format!("Consul leader={leader_trim}");
    emit_consul(addr, port, &detail, None, &emit);
    Ok(Some(detail))
}

/// Kubernetes API server observe (typically :6443 HTTPS) -- `/version` / `/readyz`.
pub async fn observe_kubernetes(
    addr: IpAddr,
    port: u16,
    sni: Option<&str>,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    use crate::http::HttpEngine;

    let engine = HttpEngine {
        timeout: Duration::from_secs(5),
        max_redirects: 0,
        ..Default::default()
    };
    let host = sni
        .map(|s| s.to_string())
        .unwrap_or_else(|| addr.to_string());
    let sni_opt = if host.parse::<IpAddr>().is_ok() {
        None
    } else {
        Some(host.as_str())
    };

    // Prefer /version JSON
    let ver = engine
        .get_tls(addr, port, &host, "/version", sni_opt, |_| {})
        .await;
    if let Ok(resp) = ver {
        let body = &resp.body_preview;
        let status = &resp.status_line;
        let git = json_string_field(body, "gitVersion");
        let plat = json_string_field(body, "platform");
        let looks = git.is_some()
            || body.contains("gitVersion")
            || body.contains("k8s")
            || (status.contains("401")
                && (body.contains("Unauthorized") || body.contains("Forbidden")));

        if looks {
            let detail = match (&git, &plat) {
                (Some(g), Some(p)) => format!("Kubernetes API {g} platform={p}"),
                (Some(g), None) => format!("Kubernetes API {g}"),
                _ if status.contains("401") || status.contains("403") => {
                    "Kubernetes API (auth required)".into()
                }
                _ => format!(
                    "Kubernetes API ({})",
                    status.chars().take(40).collect::<String>()
                ),
            };
            emit_k8s(addr, port, &detail, git, &emit);
            return Ok(Some(detail));
        }
    }

    // Fallback health endpoints (often unauthenticated on misconfig)
    for path in ["/readyz", "/livez", "/healthz"] {
        if let Ok(resp) = engine
            .get_tls(addr, port, &host, path, sni_opt, |_| {})
            .await
        {
            let body = resp.body_preview.to_ascii_lowercase();
            let ok = resp.status_line.contains("200")
                && (body.contains("ok") || body.trim().is_empty() || body.contains("ready"));
            if ok || (resp.status_line.contains("401") && body.contains("unauthorized")) {
                let detail = if resp.status_line.contains("200") {
                    format!("Kubernetes API health {path} OK")
                } else {
                    format!("Kubernetes API {path} (auth required)")
                };
                emit_k8s(addr, port, &detail, None, &emit);
                return Ok(Some(detail));
            }
        }
    }

    emit(Event::ProbeResult {
        addr,
        port,
        probe: "kubernetes".into(),
        detail: "no Kubernetes API markers".into(),
        confidence: 0.2,
    });
    Ok(None)
}

/// MinIO / S3-compatible HTTP observe (default :9000).
pub async fn observe_minio(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    // MinIO health endpoint is a strong signal when enabled.
    let (hst, _hraw, _hbody) = http_get_raw(addr, port, "/minio/health/live").await?;
    let health_ok = hst == 200;

    let (st, raw, body) = http_get_raw(addr, port, "/").await?;
    let server = http_header_value(&raw, "Server").unwrap_or_default();
    let amz_id = http_header_value(&raw, "x-amz-request-id")
        .or_else(|| http_header_value(&raw, "x-amz-id-2"));
    let lower_body = body.to_ascii_lowercase();
    let lower_srv = server.to_ascii_lowercase();

    let is_minio = health_ok
        || lower_srv.contains("minio")
        || lower_body.contains("minio")
        || (lower_body.contains("<error>") && lower_body.contains("minio"));
    let is_s3 = amz_id.is_some()
        || lower_srv.contains("amazons3")
        || lower_body.contains("amazonaws")
        || (lower_body.contains("accessdenied") && lower_body.contains("s3"));

    if !is_minio && !is_s3 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "minio".into(),
            detail: format!("no MinIO/S3 markers (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let (name, product, detail) = if is_minio {
        let detail = if !server.is_empty() && lower_srv.contains("minio") {
            format!("MinIO ({server})")
        } else if health_ok {
            "MinIO (health/live)".into()
        } else {
            "MinIO/S3-compatible".into()
        };
        ("minio", "MinIO", detail)
    } else {
        let detail = if !server.is_empty() {
            format!("S3-compatible ({server})")
        } else {
            "S3-compatible API".into()
        };
        ("s3", "Amazon S3-compatible", detail)
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "minio".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: name.into(),
            product: Some(product.into()),
            version: None,
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

/// HashiCorp Vault HTTP observe (often :8200) -- `/v1/sys/health`.
pub async fn observe_vault(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, body) = http_get_body(addr, port, "/v1/sys/health").await?;
    // Vault returns 200 (active), 429 (uninitialized), 472/473 (standby/DR), 501/503…
    let lower = body.to_ascii_lowercase();
    let looks = (200..600).contains(&st)
        && (lower.contains("\"initialized\"")
            || lower.contains("\"sealed\"")
            || lower.contains("\"cluster_name\"")
            || lower.contains("\"version\""));
    if !looks {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "vault".into(),
            detail: format!("no Vault health markers (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let version = json_string_field(&body, "version");
    let sealed = lower.contains("\"sealed\":true") || lower.contains("\"sealed\": true");
    let initialized =
        lower.contains("\"initialized\":true") || lower.contains("\"initialized\": true");
    let detail = match &version {
        Some(v) if sealed => format!("Vault {v} (sealed)"),
        Some(v) if !initialized => format!("Vault {v} (uninitialized)"),
        Some(v) => format!("Vault {v}"),
        None if sealed => "Vault (sealed)".into(),
        None => "Vault".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "vault".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "vault".into(),
            product: Some("HashiCorp Vault".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}

/// HashiCorp Nomad HTTP observe (default :4646) -- `/v1/agent/self` / leader.
pub async fn observe_nomad(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, body) = http_get_body(addr, port, "/v1/agent/self").await?;
    let lower = body.to_ascii_lowercase();
    let looks = st == 200
        && (lower.contains("\"member\"")
            || lower.contains("\"config\"")
            || lower.contains("nomad")
            || lower.contains("\"datacenter\""));
    if !looks {
        let (st2, b2) = http_get_body(addr, port, "/v1/status/leader").await?;
        if !(st2 == 200 && (b2.contains(':') || b2.contains('"'))) {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "nomad".into(),
                detail: format!("no Nomad markers (status={st})"),
                confidence: 0.2,
            });
            return Ok(None);
        }
        let detail = "Nomad (leader endpoint)".to_string();
        emit_service_simple(
            addr,
            port,
            "nomad",
            "HashiCorp Nomad",
            None,
            &detail,
            0.85,
            &emit,
        );
        return Ok(Some(detail));
    }

    let version = json_string_field(&body, "Version")
        .or_else(|| json_string_field(&body, "version"))
        .or_else(|| {
            // Nested under member/tags or config.Version often as plain field nearby.
            body.lines().find_map(|l| {
                let l = l.trim();
                l.strip_prefix("\"Version\":")
                    .or_else(|| l.strip_prefix("\"version\":"))
                    .map(|s| s.trim().trim_matches(',').trim_matches('"').to_string())
                    .filter(|s| !s.is_empty() && s.len() < 32)
            })
        });
    let detail = match &version {
        Some(v) => format!("Nomad {v}"),
        None => "Nomad".into(),
    };
    emit_service_simple(
        addr,
        port,
        "nomad",
        "HashiCorp Nomad",
        version,
        &detail,
        0.93,
        &emit,
    );
    Ok(Some(detail))
}

#[allow(clippy::too_many_arguments)]
fn emit_service_simple(
    addr: IpAddr,
    port: u16,
    name: &str,
    product: &str,
    version: Option<String>,
    detail: &str,
    confidence: f32,
    emit: &impl Fn(Event),
) {
    emit(Event::Banner {
        addr,
        port,
        banner: detail.to_string(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: name.into(),
        detail: detail.to_string(),
        confidence,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: name.into(),
            product: Some(product.into()),
            version,
            extra: Some(detail.to_string()),
            confidence,
        },
    });
}
