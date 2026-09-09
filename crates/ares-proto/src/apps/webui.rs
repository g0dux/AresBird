//! webui service observers (shared helpers live in the parent module).

use super::*;

/// Grafana HTTP observe (default :3000) -- `/api/health` + login markers.
pub async fn observe_grafana(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (hst, _hraw, hbody) = http_get_raw(addr, port, "/api/health").await?;
    let version = json_string_field(&hbody, "version");
    let database = json_string_field(&hbody, "database");
    let health_ok = hst == 200
        && (version.is_some()
            || database.as_deref() == Some("ok")
            || hbody.to_ascii_lowercase().contains("database"));

    let mut login_hit = false;
    if !health_ok {
        for path in ["/login", "/"] {
            let (_st, raw, body) = http_get_raw(addr, port, path).await?;
            let lower = body.to_ascii_lowercase();
            if lower.contains("grafana")
                || http_header_value(&raw, "X-Grafana-Org-Id").is_some()
                || lower.contains("grafana-app")
            {
                login_hit = true;
                break;
            }
        }
    }

    if !health_ok && !login_hit {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "grafana".into(),
            detail: format!("no Grafana markers (health status={hst})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let detail: String = match (&version, &database) {
        (Some(v), Some(db)) => format!("Grafana {v} (db={db})"),
        (Some(v), None) => format!("Grafana {v}"),
        (None, Some(db)) => format!("Grafana (db={db})"),
        _ => "Grafana".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "grafana".into(),
        detail: detail.clone(),
        confidence: if health_ok { 0.95 } else { 0.85 },
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "grafana".into(),
            product: Some("Grafana".into()),
            version,
            extra: Some(detail.clone()),
            confidence: if health_ok { 0.95 } else { 0.85 },
        },
    });
    Ok(Some(detail))
}

/// Kibana HTTP observe (default :5601) -- `/api/status` + UI markers.
pub async fn observe_kibana(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, raw, body) = http_get_raw(addr, port, "/api/status").await?;
    let kbn_name = http_header_value(&raw, "kbn-name");
    let kbn_version = http_header_value(&raw, "kbn-version");
    let version = kbn_version
        .clone()
        .or_else(|| {
            // nested: version.number in status payload
            let lower = body.to_ascii_lowercase();
            if let Some(vi) = lower.find("\"version\"") {
                json_string_field(&body[vi..], "number")
            } else {
                None
            }
        })
        .or_else(|| json_string_field(&body, "version"));
    let name = kbn_name
        .clone()
        .or_else(|| json_string_field(&body, "name"));
    let looks = name
        .as_deref()
        .is_some_and(|n| n.eq_ignore_ascii_case("kibana"))
        || body.to_ascii_lowercase().contains("kibana")
        || kbn_name.is_some()
        || kbn_version.is_some();

    if !looks {
        // Fallback: root UI
        let (st2, raw2, body2) = http_get_raw(addr, port, "/").await?;
        let l2 = body2.to_ascii_lowercase();
        let root_hit = l2.contains("kibana")
            || http_header_value(&raw2, "kbn-name").is_some()
            || http_header_value(&raw2, "kbn-version").is_some();
        if !root_hit {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "kibana".into(),
                detail: format!("no Kibana markers (status={st}/{st2})"),
                confidence: 0.2,
            });
            return Ok(None);
        }
        let ver = http_header_value(&raw2, "kbn-version");
        let detail: String = match &ver {
            Some(v) => format!("Kibana {v}"),
            None => "Kibana".into(),
        };
        emit(Event::Banner {
            addr,
            port,
            banner: detail.clone(),
        });
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "kibana".into(),
            detail: detail.clone(),
            confidence: 0.85,
        });
        emit(Event::ServiceDetected {
            addr,
            port,
            service: ServiceInfo {
                name: "kibana".into(),
                product: Some("Kibana".into()),
                version: ver,
                extra: Some(detail.clone()),
                confidence: 0.85,
            },
        });
        return Ok(Some(detail));
    }

    let detail: String = match &version {
        Some(v) => format!("Kibana {v}"),
        None => "Kibana".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "kibana".into(),
        detail: detail.clone(),
        confidence: 0.93,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "kibana".into(),
            product: Some("Kibana".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.93,
        },
    });
    Ok(Some(detail))
}

/// Prometheus HTTP observe (default :9090) -- `/-/healthy` + `/api/v1/status/buildinfo`.
pub async fn observe_prometheus(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (hst, _hraw, hbody) = http_get_raw(addr, port, "/-/healthy").await?;
    let healthy = hst == 200 && hbody.to_ascii_lowercase().contains("prometheus");

    let (bst, _braw, bbody) = http_get_raw(addr, port, "/api/v1/status/buildinfo").await?;
    let version = {
        let lower = bbody.to_ascii_lowercase();
        if let Some(i) = lower.find("\"version\"") {
            json_string_field(&bbody[i..], "version")
        } else {
            json_string_field(&bbody, "version")
        }
    };
    let build_ok = bst == 200
        && (version.is_some()
            || bbody.contains("\"status\":\"success\"")
            || bbody.to_ascii_lowercase().contains("prometheus"));

    if !healthy && !build_ok {
        let (mst, _mraw, mbody) = http_get_raw(addr, port, "/metrics").await?;
        let metrics_ok = mst == 200
            && (mbody.contains("prometheus_")
                || (mbody.contains("# HELP") && mbody.contains("# TYPE")));
        if !metrics_ok {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "prometheus".into(),
                detail: format!("no Prometheus markers (health={hst})"),
                confidence: 0.2,
            });
            return Ok(None);
        }
        let detail: String = "Prometheus (/metrics)".into();
        emit(Event::Banner {
            addr,
            port,
            banner: detail.clone(),
        });
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "prometheus".into(),
            detail: detail.clone(),
            confidence: 0.85,
        });
        emit(Event::ServiceDetected {
            addr,
            port,
            service: ServiceInfo {
                name: "prometheus".into(),
                product: Some("Prometheus".into()),
                version: None,
                extra: Some(detail.clone()),
                confidence: 0.85,
            },
        });
        return Ok(Some(detail));
    }

    let detail: String = match &version {
        Some(v) => format!("Prometheus {v}"),
        None if healthy => "Prometheus (healthy)".into(),
        None => "Prometheus".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "prometheus".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "prometheus".into(),
            product: Some("Prometheus".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}

/// Jenkins HTTP observe (often :8080) -- `/login` + `X-Jenkins` markers.
pub async fn observe_jenkins(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, raw, body) = http_get_raw(addr, port, "/login").await?;
    let x_jenkins = http_header_value(&raw, "X-Jenkins");
    let lower = body.to_ascii_lowercase();
    let looks = x_jenkins.is_some()
        || http_header_value(&raw, "X-Hudson").is_some()
        || lower.contains("jenkins");

    if !looks {
        let (st2, raw2, body2) = http_get_raw(addr, port, "/").await?;
        let xj = http_header_value(&raw2, "X-Jenkins");
        let l2 = body2.to_ascii_lowercase();
        if xj.is_none() && !l2.contains("jenkins") && http_header_value(&raw2, "X-Hudson").is_none()
        {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "jenkins".into(),
                detail: format!("no Jenkins markers (status={st}/{st2})"),
                confidence: 0.2,
            });
            return Ok(None);
        }
        let ver = xj;
        let detail: String = match &ver {
            Some(v) if v.chars().any(|c| c.is_ascii_digit()) => format!("Jenkins {v}"),
            _ => "Jenkins".into(),
        };
        emit(Event::Banner {
            addr,
            port,
            banner: detail.clone(),
        });
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "jenkins".into(),
            detail: detail.clone(),
            confidence: 0.9,
        });
        emit(Event::ServiceDetected {
            addr,
            port,
            service: ServiceInfo {
                name: "jenkins".into(),
                product: Some("Jenkins".into()),
                version: ver.filter(|v| v.chars().any(|c| c.is_ascii_digit())),
                extra: Some(detail.clone()),
                confidence: 0.9,
            },
        });
        return Ok(Some(detail));
    }

    let version = x_jenkins
        .clone()
        .filter(|v| v.chars().any(|c| c.is_ascii_digit()));
    let detail: String = match &version {
        Some(v) => format!("Jenkins {v}"),
        None => "Jenkins".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "jenkins".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "jenkins".into(),
            product: Some("Jenkins".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}

/// Keycloak HTTP observe (often :8080) -- `/realms/master` + UI markers.
pub async fn observe_keycloak(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, _raw, body) = http_get_raw(addr, port, "/realms/master").await?;
    let realm = json_string_field(&body, "realm");
    let lower = body.to_ascii_lowercase();
    let mut looks = realm.as_deref() == Some("master")
        || lower.contains("keycloak")
        || lower.contains("\"public_key\"");

    if !looks {
        for path in [
            "/",
            "/admin/",
            "/realms/master/protocol/openid-connect/certs",
        ] {
            let (_st2, raw2, body2) = http_get_raw(addr, port, path).await?;
            let l2 = body2.to_ascii_lowercase();
            let r2 = raw2.to_ascii_lowercase();
            if l2.contains("keycloak")
                || r2.contains("keycloak")
                || l2.contains("kc-form")
                || l2.contains("realm-management")
            {
                looks = true;
                break;
            }
        }
    }

    if !looks {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "keycloak".into(),
            detail: format!("no Keycloak markers (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let detail: String = if realm.as_deref() == Some("master") {
        "Keycloak realm=master".into()
    } else {
        "Keycloak".into()
    };
    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "keycloak".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "keycloak".into(),
            product: Some("Keycloak".into()),
            version: None,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}

/// Portainer HTTP observe (default :9000 / HTTPS :9443) -- `/api/system/status`.
pub async fn observe_portainer(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, _raw, body) = http_get_raw(addr, port, "/api/system/status").await?;
    let version =
        json_string_field(&body, "Version").or_else(|| json_string_field(&body, "version"));
    let lower = body.to_ascii_lowercase();
    let mut looks = version.is_some() || lower.contains("portainer");

    if !looks {
        for path in ["/", "/api/status", "/api/endpoints"] {
            let (_st2, raw2, body2) = http_get_raw(addr, port, path).await?;
            let l2 = body2.to_ascii_lowercase();
            let r2 = raw2.to_ascii_lowercase();
            if l2.contains("portainer") || r2.contains("portainer") {
                looks = true;
                break;
            }
        }
    }

    if !looks {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "portainer".into(),
            detail: format!("no Portainer markers (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let detail = match &version {
        Some(v) => format!("Portainer {v}"),
        None => "Portainer".into(),
    };
    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "portainer".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "portainer".into(),
            product: Some("Portainer".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}

/// Argo CD HTTP observe (often :8080) -- `/api/version`.
pub async fn observe_argocd(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, _raw, body) = http_get_raw(addr, port, "/api/version").await?;
    let version =
        json_string_field(&body, "Version").or_else(|| json_string_field(&body, "version"));
    let lower = body.to_ascii_lowercase();
    let mut looks = version.is_some()
        || lower.contains("argocd")
        || lower.contains("argo-cd")
        || lower.contains("builddate");

    if !looks {
        for path in ["/", "/login", "/api/v1/session"] {
            let (_st2, raw2, body2) = http_get_raw(addr, port, path).await?;
            let l2 = body2.to_ascii_lowercase();
            let r2 = raw2.to_ascii_lowercase();
            if l2.contains("argocd") || l2.contains("argo cd") || r2.contains("argocd") {
                looks = true;
                break;
            }
        }
    }

    if !looks {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "argocd".into(),
            detail: format!("no Argo CD markers (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let detail = match &version {
        Some(v) => format!("Argo CD {v}"),
        None => "Argo CD".into(),
    };
    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "argocd".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "argocd".into(),
            product: Some("Argo CD".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}

/// SonarQube HTTP observe (default :9000) -- `/api/system/status` + `/api/server/version`.
pub async fn observe_sonarqube(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, _raw, body) = http_get_raw(addr, port, "/api/system/status").await?;
    let mut version = json_string_field(&body, "version");
    let status = json_string_field(&body, "status");
    let lower = body.to_ascii_lowercase();
    let mut looks = version.is_some()
        || status.is_some()
        || lower.contains("sonarqube")
        || lower.contains("sonar");

    if !looks || version.is_none() {
        let (st2, _raw2, body2) = http_get_raw(addr, port, "/api/server/version").await?;
        let vplain = body2.trim();
        if st2 == 200
            && !vplain.is_empty()
            && vplain.len() < 64
            && vplain.chars().any(|c| c.is_ascii_digit())
            && !vplain.contains('<')
        {
            if version.is_none() {
                version = Some(vplain.to_string());
            }
            looks = true;
        } else if !looks {
            for path in ["/", "/sessions/new"] {
                let (_st3, raw3, body3) = http_get_raw(addr, port, path).await?;
                let l3 = body3.to_ascii_lowercase();
                let r3 = raw3.to_ascii_lowercase();
                if l3.contains("sonarqube") || l3.contains("sonar") || r3.contains("sonar") {
                    looks = true;
                    break;
                }
            }
        }
    }

    if !looks {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "sonarqube".into(),
            detail: format!("no SonarQube markers (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let detail = match (&version, &status) {
        (Some(v), Some(s)) => format!("SonarQube {v} ({s})"),
        (Some(v), None) => format!("SonarQube {v}"),
        (None, Some(s)) => format!("SonarQube ({s})"),
        _ => "SonarQube".into(),
    };
    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "sonarqube".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "sonarqube".into(),
            product: Some("SonarQube".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}

/// Elastic APM Server HTTP observe (default :8200) -- root JSON `ok.version`.
pub async fn observe_elastic_apm(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, raw, body) = http_get_raw(addr, port, "/").await?;
    let version = {
        // Nested: {"ok":{"version":"8.x"}} -- search after "ok" first.
        if let Some(i) = body.find("\"ok\"") {
            json_string_field(&body[i..], "version")
        } else {
            None
        }
    }
    .or_else(|| json_string_field(&body, "version"));
    let lower = body.to_ascii_lowercase();
    let looks = st == 200
        && (version.is_some()
            || lower.contains("\"build_sha\"")
            || lower.contains("\"build_date\"")
            || http_header_value(&raw, "X-Elastic-Product")
                .map(|v| v.to_ascii_lowercase().contains("apm"))
                .unwrap_or(false)
            || (lower.contains("\"ok\"") && lower.contains("version")));

    if !looks {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "elastic-apm".into(),
            detail: format!("no Elastic APM markers (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let detail = match &version {
        Some(v) => format!("Elastic APM Server {v}"),
        None => "Elastic APM Server".into(),
    };
    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "elastic-apm".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "elastic-apm".into(),
            product: Some("Elastic APM Server".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}
