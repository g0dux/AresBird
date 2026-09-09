//! sql service observers (shared helpers live in the parent module).

use super::*;

/// MySQL/MariaDB: parse initial Handshake packet version string.
pub async fn observe_mysql(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    let mut buf = [0u8; 512];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
    if n < 5 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "mysql".into(),
            detail: "short/no greeting".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }

    // Packet: 3-byte len LE, 1-byte seq, payload...
    let payload = if n >= 5
        && buf[0] as usize + ((buf[1] as usize) << 8) + ((buf[2] as usize) << 16)
            <= n.saturating_sub(4)
    {
        &buf[4..n]
    } else {
        &buf[..n]
    };

    // Error packet: 0xff
    if payload.first() == Some(&0xff) {
        let msg = String::from_utf8_lossy(payload).trim().to_string();
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "mysql".into(),
            detail: format!("error greeting: {msg}"),
            confidence: 0.7,
        });
        return Ok(Some(msg));
    }

    // Protocol version (usually 10) + null-terminated server version
    let proto = payload[0];
    let version = if let Some(end) = payload[1..].iter().position(|&b| b == 0) {
        String::from_utf8_lossy(&payload[1..1 + end]).to_string()
    } else {
        String::new()
    };

    if version.is_empty() && proto != 10 && proto != 9 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "mysql".into(),
            detail: format!("not a mysql greeting (proto={proto})"),
            confidence: 0.3,
        });
        return Ok(None);
    }

    let product = if version.to_ascii_lowercase().contains("mariadb") {
        "MariaDB"
    } else {
        "MySQL"
    };
    let detail = if version.is_empty() {
        format!("mysql protocol {proto}")
    } else {
        format!("{product} {version}")
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "mysql".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "mysql".into(),
            product: Some(product.into()),
            version: if version.is_empty() {
                None
            } else {
                Some(version)
            },
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

/// PostgreSQL: SSLRequest observe + StartupMessage to harvest ErrorResponse fields.
pub async fn observe_postgres(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;

    // SSLRequest: len=8, code=80877103
    let ssl_req: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
    stream.write_all(&ssl_req).await?;
    let mut one = [0u8; 1];
    let ssl_n = timeout(Duration::from_secs(2), stream.read(&mut one)).await??;
    let ssl_mode = if ssl_n == 1 {
        match one[0] {
            b'S' => "ssl=required",
            b'N' => "ssl=off",
            other => {
                emit(Event::ProbeResult {
                    addr,
                    port,
                    probe: "postgres".into(),
                    detail: format!("unexpected SSLReply 0x{other:02x}"),
                    confidence: 0.35,
                });
                return Ok(None);
            }
        }
    } else {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "postgres".into(),
            detail: "no SSLReply".into(),
            confidence: 0.2,
        });
        return Ok(None);
    };

    // After 'S', TLS would be required -- stop at SSL observe. After 'N', send Startup.
    let mut server_version = None;
    let mut severity = None;
    let mut message = None;
    if one[0] == b'N' {
        let mut params = Vec::new();
        for (k, v) in [
            ("user", "aresbird"),
            ("database", "postgres"),
            ("application_name", "aresbird"),
        ] {
            params.extend_from_slice(k.as_bytes());
            params.push(0);
            params.extend_from_slice(v.as_bytes());
            params.push(0);
        }
        params.push(0);
        let mut startup = Vec::with_capacity(8 + params.len());
        let len = (8 + params.len()) as u32;
        startup.extend_from_slice(&len.to_be_bytes());
        startup.extend_from_slice(&196608u32.to_be_bytes()); // 3.0
        startup.extend_from_slice(&params);
        stream.write_all(&startup).await?;

        let mut buf = [0u8; 2048];
        let n = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        if n > 0 && buf[0] == b'E' {
            let body = &buf[5..n];
            let mut i = 0;
            while i < body.len() {
                let code = body[i];
                if code == 0 {
                    break;
                }
                i += 1;
                let start = i;
                while i < body.len() && body[i] != 0 {
                    i += 1;
                }
                let val = String::from_utf8_lossy(&body[start..i]).to_string();
                if i < body.len() {
                    i += 1;
                }
                match code {
                    b'V' | b'S' => severity = Some(val),
                    b'M' => message = Some(val),
                    _ => {}
                }
            }
            if let Some(ref m) = message {
                if let Some(idx) = m.find("server version") {
                    server_version = Some(m[idx..].chars().take(40).collect());
                }
            }
        } else if n > 0 && buf[0] == b'R' {
            message = Some("auth challenge".into());
        }
    }

    let detail = match (&message, &severity) {
        (Some(m), Some(s)) => format!("{ssl_mode}; {s}: {m}"),
        (Some(m), None) => format!("{ssl_mode}; {m}"),
        _ => ssl_mode.to_string(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "postgres".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "postgresql".into(),
            product: Some("PostgreSQL".into()),
            version: server_version,
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

/// MSSQL / TDS Pre-Login observe (default :1433) -- no auth / no query abuse.
pub async fn observe_mssql(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    let pkt = tds_prelogin_request();
    stream.write_all(&pkt).await?;
    let mut buf = [0u8; 1024];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n < 8 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "mssql".into(),
            detail: "short/no TDS reply".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }
    // TDS packet type in first byte: 0x04 (TABULAR RESULT) wrapping PRELOGIN, or 0x12
    let ptype = buf[0];
    if ptype != 0x04 && ptype != 0x12 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "mssql".into(),
            detail: format!("unexpected TDS type 0x{ptype:02x}"),
            confidence: 0.25,
        });
        return Ok(None);
    }

    let body = &buf[8..n];
    let (version, encryption) = parse_tds_prelogin(body);
    let mut parts = vec!["MSSQL/TDS prelogin".to_string()];
    if let Some(v) = &version {
        parts.push(format!("version={v}"));
    }
    if let Some(e) = encryption {
        parts.push(format!(
            "encrypt={}",
            match e {
                0 => "off",
                1 => "on",
                2 => "not_supported",
                3 => "required",
                _ => "?",
            }
        ));
    }
    let detail = parts.join(" ");
    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "mssql".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "mssql".into(),
            product: Some("Microsoft SQL Server".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

/// Oracle TNS listener observe (default :1521) -- `COMMAND=version` only.
pub async fn observe_oracle(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    let pkt = tns_version_request();
    stream.write_all(&pkt).await?;
    let mut buf = [0u8; 2048];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n < 8 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "oracle".into(),
            detail: "short/no TNS reply".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let text = String::from_utf8_lossy(&buf[..n]);
    let ptype = buf.get(4).copied().unwrap_or(0);
    // Accept(2), Refuse(4), Redirect(5), Data(6)
    let looks = text.to_ascii_lowercase().contains("oracle")
        || text.contains("VSNNUM")
        || text.contains("DESCRIPTION")
        || text.contains("TNS")
        || matches!(ptype, 2 | 4 | 5 | 6);

    if !looks {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "oracle".into(),
            detail: format!("unexpected TNS type={ptype}"),
            confidence: 0.25,
        });
        return Ok(None);
    }

    let version = extract_oracle_version(&text);
    let detail = match &version {
        Some(v) => format!("Oracle TNS {v}"),
        None if text.to_ascii_lowercase().contains("oracle") => {
            let snippet: String = text
                .chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .take(80)
                .collect();
            format!("Oracle TNS ({snippet})")
        }
        None => "Oracle TNS listener".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "oracle".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "oracle".into(),
            product: Some("Oracle TNS".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

/// Cassandra native protocol observe (default :9042) -- OPTIONS -> SUPPORTED.
pub async fn observe_cassandra(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    // Native protocol v4 OPTIONS request
    let pkt: [u8; 9] = [
        0x04, // version (request / v4)
        0x00, // flags
        0x00, 0x01, // stream
        0x05, // OPTIONS
        0x00, 0x00, 0x00, 0x00, // length
    ];
    stream.write_all(&pkt).await?;
    let mut buf = [0u8; 2048];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n < 9 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "cassandra".into(),
            detail: "short/no native reply".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let ver = buf[0];
    let opcode = buf[4];
    // Response bit set on high nibble of version byte; SUPPORTED = 0x06
    let is_resp = ver & 0x80 != 0;
    if !is_resp || opcode != 0x06 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "cassandra".into(),
            detail: format!("unexpected native frame ver=0x{ver:02x} op=0x{opcode:02x}"),
            confidence: 0.25,
        });
        return Ok(None);
    }

    let proto_v = ver & 0x7f;
    let body = if n > 9 { &buf[9..n] } else { &[][..] };
    let cql = cassandra_multimap_first(body, "CQL_VERSION")
        .or_else(|| cassandra_multimap_first(body, "cql_version"));
    let detail = match &cql {
        Some(v) => format!("Cassandra native v{proto_v} CQL {v}"),
        None => format!("Cassandra native v{proto_v}"),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "cassandra".into(),
        detail: detail.clone(),
        confidence: 0.92,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "cassandra".into(),
            product: Some("Apache Cassandra".into()),
            version: cql.clone(),
            extra: Some(detail.clone()),
            confidence: 0.92,
        },
    });
    Ok(Some(detail))
}

/// ClickHouse HTTP observe (default :8123) -- `/ping` + optional `SELECT version()`.
pub async fn observe_clickhouse(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, body) = http_get_body(addr, port, "/ping").await?;
    let ping_ok = st == 200 && body.trim().eq_ignore_ascii_case("Ok.");
    // Fallback: unauthenticated GET / often returns Ok.
    let root_ok = if !ping_ok {
        let (st2, b2) = http_get_body(addr, port, "/").await?;
        st2 == 200 && b2.trim().eq_ignore_ascii_case("Ok.")
    } else {
        false
    };
    if !ping_ok && !root_ok {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "clickhouse".into(),
            detail: format!("no ClickHouse ping (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let mut version: Option<String> = None;
    if let Ok((vst, vbody)) = http_get_body(addr, port, "/?query=SELECT%20version()").await {
        if vst == 200 {
            let ver = vbody.trim();
            if !ver.is_empty()
                && ver.len() < 64
                && ver.chars().all(|c| c.is_ascii_digit() || c == '.')
            {
                version = Some(ver.to_string());
            }
        }
    }

    let detail = match &version {
        Some(v) => format!("ClickHouse {v}"),
        None => "ClickHouse HTTP".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "clickhouse".into(),
        detail: detail.clone(),
        confidence: 0.93,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "clickhouse".into(),
            product: Some("ClickHouse".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.93,
        },
    });
    Ok(Some(detail))
}

/// InfluxDB HTTP observe (default :8086) -- `/health` + `/ping` markers.
pub async fn observe_influxdb(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (hst, hbody) = http_get_body(addr, port, "/health").await?;
    let status = json_string_field(&hbody, "status");
    let version =
        json_string_field(&hbody, "version").or_else(|| json_string_field(&hbody, "influxdb"));
    let health_ok = hst == 200
        && (status.as_deref() == Some("pass")
            || hbody.to_ascii_lowercase().contains("\"status\"")
            || hbody.to_ascii_lowercase().contains("ready"));

    let mut ping_ok = false;
    let mut ping_ver: Option<String> = None;
    if !health_ok {
        let (pst, praw, pbody) = http_get_raw(addr, port, "/ping").await?;
        // InfluxDB 1.x answers /ping with 204 + X-Influxdb-Version
        ping_ver = http_header_value(&praw, "X-Influxdb-Version")
            .or_else(|| http_header_value(&praw, "X-InfluxDB-Version"));
        ping_ok = (pst == 204 || pst == 200)
            && (ping_ver.is_some()
                || pbody.to_ascii_lowercase().contains("influx")
                || http_header_value(&praw, "X-Influxdb-Build").is_some());
    }

    if !health_ok && !ping_ok {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "influxdb".into(),
            detail: format!("no InfluxDB markers (health status={hst})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let version = version.or(ping_ver);
    let detail = match &version {
        Some(v) => format!("InfluxDB {v}"),
        None => "InfluxDB".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "influxdb".into(),
        detail: detail.clone(),
        confidence: 0.93,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "influxdb".into(),
            product: Some("InfluxDB".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.93,
        },
    });
    Ok(Some(detail))
}

/// ScyllaDB REST API observe (default :10000) -- release version endpoint.
pub async fn observe_scylla(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, body) = http_get_body(addr, port, "/storage_service/scylla_release_version").await?;
    let ver = body.trim().trim_matches('"');
    let looks = st == 200
        && !ver.is_empty()
        && ver.len() < 64
        && (ver.chars().any(|c| c.is_ascii_digit())
            || body.to_ascii_lowercase().contains("scylla"));

    if !looks {
        // Fallback: root often returns a Swagger / API index mentioning Scylla.
        let (st2, b2) = http_get_body(addr, port, "/").await?;
        let lower = b2.to_ascii_lowercase();
        if !(st2 == 200 && (lower.contains("scylla") || lower.contains("storage_service"))) {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "scylla".into(),
                detail: format!("no Scylla REST markers (status={st})"),
                confidence: 0.2,
            });
            return Ok(None);
        }
        let detail = "ScyllaDB REST API".to_string();
        emit(Event::Banner {
            addr,
            port,
            banner: detail.clone(),
        });
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "scylla".into(),
            detail: detail.clone(),
            confidence: 0.85,
        });
        emit(Event::ServiceDetected {
            addr,
            port,
            service: ServiceInfo {
                name: "scylla".into(),
                product: Some("ScyllaDB".into()),
                version: None,
                extra: Some(detail.clone()),
                confidence: 0.85,
            },
        });
        return Ok(Some(detail));
    }

    let version = Some(ver.to_string());
    let detail = format!("ScyllaDB {ver}");
    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "scylla".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "scylla".into(),
            product: Some("ScyllaDB".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}
