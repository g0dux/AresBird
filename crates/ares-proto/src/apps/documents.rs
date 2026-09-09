//! documents service observers (shared helpers live in the parent module).

use super::*;

/// MongoDB: legacy OP_QUERY `{ isMaster: 1 }` / `{ hello: 1 }` observe.
pub async fn observe_mongodb(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    let doc = bson_int32_cmd("isMaster", 1);
    let msg = op_query_admin_cmd(&doc);
    stream.write_all(&msg).await?;

    let mut buf = vec![0u8; 4096];
    let n = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    // Retry with hello if empty / short
    let n = if n < 16 {
        let doc2 = bson_int32_cmd("hello", 1);
        let msg2 = op_query_admin_cmd(&doc2);
        let _ = stream.write_all(&msg2).await;
        match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(m)) => m,
            _ => n,
        }
    } else {
        n
    };

    if n < 16 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "mongodb".into(),
            detail: "no wire reply".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }

    // OP_REPLY opcode = 1
    let opcode = i32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    if opcode != 1 && opcode != 2013 {
        // Still try to mine version strings from payload
        if !buf[..n].windows(7).any(|w| w == b"version")
            && !buf[..n].windows(6).any(|w| w == b"ismaster")
            && !buf[..n].windows(5).any(|w| w == b"hello")
        {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "mongodb".into(),
                detail: format!("unexpected opcode {opcode}"),
                confidence: 0.3,
            });
            return Ok(None);
        }
    }

    let version = bson_find_cstring(&buf[..n], "version")
        .or_else(|| bson_find_cstring(&buf[..n], "versionString"));
    let max_wire = bson_find_i32(&buf[..n], "maxWireVersion");
    let detail = match (&version, max_wire) {
        (Some(v), Some(w)) => format!("MongoDB {v} (maxWireVersion={w})"),
        (Some(v), None) => format!("MongoDB {v}"),
        (None, Some(w)) => format!("MongoDB (maxWireVersion={w})"),
        (None, None) => "MongoDB isMaster/hello reply".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "mongodb".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "mongodb".into(),
            product: Some("MongoDB".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

/// Elasticsearch: HTTP GET `/` -- parse `version.number` / tagline.
pub async fn observe_elasticsearch(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    let host = addr.to_string();
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: AresBird/0.1\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = vec![0u8; 8192];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n == 0 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "elasticsearch".into(),
            detail: "empty HTTP reply".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&buf[..n]);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or(&text);
    let looks = body.contains("You Know, for Search")
        || body.contains("\"tagline\"")
        || (body.contains("\"cluster_name\"") && body.contains("\"version\""))
        || body.contains("lucene_version");
    if !looks {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "elasticsearch".into(),
            detail: "HTTP reply without ES markers".into(),
            confidence: 0.3,
        });
        return Ok(None);
    }

    let version = {
        let lower = body.to_ascii_lowercase();
        if let Some(vi) = lower.find("\"version\"") {
            json_string_field(&body[vi..], "number")
        } else {
            None
        }
    }
    .or_else(|| json_string_field(body, "number"));
    let cluster = json_string_field(body, "cluster_name");
    let detail = match (&version, &cluster) {
        (Some(v), Some(c)) => format!("Elasticsearch {v} cluster={c}"),
        (Some(v), None) => format!("Elasticsearch {v}"),
        (None, Some(c)) => format!("Elasticsearch cluster={c}"),
        (None, None) => "Elasticsearch".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "elasticsearch".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "elasticsearch".into(),
            product: Some("Elasticsearch".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

/// CouchDB HTTP API observe (default :5984) -- `GET /`.
pub async fn observe_couchdb(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, body) = http_get_body(addr, port, "/").await?;
    let looks = body.contains("\"couchdb\"")
        || (body.to_ascii_lowercase().contains("welcome")
            && body.to_ascii_lowercase().contains("couch"));
    if st != 200 || !looks {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "couchdb".into(),
            detail: format!("no CouchDB markers (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }
    let version = json_string_field(&body, "version");
    let vendor = json_string_field(&body, "couchdb").or_else(|| {
        if body.contains("Welcome") {
            Some("Welcome".into())
        } else {
            None
        }
    });
    let detail = match (&version, &vendor) {
        (Some(v), _) => format!("CouchDB {v}"),
        (None, Some(w)) => format!("CouchDB ({w})"),
        _ => "CouchDB".into(),
    };
    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "couchdb".into(),
        detail: detail.clone(),
        confidence: 0.92,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "couchdb".into(),
            product: Some("Apache CouchDB".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.92,
        },
    });
    Ok(Some(detail))
}

/// Neo4j HTTP discovery observe (default :7474) -- GET /.
pub async fn observe_neo4j(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, body) = http_get_body(addr, port, "/").await?;
    let lower = body.to_ascii_lowercase();
    let looks = lower.contains("neo4j")
        || body.contains("bolt_direct")
        || body.contains("bolt_routing")
        || body.contains("neo4j_version");
    if !(looks || (st == 200 && body.contains("transaction"))) {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "neo4j".into(),
            detail: format!("no Neo4j markers (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let version = json_string_field(&body, "neo4j_version");
    let edition = json_string_field(&body, "neo4j_edition");
    let detail = match (&version, &edition) {
        (Some(v), Some(e)) => format!("Neo4j {v} ({e})"),
        (Some(v), None) => format!("Neo4j {v}"),
        (None, Some(e)) => format!("Neo4j ({e})"),
        _ => "Neo4j HTTP API".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "neo4j".into(),
        detail: detail.clone(),
        confidence: 0.92,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "neo4j".into(),
            product: Some("Neo4j".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.92,
        },
    });
    Ok(Some(detail))
}

/// Neo4j Bolt protocol handshake observe (default :7687).
pub async fn observe_bolt(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    // Magic + version candidates: prefer modern then fall back.
    let mut pkt = vec![0x60, 0x60, 0xb0, 0x17];
    // Bolt 5.4, 4.4, 3.0, 1.0 style identifiers (big-endian).
    pkt.extend_from_slice(&0x0000_0504u32.to_be_bytes());
    pkt.extend_from_slice(&0x0000_0404u32.to_be_bytes());
    pkt.extend_from_slice(&0x0000_0003u32.to_be_bytes());
    pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes());
    stream.write_all(&pkt).await?;

    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n < 4 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "bolt".into(),
            detail: "short/no Bolt handshake".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let selected = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if selected == 0 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "bolt".into(),
            detail: "Bolt handshake refused (no shared version)".into(),
            confidence: 0.4,
        });
        return Ok(None);
    }

    let version = format_bolt_version(selected);
    let detail = format!("Bolt {version}");

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "bolt".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "bolt".into(),
            product: Some("Neo4j Bolt".into()),
            version: Some(version),
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}

/// RethinkDB native protocol observe (default :28015) -- V0_4 JSON handshake.
pub async fn observe_rethinkdb(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    // Magic V0_4 (LE) + auth_key_len=0 + protocol JSON (LE).
    let mut handshake = Vec::with_capacity(12);
    handshake.extend_from_slice(&0x34c2bdc3u32.to_le_bytes());
    handshake.extend_from_slice(&0u32.to_le_bytes());
    handshake.extend_from_slice(&0x7e6970c7u32.to_le_bytes());
    stream.write_all(&handshake).await?;

    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n == 0 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "rethinkdb".into(),
            detail: "empty handshake reply".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&buf[..n]);
    let ok = text.contains("SUCCESS")
        || text.to_ascii_lowercase().contains("rethink")
        || text.contains("ERROR");
    if !ok {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "rethinkdb".into(),
            detail: format!("unexpected handshake ({n} bytes)"),
            confidence: 0.3,
        });
        return Ok(None);
    }

    let auth_required = text.to_ascii_uppercase().contains("ERROR")
        && (text.to_ascii_lowercase().contains("auth")
            || text.to_ascii_lowercase().contains("password"));
    let detail = if text.contains("SUCCESS") {
        "RethinkDB handshake SUCCESS".to_string()
    } else if auth_required {
        "RethinkDB (auth required)".to_string()
    } else {
        text.trim_matches('\0').trim().chars().take(80).collect()
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "rethinkdb".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "rethinkdb".into(),
            product: Some("RethinkDB".into()),
            version: None,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}

/// OpenSearch HTTP observe (default :9200) -- root JSON with `tagline` / distribution.
pub async fn observe_opensearch(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, body) = http_get_body(addr, port, "/").await?;
    let lower = body.to_ascii_lowercase();
    let looks = st == 200
        && (lower.contains("opensearch")
            || lower.contains("\"distribution\"") && lower.contains("opensearch")
            || (lower.contains("\"tagline\"") && lower.contains("the missing piece")));
    if !looks {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "opensearch".into(),
            detail: format!("no OpenSearch markers (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let version = {
        if let Some(i) = lower.find("\"version\"") {
            json_string_field(&body[i..], "number")
        } else {
            None
        }
    }
    .or_else(|| json_string_field(&body, "number"));
    let cluster = json_string_field(&body, "cluster_name");
    let detail = match (&version, &cluster) {
        (Some(v), Some(c)) => format!("OpenSearch {v} cluster={c}"),
        (Some(v), None) => format!("OpenSearch {v}"),
        (None, Some(c)) => format!("OpenSearch cluster={c}"),
        _ => "OpenSearch".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "opensearch".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "opensearch".into(),
            product: Some("OpenSearch".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}

/// Apache Solr HTTP observe (default :8983) -- `/solr/admin/info/system`.
pub async fn observe_solr(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, body) = http_get_body(addr, port, "/solr/admin/info/system").await?;
    let lower = body.to_ascii_lowercase();
    let looks = st == 200
        && (lower.contains("solr") || lower.contains("lucene") || lower.contains("\"mode\""));
    if !looks {
        let (st2, b2) = http_get_body(addr, port, "/solr/").await?;
        let l2 = b2.to_ascii_lowercase();
        if !(st2 == 200 && (l2.contains("solr") || l2.contains("dashboard"))) {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "solr".into(),
                detail: format!("no Solr markers (status={st})"),
                confidence: 0.2,
            });
            return Ok(None);
        }
        let detail = "Apache Solr".to_string();
        emit(Event::Banner {
            addr,
            port,
            banner: detail.clone(),
        });
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "solr".into(),
            detail: detail.clone(),
            confidence: 0.85,
        });
        emit(Event::ServiceDetected {
            addr,
            port,
            service: ServiceInfo {
                name: "solr".into(),
                product: Some("Apache Solr".into()),
                version: None,
                extra: Some(detail.clone()),
                confidence: 0.85,
            },
        });
        return Ok(Some(detail));
    }

    let version = json_string_field(&body, "solr-spec-version")
        .or_else(|| json_string_field(&body, "solr_spec_version"))
        .or_else(|| json_string_field(&body, "version"));
    let detail = match &version {
        Some(v) => format!("Apache Solr {v}"),
        None => "Apache Solr".into(),
    };
    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "solr".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "solr".into(),
            product: Some("Apache Solr".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}
