//! Observe-only probes for common application services (no auth abuse / no exploits).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ares_core::event::Event;
use ares_core::model::ServiceInfo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

async fn connect(addr: IpAddr, port: u16) -> anyhow::Result<TcpStream> {
    let sa = SocketAddr::new(addr, port);
    Ok(timeout(Duration::from_secs(3), TcpStream::connect(sa)).await??)
}

/// Redis: RESP `PING` (+ optional `INFO server` for version).
pub async fn observe_redis(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    stream.write_all(b"*1\r\n$4\r\nPING\r\n").await?;
    let mut buf = [0u8; 512];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
    if n == 0 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "redis".into(),
            detail: "empty reply".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&buf[..n]);
    let looks = text.contains("PONG")
        || text.contains("-NOAUTH")
        || text.contains("-ERR")
        || text.starts_with('+')
        || text.starts_with('-');
    if !looks {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "redis".into(),
            detail: format!("unexpected reply ({n} bytes)"),
            confidence: 0.3,
        });
        return Ok(None);
    }

    let mut version = None;
    // Best-effort INFO (may fail if requirepass / renamed commands).
    if text.contains("PONG") {
        let _ = stream
            .write_all(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
            .await;
        let mut ibuf = [0u8; 2048];
        if let Ok(Ok(m)) = timeout(Duration::from_secs(2), stream.read(&mut ibuf)).await {
            let info = String::from_utf8_lossy(&ibuf[..m]);
            for line in info.lines() {
                if let Some(v) = line.strip_prefix("redis_version:") {
                    version = Some(v.trim().to_string());
                    break;
                }
            }
        }
    }

    let detail = match &version {
        Some(v) => format!("PONG redis_version={v}"),
        None => text.lines().next().unwrap_or("PONG").trim().to_string(),
    };
    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "redis".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "redis".into(),
            product: Some("Redis".into()),
            version: version.clone(),
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

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

    // Packet: 3-byte len LE, 1-byte seq, payload…
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

    // After 'S', TLS would be required — stop at SSL observe. After 'N', send Startup.
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

/// IMAP: read unsolicited greeting (`* OK …`).
pub async fn observe_imap(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    observe_line_banner(
        addr,
        port,
        "imap",
        |l| {
            let lower = l.to_ascii_lowercase();
            lower.contains("imap") || lower.starts_with("* ok") || lower.starts_with("* preauth")
        },
        emit,
    )
    .await
}

/// POP3: read `+OK` greeting.
pub async fn observe_pop3(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    observe_line_banner(
        addr,
        port,
        "pop3",
        |l| {
            let lower = l.to_ascii_lowercase();
            lower.starts_with("+ok") || lower.contains("pop3")
        },
        emit,
    )
    .await
}

async fn observe_line_banner(
    addr: IpAddr,
    port: u16,
    name: &str,
    looks_like: impl Fn(&str) -> bool,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    let mut buf = [0u8; 512];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
    if n == 0 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: name.into(),
            detail: "empty greeting".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }
    let line = String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .take(200)
        .collect::<String>();
    if line.is_empty() || !looks_like(&line) {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: name.into(),
            detail: format!("unexpected greeting: {line}"),
            confidence: 0.35,
        });
        return Ok(None);
    }
    emit(Event::Banner {
        addr,
        port,
        banner: line.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: name.into(),
        detail: line.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: name.into(),
            product: Some(name.to_ascii_uppercase()),
            version: None,
            extra: Some(line.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(line))
}

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

fn bson_int32_cmd(name: &str, value: i32) -> Vec<u8> {
    let mut doc = vec![0u8; 4];
    doc.push(0x10); // int32
    doc.extend_from_slice(name.as_bytes());
    doc.push(0);
    doc.extend_from_slice(&value.to_le_bytes());
    doc.push(0);
    let len = doc.len() as i32;
    doc[0..4].copy_from_slice(&len.to_le_bytes());
    doc
}

fn op_query_admin_cmd(query_doc: &[u8]) -> Vec<u8> {
    let coll = b"admin.$cmd\0";
    let mut msg = Vec::new();
    msg.extend_from_slice(&0i32.to_le_bytes());
    msg.extend_from_slice(&1i32.to_le_bytes()); // requestId
    msg.extend_from_slice(&0i32.to_le_bytes());
    msg.extend_from_slice(&2004i32.to_le_bytes()); // OP_QUERY
    msg.extend_from_slice(&0i32.to_le_bytes()); // flags
    msg.extend_from_slice(coll);
    msg.extend_from_slice(&0i32.to_le_bytes()); // skip
    msg.extend_from_slice(&(-1i32).to_le_bytes()); // return
    msg.extend_from_slice(query_doc);
    let len = msg.len() as i32;
    msg[0..4].copy_from_slice(&len.to_le_bytes());
    msg
}

/// Best-effort BSON UTF-8 string field extractor (`\x02 name \\0 int32 value \\0`).
fn bson_find_cstring(buf: &[u8], field: &str) -> Option<String> {
    let mut needle = Vec::with_capacity(field.len() + 2);
    needle.push(0x02);
    needle.extend_from_slice(field.as_bytes());
    needle.push(0);
    let pos = buf
        .windows(needle.len())
        .position(|w| w == needle.as_slice())?;
    let start = pos + needle.len();
    if start + 4 > buf.len() {
        return None;
    }
    let slen = i32::from_le_bytes(buf[start..start + 4].try_into().ok()?) as usize;
    if slen == 0 || start + 4 + slen > buf.len() {
        return None;
    }
    // slen includes trailing NUL
    let raw = &buf[start + 4..start + 4 + slen.saturating_sub(1)];
    let s = String::from_utf8_lossy(raw).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s.chars().take(64).collect())
    }
}

fn bson_find_i32(buf: &[u8], field: &str) -> Option<i32> {
    let mut needle = Vec::with_capacity(field.len() + 2);
    needle.push(0x10);
    needle.extend_from_slice(field.as_bytes());
    needle.push(0);
    let pos = buf
        .windows(needle.len())
        .position(|w| w == needle.as_slice())?;
    let start = pos + needle.len();
    if start + 4 > buf.len() {
        return None;
    }
    Some(i32::from_le_bytes(buf[start..start + 4].try_into().ok()?))
}

/// Elasticsearch: HTTP GET `/` — parse `version.number` / tagline.
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

/// Memcached: ASCII `version` / `stats` observe.
pub async fn observe_memcached(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    stream.write_all(b"version\r\n").await?;
    let mut buf = [0u8; 512];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
    if n == 0 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "memcached".into(),
            detail: "empty reply".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&buf[..n]);
    let line = text.lines().next().unwrap_or("").trim();
    if !line.to_ascii_uppercase().starts_with("VERSION") && !line.contains("ERROR") {
        // Try stats once
        let _ = stream.write_all(b"stats\r\n").await;
        let mut sbuf = [0u8; 2048];
        let sn = match timeout(Duration::from_secs(2), stream.read(&mut sbuf)).await {
            Ok(Ok(m)) => m,
            _ => 0,
        };
        let stext = String::from_utf8_lossy(&sbuf[..sn]);
        if !stext.contains("STAT ") && !stext.contains("END") {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "memcached".into(),
                detail: format!("unexpected: {line}"),
                confidence: 0.3,
            });
            return Ok(None);
        }
        let ver = stext.lines().find_map(|l| {
            l.strip_prefix("STAT version ")
                .map(|v| v.trim().to_string())
        });
        let detail = match &ver {
            Some(v) => format!("Memcached {v}"),
            None => "Memcached (stats ok)".into(),
        };
        emit_memcached(addr, port, &detail, ver.as_deref(), &emit);
        let _ = stream.write_all(b"quit\r\n").await;
        return Ok(Some(detail));
    }

    let version = line
        .strip_prefix("VERSION ")
        .or_else(|| line.strip_prefix("VERSION"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let detail = match &version {
        Some(v) => format!("Memcached {v}"),
        None => line.chars().take(80).collect(),
    };
    emit_memcached(addr, port, &detail, version.as_deref(), &emit);
    let _ = stream.write_all(b"quit\r\n").await;
    Ok(Some(detail))
}

fn emit_memcached(
    addr: IpAddr,
    port: u16,
    detail: &str,
    version: Option<&str>,
    emit: &impl Fn(Event),
) {
    emit(Event::Banner {
        addr,
        port,
        banner: detail.into(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "memcached".into(),
        detail: detail.into(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "memcached".into(),
            product: Some("Memcached".into()),
            version: version.map(|s| s.into()),
            extra: Some(detail.into()),
            confidence: 0.9,
        },
    });
}

/// Minimal JSON string field extractor (`"key" : "value"`).
fn json_string_field(json: &str, key: &str) -> Option<String> {
    let patterns = [format!("\"{key}\""), format!("\"{key}\" ")];
    for pat in &patterns {
        let mut rest = json;
        while let Some(i) = rest.find(pat.as_str()) {
            let after = &rest[i + pat.len()..];
            let after = after.trim_start();
            let after = after.strip_prefix(':')?.trim_start();
            if let Some(after) = after.strip_prefix('"') {
                let end = after.find('"')?;
                let val = after[..end].to_string();
                if !val.is_empty() && val.len() < 64 {
                    return Some(val);
                }
            }
            rest = &rest[i + 1..];
        }
    }
    None
}

/// Kafka: ApiVersions (apiKey=18, v0) observe — no topics listed.
pub async fn observe_kafka(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    let client_id = b"aresbird";
    let mut body = Vec::new();
    body.extend_from_slice(&18i16.to_be_bytes()); // ApiVersions
    body.extend_from_slice(&0i16.to_be_bytes()); // version 0
    body.extend_from_slice(&1i32.to_be_bytes()); // correlation_id
    body.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
    body.extend_from_slice(client_id);
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.extend_from_slice(&(body.len() as i32).to_be_bytes());
    msg.extend_from_slice(&body);
    stream.write_all(&msg).await?;

    let mut len_buf = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf)).await??;
    let resp_len = i32::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > 1_000_000 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "kafka".into(),
            detail: format!("bad response size {resp_len}"),
            confidence: 0.2,
        });
        return Ok(None);
    }
    let mut resp = vec![0u8; resp_len.min(8192)];
    let to_read = resp.len();
    timeout(
        Duration::from_secs(3),
        stream.read_exact(&mut resp[..to_read]),
    )
    .await??;
    // Drain remainder if truncated for classification
    if resp_len > to_read {
        let mut sink = vec![0u8; (resp_len - to_read).min(64 * 1024)];
        let _ = timeout(Duration::from_secs(1), stream.read_exact(&mut sink)).await;
    }

    if resp.len() < 6 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "kafka".into(),
            detail: "short ApiVersions reply".into(),
            confidence: 0.25,
        });
        return Ok(None);
    }
    let corr = i32::from_be_bytes(resp[0..4].try_into()?);
    let error = i16::from_be_bytes(resp[4..6].try_into()?);
    if corr != 1 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "kafka".into(),
            detail: format!("unexpected correlation_id {corr}"),
            confidence: 0.35,
        });
        return Ok(None);
    }

    let mut api_count = 0i32;
    if resp.len() >= 10 && error == 0 {
        api_count = i32::from_be_bytes(resp[6..10].try_into()?);
        if !(0..=512).contains(&api_count) {
            api_count = 0;
        }
    }

    let detail = if error != 0 {
        format!("Kafka ApiVersions error_code={error}")
    } else if api_count > 0 {
        format!("Kafka broker (ApiVersions ok, {api_count} APIs)")
    } else {
        "Kafka broker (ApiVersions ok)".into()
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "kafka".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "kafka".into(),
            product: Some("Apache Kafka".into()),
            version: None,
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

/// RabbitMQ / AMQP 0-9-1: send protocol header, parse Connection.Start.
pub async fn observe_amqp(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    // AMQP 0-9-1 protocol header
    stream.write_all(b"AMQP\x00\x00\x09\x01").await?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n < 8 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "amqp".into(),
            detail: "no Connection.Start".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }

    // Frame: type(1) channel(2) size(4) payload… frame-end(0xCE)
    let frame_type = buf[0];
    if frame_type != 1 {
        // Some brokers echo adjusted protocol header on mismatch
        if &buf[..4] == b"AMQP" {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "amqp".into(),
                detail: "AMQP protocol negotiation reply".into(),
                confidence: 0.7,
            });
            emit(Event::ServiceDetected {
                addr,
                port,
                service: ServiceInfo {
                    name: "amqp".into(),
                    product: Some("AMQP".into()),
                    version: None,
                    extra: Some("protocol header reply".into()),
                    confidence: 0.7,
                },
            });
            return Ok(Some("AMQP protocol header reply".into()));
        }
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "amqp".into(),
            detail: format!("unexpected frame type {frame_type}"),
            confidence: 0.3,
        });
        return Ok(None);
    }

    let size = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]) as usize;
    let payload_end = 7 + size.min(n.saturating_sub(7));
    let payload = &buf[7..payload_end];
    if payload.len() < 4 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "amqp".into(),
            detail: "short method frame".into(),
            confidence: 0.3,
        });
        return Ok(None);
    }
    let class_id = u16::from_be_bytes([payload[0], payload[1]]);
    let method_id = u16::from_be_bytes([payload[2], payload[3]]);
    // connection.start = class 10 method 10
    if class_id != 10 || method_id != 10 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "amqp".into(),
            detail: format!("AMQP method {class_id}.{method_id}"),
            confidence: 0.55,
        });
        return Ok(None);
    }

    let major = payload.get(4).copied().unwrap_or(0);
    let minor = payload.get(5).copied().unwrap_or(0);
    let ascii = String::from_utf8_lossy(payload);
    let product = if ascii.to_ascii_lowercase().contains("rabbitmq") {
        "RabbitMQ"
    } else if ascii.to_ascii_lowercase().contains("qpid") {
        "Apache Qpid"
    } else {
        "AMQP broker"
    };
    let version =
        amqp_table_shortstr(&ascii, "version").or_else(|| amqp_find_version_bytes(payload));
    let detail = match &version {
        Some(v) => format!("{product} {v} (AMQP {major}.{minor})"),
        None => format!("{product} (AMQP {major}.{minor} Connection.Start)"),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "amqp".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: if product == "RabbitMQ" {
                "rabbitmq".into()
            } else {
                "amqp".into()
            },
            product: Some(product.into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

fn amqp_table_shortstr(ascii: &str, key: &str) -> Option<String> {
    // Server properties are a binary table; keys often appear as plaintext.
    let needle = key;
    let lower = ascii.to_ascii_lowercase();
    let ki = lower.find(needle)?;
    let after = &ascii[ki + needle.len()..];
    // Skip binary type tags; find consecutive printable version-like token
    let bytes = after.as_bytes();
    let mut i = 0;
    while i < bytes.len() && (bytes[i] < 0x20 || bytes[i] > 0x7e) {
        i += 1;
        if i > 8 {
            break;
        }
    }
    let rest = &after[i..];
    let ver: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if ver.contains('.') && ver.len() >= 3 {
        Some(ver.chars().take(24).collect())
    } else {
        None
    }
}

fn amqp_find_version_bytes(payload: &[u8]) -> Option<String> {
    let key = b"version";
    let pos = payload.windows(key.len()).position(|w| w == key)?;
    let after = &payload[pos + key.len()..];
    // common: type 'S' (long string) = 0x53, then uint32 len, then bytes
    let mut i = 0;
    while i < after.len().min(6) {
        if after[i] == b'S' && i + 5 < after.len() {
            let len = u32::from_be_bytes(after[i + 1..i + 5].try_into().ok()?) as usize;
            if len > 0 && len < 32 && i + 5 + len <= after.len() {
                let s = String::from_utf8_lossy(&after[i + 5..i + 5 + len]).to_string();
                if s.chars().all(|c| c.is_ascii_graphic() || c == '.') {
                    return Some(s);
                }
            }
        }
        i += 1;
    }
    None
}

/// MQTT 3.1.1: CONNECT → CONNACK (client id `ares`, clean session).
pub async fn observe_mqtt(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    // Fixed header 0x10, remaining length 16; Protocol MQTT / level 4 / clean / client "ares"
    let connect = [
        0x10, 0x10, // CONNECT, remaining length 16
        0x00, 0x04, b'M', b'Q', b'T', b'T', // protocol name
        0x04, // protocol level 3.1.1
        0x02, // clean session
        0x00, 0x00, // keep alive
        0x00, 0x04, b'a', b'r', b'e', b's', // client id
    ];
    stream.write_all(&connect).await?;

    let mut buf = [0u8; 8];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n < 4 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "mqtt".into(),
            detail: "no CONNACK".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }
    let packet_type = buf[0] >> 4;
    if packet_type != 2 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "mqtt".into(),
            detail: format!("unexpected MQTT packet type {packet_type}"),
            confidence: 0.3,
        });
        return Ok(None);
    }
    // CONNACK: type, remaining len, flags, return code
    let rc = if n >= 4 { buf[3] } else { 0xff };
    let rc_label = match rc {
        0 => "accepted",
        1 => "unacceptable protocol",
        2 => "identifier rejected",
        3 => "server unavailable",
        4 => "bad credentials",
        5 => "not authorized",
        other => {
            return {
                emit(Event::ProbeResult {
                    addr,
                    port,
                    probe: "mqtt".into(),
                    detail: format!("CONNACK rc={other}"),
                    confidence: 0.7,
                });
                Ok(Some(format!("MQTT CONNACK rc={other}")))
            }
        }
    };
    let detail = format!("MQTT 3.1.1 CONNACK ({rc_label})");
    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "mqtt".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "mqtt".into(),
            product: Some("MQTT".into()),
            version: Some("3.1.1".into()),
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    // DISCONNECT
    let _ = stream.write_all(&[0xe0, 0x00]).await;
    Ok(Some(detail))
}

/// NATS: read server `INFO {…}` line on connect.
pub async fn observe_nats(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n == 0 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "nats".into(),
            detail: "empty greeting".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&buf[..n]);
    let line = text.lines().next().unwrap_or("").trim();
    if !line.starts_with("INFO ") && !line.starts_with("info ") {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "nats".into(),
            detail: format!("unexpected: {}", line.chars().take(60).collect::<String>()),
            confidence: 0.3,
        });
        return Ok(None);
    }
    let json = line
        .strip_prefix("INFO ")
        .or_else(|| line.strip_prefix("info "))
        .unwrap_or("");
    let version = json_string_field(json, "version");
    let server_name = json_string_field(json, "server_name");
    let proto = json_string_field(json, "proto").or_else(|| {
        // proto is often a number
        let key = "\"proto\"";
        let i = json.find(key)?;
        let after = json[i + key.len()..]
            .trim_start()
            .strip_prefix(':')?
            .trim_start();
        let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if num.is_empty() {
            None
        } else {
            Some(num)
        }
    });
    let detail = match (&version, &server_name) {
        (Some(v), Some(n)) => format!("NATS {v} server={n}"),
        (Some(v), None) => format!("NATS {v}"),
        (None, Some(n)) => format!("NATS server={n}"),
        (None, None) => match &proto {
            Some(p) => format!("NATS INFO proto={p}"),
            None => "NATS INFO".into(),
        },
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "nats".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "nats".into(),
            product: Some("NATS".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    let _ = stream.write_all(b"CONNECT {\"verbose\":false,\"pedantic\":false,\"lang\":\"aresbird\",\"version\":\"0.1\"}\r\n").await;
    let _ = stream.write_all(b"PING\r\n").await;
    Ok(Some(detail))
}

/// LDAP: anonymous RootDSE search (namingContexts / vendorName / dnsHostName).
pub async fn observe_ldap(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    let req = ldap_rootdse_search(1);
    stream.write_all(&req).await?;

    let mut buf = vec![0u8; 8192];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    // Unbind (best-effort)
    let _ = stream.write_all(&ldap_unbind(2)).await;

    if n < 8 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "ldap".into(),
            detail: "empty/short reply".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }

    // LDAPMessage starts with SEQUENCE 0x30
    if buf[0] != 0x30 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "ldap".into(),
            detail: format!("unexpected BER tag 0x{:02x}", buf[0]),
            confidence: 0.3,
        });
        return Ok(None);
    }

    let ascii = String::from_utf8_lossy(&buf[..n]);
    let looks = ascii.contains("namingContexts")
        || ascii.contains("supportedLDAPVersion")
        || ascii.contains("vendorName")
        || ascii.contains("dsServiceName")
        || ascii.contains("defaultNamingContext")
        || buf[..n]
            .windows(2)
            .any(|w| w == [0x64, 0x84] || w[0] == 0x64); // searchResEntry

    if !looks {
        // Still might be searchResDone with resultCode success and empty entry
        let has_result = buf[..n].contains(&0x65); // searchResDone app 5
        if !has_result {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "ldap".into(),
                detail: "reply without LDAP markers".into(),
                confidence: 0.35,
            });
            return Ok(None);
        }
    }

    let vendor =
        ldap_attr_value(&ascii, "vendorName").or_else(|| ldap_attr_value(&ascii, "vendorVersion"));
    let naming = ldap_attr_value(&ascii, "defaultNamingContext")
        .or_else(|| ldap_attr_value(&ascii, "namingContexts"));
    let dns = ldap_attr_value(&ascii, "dnsHostName");
    let forest = ldap_attr_value(&ascii, "rootDomainNamingContext");

    let product = if ascii.to_ascii_lowercase().contains("microsoft")
        || ascii.contains("ADAM")
        || ascii.contains("dsServiceName")
        || forest.is_some()
    {
        "Microsoft AD / LDAP"
    } else if let Some(ref v) = vendor {
        if v.to_ascii_lowercase().contains("openldap") {
            "OpenLDAP"
        } else if v.to_ascii_lowercase().contains("389") {
            "389 Directory Server"
        } else {
            "LDAP"
        }
    } else {
        "LDAP"
    };

    let mut parts = vec![product.to_string()];
    if let Some(v) = &vendor {
        parts.push(v.clone());
    }
    if let Some(nctx) = &naming {
        parts.push(format!("nc={nctx}"));
    }
    if let Some(d) = &dns {
        parts.push(format!("dns={d}"));
    }
    let detail = parts.join(" | ");

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "ldap".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "ldap".into(),
            product: Some(product.into()),
            version: vendor.clone(),
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

fn ber_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else if len <= 0xffff {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    } else {
        vec![
            0x84,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            (len & 0xff) as u8,
        ]
    }
}

fn ber_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + contents.len());
    out.push(tag);
    out.extend(ber_len(contents.len()));
    out.extend_from_slice(contents);
    out
}

fn ber_int(n: i32) -> Vec<u8> {
    // compact positive integer
    let mut bytes = n.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 && bytes[1] < 0x80 {
        bytes.remove(0);
    }
    ber_tlv(0x02, &bytes)
}

fn ber_enum(n: u8) -> Vec<u8> {
    ber_tlv(0x0a, &[n])
}

fn ber_bool(v: bool) -> Vec<u8> {
    ber_tlv(0x01, &[if v { 0xff } else { 0x00 }])
}

fn ber_octet(s: &[u8]) -> Vec<u8> {
    ber_tlv(0x04, s)
}

fn ldap_rootdse_search(msg_id: i32) -> Vec<u8> {
    // filter: present objectClass — context tag 7
    let filter = ber_tlv(0x87, b"objectClass");
    let mut attrs_body = Vec::new();
    for a in [
        &b"namingContexts"[..],
        b"defaultNamingContext",
        b"vendorName",
        b"vendorVersion",
        b"supportedLDAPVersion",
        b"dnsHostName",
        b"rootDomainNamingContext",
        b"dsServiceName",
    ] {
        attrs_body.extend(ber_octet(a));
    }
    let attrs = ber_tlv(0x30, &attrs_body);

    let mut search = Vec::new();
    search.extend(ber_octet(b"")); // baseObject
    search.extend(ber_enum(0)); // scope base
    search.extend(ber_enum(0)); // deref never
    search.extend(ber_int(0)); // sizeLimit
    search.extend(ber_int(0)); // timeLimit
    search.extend(ber_bool(false)); // typesOnly
    search.extend(filter);
    search.extend(attrs);
    let search_req = ber_tlv(0x63, &search); // APPLICATION 3

    let mut msg = Vec::new();
    msg.extend(ber_int(msg_id));
    msg.extend(search_req);
    ber_tlv(0x30, &msg)
}

fn ldap_unbind(msg_id: i32) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend(ber_int(msg_id));
    msg.extend(ber_tlv(0x42, &[])); // APPLICATION 2 unbindRequest
    ber_tlv(0x30, &msg)
}

/// Best-effort: find attribute type then next printable LDAP string nearby.
fn ldap_attr_value(ascii: &str, attr: &str) -> Option<String> {
    let lower = ascii.to_ascii_lowercase();
    let key = attr.to_ascii_lowercase();
    let mut rest = ascii;
    let mut lower_rest = lower.as_str();
    while let Some(i) = lower_rest.find(&key) {
        let after = &rest[i + attr.len()..];
        // Skip binary noise; gather a DN-ish / version-ish token
        let bytes = after.as_bytes();
        let mut j = 0;
        while j < bytes.len().min(12) && (bytes[j] < 0x20 || bytes[j] > 0x7e) {
            j += 1;
        }
        let candidate: String = after[j..]
            .chars()
            .take_while(|c| {
                c.is_ascii_graphic()
                    || *c == ' '
                    || *c == '='
                    || *c == ','
                    || *c == '.'
                    || *c == '-'
                    || *c == '_'
            })
            .take(120)
            .collect();
        let candidate = candidate.trim().to_string();
        if candidate.len() >= 2
            && !candidate.eq_ignore_ascii_case(attr)
            && !candidate.starts_with("supported")
        {
            return Some(candidate);
        }
        rest = &after[1..];
        lower_rest = &lower_rest[i + 1..];
    }
    None
}

/// VNC / RFB: read server protocol version banner (`RFB 003.008`).
pub async fn observe_vnc(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    let mut buf = [0u8; 32];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n < 12 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "vnc".into(),
            detail: "short/no RFB banner".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }
    let banner = String::from_utf8_lossy(&buf[..n]);
    let line = banner.lines().next().unwrap_or("").trim();
    if !line.starts_with("RFB ") {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "vnc".into(),
            detail: format!("unexpected: {}", line.chars().take(40).collect::<String>()),
            confidence: 0.3,
        });
        return Ok(None);
    }
    let version = line.strip_prefix("RFB ").unwrap_or("").trim().to_string();
    // Echo the same version to advance handshake briefly (security-types byte).
    let reply = format!("{}\n", line.trim_end_matches('\n'));
    let _ = stream.write_all(reply.as_bytes()).await;
    let mut sec = [0u8; 16];
    let sn = timeout(Duration::from_secs(2), stream.read(&mut sec))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0);
    let sec_detail = if sn >= 1 {
        let ntypes = sec[0] as usize;
        if ntypes > 0 && ntypes < 16 && sn >= 1 + ntypes {
            let types: Vec<String> = sec[1..1 + ntypes]
                .iter()
                .map(|t| match t {
                    0 => "Invalid".into(),
                    1 => "None".into(),
                    2 => "VNCAuth".into(),
                    16 => "Tight".into(),
                    18 => "TLS".into(),
                    19 => "VeNCrypt".into(),
                    other => format!("type-{other}"),
                })
                .collect();
            format!("; security=[{}]", types.join(","))
        } else if ntypes == 0 && sn >= 5 {
            // failure reason string length follows
            "; security negotiation failed".into()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let detail = format!("VNC RFB {version}{sec_detail}");
    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "vnc".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "vnc".into(),
            product: Some("VNC/RFB".into()),
            version: Some(version),
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

/// Kerberos V5: AS-REQ over TCP/88 → parse KRB-ERROR/AS-REP for realm (no password/preauth abuse).
pub async fn observe_kerberos(
    addr: IpAddr,
    port: u16,
    realm_hint: Option<&str>,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let realm = realm_hint
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "UNKNOWN".into());
    let as_req = build_as_req("aresbird", &realm);
    let mut stream = connect(addr, port).await?;
    let mut framed = Vec::with_capacity(4 + as_req.len());
    framed.extend_from_slice(&(as_req.len() as u32).to_be_bytes());
    framed.extend_from_slice(&as_req);
    stream.write_all(&framed).await?;

    let mut len_buf = [0u8; 4];
    match timeout(Duration::from_secs(3), stream.read_exact(&mut len_buf)).await {
        Ok(Ok(_)) => {}
        _ => {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "kerberos".into(),
                detail: "no TCP Kerberos reply".into(),
                confidence: 0.2,
            });
            return Ok(None);
        }
    }
    let mut resp_len = u32::from_be_bytes(len_buf);
    // Ignore extension high-bit probes — treat lower 31 bits as length when plausible.
    if resp_len & 0x8000_0000 != 0 {
        resp_len &= 0x7fff_ffff;
    }
    if resp_len == 0 || resp_len > 64 * 1024 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "kerberos".into(),
            detail: format!("bad Kerberos length {resp_len}"),
            confidence: 0.3,
        });
        return Ok(None);
    }
    let take = (resp_len as usize).min(8192);
    let mut resp = vec![0u8; take];
    timeout(Duration::from_secs(3), stream.read_exact(&mut resp)).await??;

    let ascii = String::from_utf8_lossy(&resp);
    // APPLICATION 30 = KRB-ERROR (0x7e), APPLICATION 11 = AS-REP (0x6b)
    let is_error = resp.first() == Some(&0x7e);
    let is_as_rep = resp.first() == Some(&0x6b);
    if !is_error && !is_as_rep && !ascii.contains("krbtgt") {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "kerberos".into(),
            detail: format!(
                "unexpected Kerberos tag 0x{:02x}",
                resp.first().unwrap_or(&0)
            ),
            confidence: 0.35,
        });
        return Ok(None);
    }

    let realm_found = krb_find_realm(&resp).or_else(|| krb_find_realm_ascii(&ascii));
    let err_code = if is_error {
        krb_error_code(&resp)
    } else {
        None
    };
    let err_label: Option<String> = match err_code {
        Some(25) => Some("PREAUTH_REQUIRED".into()),
        Some(6) => Some("C_PRINCIPAL_UNKNOWN".into()),
        Some(7) => Some("S_PRINCIPAL_UNKNOWN".into()),
        Some(68) => Some("WRONG_REALM".into()),
        Some(52) => Some("FIELD_TOOLONG".into()),
        Some(n) => Some(format!("code={n}")),
        None => None,
    };

    let detail = match (&realm_found, &err_label, is_as_rep) {
        (Some(r), Some(e), _) => format!("Kerberos V5 realm={r} ({e})"),
        (Some(r), None, true) => format!("Kerberos V5 realm={r} (AS-REP)"),
        (Some(r), None, _) => format!("Kerberos V5 realm={r}"),
        (None, Some(e), _) => format!("Kerberos V5 ({e})"),
        (None, None, true) => "Kerberos V5 AS-REP".into(),
        (None, None, _) => "Kerberos V5 KRB-ERROR".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "kerberos".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "kerberos".into(),
            product: Some("Kerberos V5".into()),
            version: realm_found.clone(),
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

/// Kerberos explicit CONTEXT tag wrapping a complete inner TLV.
fn der_ctx(n: u8, value_tlv: &[u8]) -> Vec<u8> {
    ber_tlv(0xa0 | n, value_tlv)
}

fn build_as_req(user: &str, realm: &str) -> Vec<u8> {
    let cname = principal_name(1, &[user]);
    let sname = principal_name(2, &["krbtgt", realm]);
    let mut body = Vec::new();
    body.extend(der_ctx(0, &ber_tlv(0x03, &[0x00, 0x00, 0x00, 0x00, 0x00])));
    body.extend(der_ctx(1, &cname));
    body.extend(der_ctx(2, &ber_tlv(0x1b, realm.as_bytes())));
    body.extend(der_ctx(3, &sname));
    body.extend(der_ctx(5, &ber_tlv(0x18, b"20300101000000Z")));
    body.extend(der_ctx(7, &ber_int(0x1234_5678u32 as i32)));
    let mut etypes = Vec::new();
    for e in [18i32, 17, 23] {
        etypes.extend(ber_int(e));
    }
    body.extend(der_ctx(8, &ber_tlv(0x30, &etypes)));
    let req_body = der_ctx(4, &ber_tlv(0x30, &body));

    let mut kdc_req = Vec::new();
    kdc_req.extend(der_ctx(1, &ber_int(5)));
    kdc_req.extend(der_ctx(2, &ber_int(10)));
    kdc_req.extend(req_body);
    ber_tlv(0x6a, &ber_tlv(0x30, &kdc_req))
}

fn principal_name(name_type: i32, parts: &[&str]) -> Vec<u8> {
    let mut strings = Vec::new();
    for p in parts {
        strings.extend(ber_tlv(0x1b, p.as_bytes()));
    }
    let mut seq = Vec::new();
    seq.extend(der_ctx(0, &ber_int(name_type)));
    seq.extend(der_ctx(1, &ber_tlv(0x30, &strings)));
    ber_tlv(0x30, &seq)
}

fn ber_parse_len(buf: &[u8]) -> Option<(usize, usize)> {
    let b0 = *buf.first()?;
    if b0 < 0x80 {
        Some((b0 as usize, 1))
    } else if b0 == 0x81 && buf.len() >= 2 {
        Some((buf[1] as usize, 2))
    } else if b0 == 0x82 && buf.len() >= 3 {
        Some((((buf[1] as usize) << 8) | buf[2] as usize, 3))
    } else {
        None
    }
}

fn krb_find_realm(buf: &[u8]) -> Option<String> {
    // Look for GeneralString (0x1b) that looks like a REALM (has a dot or is ALLCAPS)
    let mut i = 0;
    while i + 2 < buf.len() {
        if buf[i] == 0x1b {
            if let Some((len, hdr)) = ber_parse_len(&buf[i + 1..]) {
                let start = i + 1 + hdr;
                if start + len <= buf.len() && len >= 2 && len <= 64 {
                    let s = String::from_utf8_lossy(&buf[start..start + len]).to_string();
                    if s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
                        && (s.contains('.')
                            || s.chars()
                                .all(|c| c.is_ascii_uppercase() || c == '-' || c.is_ascii_digit()))
                        && s.to_ascii_lowercase() != "aresbird"
                        && s.to_ascii_lowercase() != "krbtgt"
                        && s.to_ascii_lowercase() != "unknown"
                    {
                        return Some(s);
                    }
                }
                i = start + len;
                continue;
            }
        }
        i += 1;
    }
    None
}

fn krb_find_realm_ascii(ascii: &str) -> Option<String> {
    // Fallback: token with dots looking like DOMAIN.LOCAL
    for tok in ascii.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
        if tok.contains('.')
            && tok.len() >= 3
            && tok.len() <= 64
            && tok.chars().any(|c| c.is_ascii_uppercase())
        {
            return Some(tok.to_string());
        }
    }
    None
}

fn krb_error_code(buf: &[u8]) -> Option<i32> {
    // error-code [6] INTEGER inside KRB-ERROR — look for CONTEXT 6 then INTEGER
    let mut i = 0;
    while i + 3 < buf.len() {
        if buf[i] == 0xa6 || buf[i] == 0x86 {
            if let Some((len, hdr)) = ber_parse_len(&buf[i + 1..]) {
                let start = i + 1 + hdr;
                let slice = &buf[start..start + len.min(buf.len().saturating_sub(start))];
                if let Some(v) = parse_inner_int(slice) {
                    return Some(v);
                }
            }
        }
        i += 1;
    }
    None
}

fn parse_inner_int(buf: &[u8]) -> Option<i32> {
    if buf.first() == Some(&0x02) {
        let (len, hdr) = ber_parse_len(&buf[1..])?;
        let start = 1 + hdr;
        if start + len > buf.len() || len == 0 || len > 4 {
            return None;
        }
        let mut v = 0i32;
        for b in &buf[start..start + len] {
            v = (v << 8) | i32::from(*b);
        }
        Some(v)
    } else if buf.len() <= 4 {
        let mut v = 0i32;
        for b in buf {
            v = (v << 8) | i32::from(*b);
        }
        Some(v)
    } else {
        None
    }
}

/// WinRM / WS-Management: HTTP(S) `/wsman` observe (no auth / no command exec).
pub async fn observe_winrm(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let use_tls = port == 5986;
    let host = addr.to_string();
    // Minimal Identify-style POST often returns 401 with WWW-Authenticate: Negotiate
    let body = concat!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" ",
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" ",
        "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\">",
        "<s:Header>",
        "<a:To>http://windows-host:5985/wsman</a:To>",
        "<w:ResourceURI s:mustUnderstand=\"true\">",
        "http://schemas.dmtf.org/wbem/wsman/1/wsman/Identity</w:ResourceURI>",
        "<a:ReplyTo><a:Address>",
        "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
        "</a:Address></a:ReplyTo>",
        "<a:Action s:mustUnderstand=\"true\">",
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>",
        "<a:MessageID>uuid:00000000-0000-0000-0000-000000000001</a:MessageID>",
        "</s:Header><s:Body/></s:Envelope>"
    );
    let req = format!(
        "POST /wsman HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: AresBird/0.1\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    let text = if use_tls {
        winrm_exchange_tls(addr, port, &host, req.as_bytes()).await?
    } else {
        winrm_exchange_plain(addr, port, req.as_bytes()).await?
    };

    if text.is_empty() {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "winrm".into(),
            detail: "empty HTTP reply".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let status = text.lines().next().unwrap_or("").to_string();
    let server = http_header_value(&text, "server");
    let auth = http_header_value(&text, "www-authenticate");
    let looks = status.contains("401")
        || status.contains("405")
        || status.contains("200")
        || server
            .as_deref()
            .map(|s| s.to_ascii_lowercase().contains("microsoft-httpapi"))
            .unwrap_or(false)
        || auth
            .as_deref()
            .map(|s| {
                let l = s.to_ascii_lowercase();
                l.contains("negotiate") || l.contains("ntlm") || l.contains("kerberos")
            })
            .unwrap_or(false)
        || text.to_ascii_lowercase().contains("wsman");

    if !looks {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "winrm".into(),
            detail: format!("HTTP reply without WinRM markers: {status}"),
            confidence: 0.3,
        });
        return Ok(None);
    }

    let scheme = if use_tls { "HTTPS" } else { "HTTP" };
    let mut parts = vec![format!("WinRM {scheme} /wsman")];
    if let Some(s) = &server {
        parts.push(s.clone());
    }
    if let Some(a) = &auth {
        let short: String = a.chars().take(48).collect();
        parts.push(format!("auth={short}"));
    }
    parts.push(status.chars().take(40).collect());
    let detail = parts.join(" | ");

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "winrm".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "winrm".into(),
            product: Some("WinRM / WS-Management".into()),
            version: server.clone(),
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

async fn winrm_exchange_plain(addr: IpAddr, port: u16, req: &[u8]) -> anyhow::Result<String> {
    let mut stream = connect(addr, port).await?;
    stream.write_all(req).await?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    Ok(String::from_utf8_lossy(&buf[..n]).to_string())
}

async fn winrm_exchange_tls(
    addr: IpAddr,
    port: u16,
    sni: &str,
    req: &[u8],
) -> anyhow::Result<String> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
    use std::sync::Arc;
    use tokio_rustls::TlsConnector;

    #[derive(Debug)]
    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            let _ = end_entity;
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let stream = connect(addr, port).await?;
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let name =
        ServerName::try_from(sni.to_string()).map_err(|e| anyhow::anyhow!("bad SNI: {e}"))?;
    let mut tls = timeout(Duration::from_secs(5), connector.connect(name, stream)).await??;
    tls.write_all(req).await?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(3), tls.read(&mut buf)).await??;
    Ok(String::from_utf8_lossy(&buf[..n]).to_string())
}

fn http_header_value(response: &str, name: &str) -> Option<String> {
    let want = name.to_ascii_lowercase();
    for line in response.lines() {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().to_ascii_lowercase() == want {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// SNMP v2c: GET `sysDescr.0` with community (default `public`) over UDP.
pub async fn observe_snmp(
    addr: IpAddr,
    port: u16,
    community: &str,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let community = if community.is_empty() {
        "public"
    } else {
        community
    };
    let pkt = snmp_v2c_get(community, &[1, 3, 6, 1, 2, 1, 1, 1, 0]); // sysDescr.0
    let sock = UdpSocket::bind(if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    let dest = SocketAddr::new(addr, port);
    sock.send_to(&pkt, dest).await?;
    let mut buf = [0u8; 1500];
    let n = match timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => n,
        _ => {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "snmp".into(),
                detail: format!("no UDP reply (community={community})"),
                confidence: 0.25,
            });
            return Ok(None);
        }
    };

    if n < 10 || buf[0] != 0x30 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "snmp".into(),
            detail: "unexpected SNMP reply".into(),
            confidence: 0.3,
        });
        return Ok(None);
    }

    let descr = snmp_extract_octet_string(&buf[..n])
        .map(|s| s.chars().take(160).collect::<String>())
        .filter(|s| !s.is_empty());
    let detail = match &descr {
        Some(d) => format!("SNMP sysDescr: {d}"),
        None => format!("SNMP v2c reply ({n} bytes, community={community})"),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "snmp".into(),
        detail: detail.clone(),
        confidence: if descr.is_some() { 0.9 } else { 0.7 },
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "snmp".into(),
            product: Some("SNMP".into()),
            version: None,
            extra: Some(detail.clone()),
            confidence: if descr.is_some() { 0.9 } else { 0.7 },
        },
    });
    Ok(Some(detail))
}

fn snmp_v2c_get(community: &str, oid: &[u32]) -> Vec<u8> {
    let oid_enc = snmp_encode_oid(oid);
    // VarBind: SEQUENCE { OID, NULL }
    let mut vb = Vec::new();
    vb.extend(ber_tlv(0x06, &oid_enc));
    vb.extend(ber_tlv(0x05, &[])); // NULL
    let vb = ber_tlv(0x30, &vb);
    let vbs = ber_tlv(0x30, &vb);

    let mut pdu = Vec::new();
    pdu.extend(ber_int(1)); // request-id
    pdu.extend(ber_int(0)); // error-status
    pdu.extend(ber_int(0)); // error-index
    pdu.extend(vbs);
    // GetRequest-PDU context [0] constructed => 0xa0
    let pdu = ber_tlv(0xa0, &pdu);

    let mut msg = Vec::new();
    msg.extend(ber_int(1)); // version SNMPv2c
    msg.extend(ber_tlv(0x04, community.as_bytes()));
    msg.extend(pdu);
    ber_tlv(0x30, &msg)
}

fn snmp_encode_oid(oid: &[u32]) -> Vec<u8> {
    assert!(oid.len() >= 2);
    let mut out = vec![(oid[0] * 40 + oid[1]) as u8];
    for &n in &oid[2..] {
        if n < 128 {
            out.push(n as u8);
        } else {
            // base-128
            let mut stack = Vec::new();
            let mut v = n;
            stack.push((v & 0x7f) as u8);
            v >>= 7;
            while v > 0 {
                stack.push(((v & 0x7f) as u8) | 0x80);
                v >>= 7;
            }
            stack.reverse();
            out.extend(stack);
        }
    }
    out
}

fn snmp_extract_octet_string(buf: &[u8]) -> Option<String> {
    // Prefer longest printable OCTET STRING (sysDescr is usually the main one).
    let mut best: Option<String> = None;
    let mut i = 0;
    while i + 2 < buf.len() {
        if buf[i] == 0x04 {
            if let Some((len, hdr)) = ber_parse_len(&buf[i + 1..]) {
                let start = i + 1 + hdr;
                if start + len <= buf.len() && len >= 3 && len <= 512 {
                    let raw = &buf[start..start + len];
                    let printable = raw
                        .iter()
                        .filter(|b| b.is_ascii_graphic() || **b == b' ' || **b == b'\t')
                        .count();
                    if printable * 10 >= len * 7 {
                        let s = String::from_utf8_lossy(raw).trim().to_string();
                        if best.as_ref().map(|b| b.len()).unwrap_or(0) < s.len() {
                            best = Some(s);
                        }
                    }
                }
                i = start + len;
                continue;
            }
        }
        i += 1;
    }
    best
}

async fn http_get_body(addr: IpAddr, port: u16, path: &str) -> anyhow::Result<(u16, String)> {
    let (st, _raw, body) = http_get_raw(addr, port, path).await?;
    Ok((st, body))
}

async fn http_get_raw(
    addr: IpAddr,
    port: u16,
    path: &str,
) -> anyhow::Result<(u16, String, String)> {
    let mut stream = connect(addr, port).await?;
    let host = addr.to_string();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: AresBird/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = vec![0u8; 8192];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .chars()
        .take(4000)
        .collect();
    Ok((status, text, body))
}

/// Docker Engine API (typically :2375 unencrypted) — `/_ping` + `/version`.
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

fn emit_docker(
    addr: IpAddr,
    port: u16,
    detail: &str,
    version: Option<String>,
    emit: &impl Fn(Event),
) {
    emit(Event::Banner {
        addr,
        port,
        banner: detail.into(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "docker".into(),
        detail: detail.into(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "docker".into(),
            product: Some("Docker Engine API".into()),
            version,
            extra: Some(detail.into()),
            confidence: 0.95,
        },
    });
}

/// etcd HTTP API — `/version` / `/health`.
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

fn emit_etcd(
    addr: IpAddr,
    port: u16,
    detail: &str,
    version: Option<String>,
    emit: &impl Fn(Event),
) {
    emit(Event::Banner {
        addr,
        port,
        banner: detail.into(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "etcd".into(),
        detail: detail.into(),
        confidence: 0.92,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "etcd".into(),
            product: Some("etcd".into()),
            version,
            extra: Some(detail.into()),
            confidence: 0.92,
        },
    });
}

/// Consul HTTP API — `/v1/status/leader` (unauthenticated lab exposure).
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

fn emit_consul(
    addr: IpAddr,
    port: u16,
    detail: &str,
    version: Option<String>,
    emit: &impl Fn(Event),
) {
    emit(Event::Banner {
        addr,
        port,
        banner: detail.into(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "consul".into(),
        detail: detail.into(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "consul".into(),
            product: Some("Consul".into()),
            version,
            extra: Some(detail.into()),
            confidence: 0.9,
        },
    });
}

/// MSSQL / TDS Pre-Login observe (default :1433) — no auth / no query abuse.
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

fn tds_prelogin_request() -> Vec<u8> {
    // PRELOGIN options: VERSION, ENCRYPTION, INSTOPT, THREADID, MARS, TERMINATOR
    // Token table then data blob (see MS-TDS).
    let mut data = Vec::new();
    // VERSION: 6 bytes major.minor.build...
    let version_data = [0x09u8, 0x00, 0x00, 0x00, 0x00, 0x00];
    let enc_data = [0x00u8]; // ENCRYPT=NOT_SUP from client probe
    let inst_data = [0x00u8];
    let thread_data = [0x00u8, 0x00, 0x00, 0x00];
    let mars_data = [0x00u8];

    let mut tokens = Vec::new();
    // After tokens (5*5 + 1 terminator = 26 bytes) comes data
    let mut offset: u16 = 26;

    // VERSION token 0x00
    tokens.extend_from_slice(&[0x00]);
    tokens.extend_from_slice(&offset.to_be_bytes());
    tokens.extend_from_slice(&(version_data.len() as u16).to_be_bytes());
    offset += version_data.len() as u16;
    // ENCRYPTION 0x01
    tokens.extend_from_slice(&[0x01]);
    tokens.extend_from_slice(&offset.to_be_bytes());
    tokens.extend_from_slice(&(enc_data.len() as u16).to_be_bytes());
    offset += enc_data.len() as u16;
    // INSTOPT 0x02
    tokens.extend_from_slice(&[0x02]);
    tokens.extend_from_slice(&offset.to_be_bytes());
    tokens.extend_from_slice(&(inst_data.len() as u16).to_be_bytes());
    offset += inst_data.len() as u16;
    // THREADID 0x03
    tokens.extend_from_slice(&[0x03]);
    tokens.extend_from_slice(&offset.to_be_bytes());
    tokens.extend_from_slice(&(thread_data.len() as u16).to_be_bytes());
    offset += thread_data.len() as u16;
    // MARS 0x04
    tokens.extend_from_slice(&[0x04]);
    tokens.extend_from_slice(&offset.to_be_bytes());
    tokens.extend_from_slice(&(mars_data.len() as u16).to_be_bytes());
    // TERMINATOR
    tokens.push(0xff);

    data.extend_from_slice(&tokens);
    data.extend_from_slice(&version_data);
    data.extend_from_slice(&enc_data);
    data.extend_from_slice(&inst_data);
    data.extend_from_slice(&thread_data);
    data.extend_from_slice(&mars_data);

    let total = (data.len() + 8) as u16;
    let mut pkt = Vec::with_capacity(total as usize);
    pkt.push(0x12); // PRELOGIN
    pkt.push(0x01); // EOM
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // SPID
    pkt.push(0x01); // PacketID
    pkt.push(0x00); // Window
    pkt.extend_from_slice(&data);
    pkt
}

fn parse_tds_prelogin(body: &[u8]) -> (Option<String>, Option<u8>) {
    // Walk option tokens until 0xFF; offsets are relative to start of token stream
    let mut version = None;
    let mut encryption = None;
    let mut i = 0;
    while i + 5 <= body.len() {
        let token = body[i];
        if token == 0xff {
            break;
        }
        let off = u16::from_be_bytes([body[i + 1], body[i + 2]]) as usize;
        let len = u16::from_be_bytes([body[i + 3], body[i + 4]]) as usize;
        i += 5;
        if off + len > body.len() {
            continue;
        }
        let slice = &body[off..off + len];
        match token {
            0x00 if slice.len() >= 6 => {
                // UL_VERSION: major, minor, build (ul), subbuild
                let major = slice[0];
                let minor = slice[1];
                let build = u16::from_be_bytes([slice[2], slice[3]]);
                version = Some(format!("{major}.{minor}.{build}"));
            }
            0x01 if !slice.is_empty() => {
                encryption = Some(slice[0]);
            }
            _ => {}
        }
    }
    (version, encryption)
}

/// Kubernetes API server observe (typically :6443 HTTPS) — `/version` / `/readyz`.
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

fn emit_k8s(addr: IpAddr, port: u16, detail: &str, version: Option<String>, emit: &impl Fn(Event)) {
    emit(Event::Banner {
        addr,
        port,
        banner: detail.into(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "kubernetes".into(),
        detail: detail.into(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "kubernetes".into(),
            product: Some("Kubernetes API".into()),
            version,
            extra: Some(detail.into()),
            confidence: 0.9,
        },
    });
}

/// Oracle TNS listener observe (default :1521) — `COMMAND=version` only.
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

fn tns_version_request() -> Vec<u8> {
    // Minimal TNS Connect carrying CONNECT_DATA=(COMMAND=version)
    let connect_data = b"(CONNECT_DATA=(COMMAND=version))";
    // Fixed-size TNS Connect header (nspcnt style) + connect data
    // Layout mirrors common oracle-tns probes (compatible with 10g–19c listeners).
    let mut body = Vec::new();
    body.extend_from_slice(&[
        0x01, 0x3a, // version
        0x01, 0x2c, // compat
        0x00, 0x00, // service options
        0x08, 0x00, // SDU size
        0x7f, 0xff, // TDU size
        0x7f, 0x08, // NT protocol characteristics
        0x00, 0x00, // line characteristics
        0x00, 0x01, // value of hardware/OS? historically 1
    ]);
    // connect data length + offset historically: len then reserved… then data
    let cd_len = connect_data.len() as u16;
    body.extend_from_slice(&cd_len.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x3a]); // historical max
    body.extend_from_slice(&[0x00; 22]);
    body.extend_from_slice(connect_data);

    let total = (body.len() + 8) as u16;
    let mut pkt = Vec::with_capacity(total as usize);
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // packet checksum
    pkt.push(0x01); // Connect
    pkt.push(0x00); // reserved
    pkt.extend_from_slice(&[0x00, 0x00]); // header checksum
    pkt.extend_from_slice(&body);
    pkt
}

fn extract_oracle_version(text: &str) -> Option<String> {
    // VSNNUM=186647296 style or "Version 19.0.0.0.0"
    if let Some(i) = text.find("Version ") {
        let rest = &text[i + 8..];
        let ver: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if !ver.is_empty() {
            return Some(ver);
        }
    }
    // ASCII digits after "Oracle"
    if let Some(i) = text.to_ascii_lowercase().find("oracle") {
        let slice = &text[i..];
        for part in slice.split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-') {
            if part.chars().any(|c| c.is_ascii_digit())
                && part.contains('.')
                && part.len() >= 3
                && part.len() <= 24
            {
                return Some(part.to_string());
            }
        }
    }
    None
}

/// CouchDB HTTP API observe (default :5984) — `GET /`.
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

/// ZooKeeper four-letter commands observe (default :2181) — `ruok` / `srvr`.
pub async fn observe_zookeeper(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    stream.write_all(b"ruok").await?;
    let mut buf = [0u8; 64];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
    let ruok = String::from_utf8_lossy(&buf[..n]);
    if !ruok.contains("imok") {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "zookeeper".into(),
            detail: format!("no ruok/imok ({n} bytes)"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    // Best-effort version/mode from `srvr` (may be disabled).
    let mut version: Option<String> = None;
    let mut mode: Option<String> = None;
    if let Ok(mut s2) = connect(addr, port).await {
        let _ = s2.write_all(b"srvr").await;
        let mut b2 = [0u8; 1024];
        if let Ok(Ok(n2)) = timeout(Duration::from_secs(2), s2.read(&mut b2)).await {
            let text = String::from_utf8_lossy(&b2[..n2]);
            for line in text.lines() {
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("zookeeper version:") {
                    version = Some(
                        line.split_once(':')
                            .map(|(_, v)| v.trim().to_string())
                            .unwrap_or_default(),
                    );
                    if version.as_ref().is_some_and(|v| v.is_empty()) {
                        version = None;
                    }
                } else if lower.starts_with("mode:") {
                    mode = Some(
                        line.split_once(':')
                            .map(|(_, v)| v.trim().to_string())
                            .unwrap_or_default(),
                    );
                }
            }
        }
    }

    let detail = match (&version, &mode) {
        (Some(v), Some(m)) => format!("ZooKeeper {v} ({m})"),
        (Some(v), None) => format!("ZooKeeper {v}"),
        (None, Some(m)) => format!("ZooKeeper imok ({m})"),
        _ => "ZooKeeper imok".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "zookeeper".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "zookeeper".into(),
            product: Some("Apache ZooKeeper".into()),
            version,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}

/// Cassandra native protocol observe (default :9042) — OPTIONS → SUPPORTED.
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

/// Parse first value for `key` from a Cassandra string-multimap body.
fn cassandra_multimap_first(body: &[u8], key: &str) -> Option<String> {
    if body.len() < 2 {
        return None;
    }
    let mut i = 0usize;
    let map_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    for _ in 0..map_len {
        if i + 2 > body.len() {
            break;
        }
        let klen = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        if i + klen > body.len() {
            break;
        }
        let k = String::from_utf8_lossy(&body[i..i + klen]);
        i += klen;
        if i + 2 > body.len() {
            break;
        }
        let vcount = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        let mut first: Option<String> = None;
        for _ in 0..vcount {
            if i + 2 > body.len() {
                return first.filter(|_| k.eq_ignore_ascii_case(key));
            }
            let vlen = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
            i += 2;
            if i + vlen > body.len() {
                return first.filter(|_| k.eq_ignore_ascii_case(key));
            }
            let v = String::from_utf8_lossy(&body[i..i + vlen]).into_owned();
            i += vlen;
            if first.is_none() {
                first = Some(v);
            }
        }
        if k.eq_ignore_ascii_case(key) {
            return first;
        }
    }
    None
}

/// RDP / Terminal Services observe (default :3389) — TPKT + X.224 CR + negotiation.
pub async fn observe_rdp(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let mut stream = connect(addr, port).await?;
    let pkt = rdp_connection_request();
    stream.write_all(&pkt).await?;
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n < 7 {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "rdp".into(),
            detail: "short/no X.224 reply".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }

    // TPKT version 3 + X.224 Connection Confirm (0xd0) is the strong signal.
    let tpkt_ok = buf[0] == 0x03;
    let x224_cc = buf.get(5).copied() == Some(0xd0);
    if !tpkt_ok || !x224_cc {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "rdp".into(),
            detail: format!("unexpected frame ({n} bytes)"),
            confidence: 0.25,
        });
        return Ok(None);
    }

    let neg = parse_rdp_negotiation(&buf[..n]);
    let detail = match &neg {
        Some(RdpNeg::Response { protocol, flags }) => {
            let proto_name = rdp_protocol_name(*protocol);
            if *flags & 0x01 != 0 {
                format!("RDP {proto_name} (extended)")
            } else {
                format!("RDP {proto_name}")
            }
        }
        Some(RdpNeg::Failure { code }) => format!("RDP negotiation failure code={code}"),
        None => "RDP (X.224 CC)".into(),
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "rdp".into(),
        detail: detail.clone(),
        confidence: 0.95,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "rdp".into(),
            product: Some("Microsoft Remote Desktop".into()),
            version: None,
            extra: Some(detail.clone()),
            confidence: 0.95,
        },
    });
    Ok(Some(detail))
}

fn rdp_connection_request() -> Vec<u8> {
    // Cookie + RDP_NEG_REQ requesting PROTOCOL_RDP | SSL | HYBRID | HYBRID_EX
    let cookie = b"Cookie: mstshash=AresBird\r\n";
    let mut x224 = Vec::new();
    x224.push(0xe0); // CR
    x224.extend_from_slice(&[0x00, 0x00]); // dst-ref
    x224.extend_from_slice(&[0x00, 0x00]); // src-ref
    x224.push(0x00); // class
    x224.extend_from_slice(cookie);
    // RDP Negotiation Request: type=1, flags=0, length=8, requestedProtocols=PROTOCOL_SSL|HYBRID|HYBRID_EX|RDP
    x224.push(0x01);
    x224.push(0x00);
    x224.extend_from_slice(&8u16.to_le_bytes());
    // 0x0000000B = PROTOCOL_SSL (1) | HYBRID (2) | HYBRID_EX (8)
    x224.extend_from_slice(&0x0000_000Bu32.to_le_bytes());

    let li = (x224.len()) as u8; // length indicator excludes itself
    let mut body = Vec::with_capacity(1 + x224.len());
    body.push(li);
    body.extend_from_slice(&x224);

    let total = (body.len() + 4) as u16;
    let mut pkt = Vec::with_capacity(total as usize);
    pkt.push(0x03); // TPKT version
    pkt.push(0x00);
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}

enum RdpNeg {
    Response { protocol: u32, flags: u8 },
    Failure { code: u32 },
}

fn parse_rdp_negotiation(buf: &[u8]) -> Option<RdpNeg> {
    // After TPKT(4) + LI(1) + CC header(~6) + optional cookie, look for type 0x02/0x03
    // Scan for negotiation structures in the reply.
    let mut i = 0usize;
    while i + 8 <= buf.len() {
        let ty = buf[i];
        if ty == 0x02 || ty == 0x03 {
            let flags = buf[i + 1];
            let len = u16::from_le_bytes([buf[i + 2], buf[i + 3]]) as usize;
            if len == 8 && i + 8 <= buf.len() {
                let code = u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
                return Some(if ty == 0x02 {
                    RdpNeg::Response {
                        protocol: code,
                        flags,
                    }
                } else {
                    RdpNeg::Failure { code }
                });
            }
        }
        i += 1;
    }
    None
}

fn rdp_protocol_name(protocol: u32) -> &'static str {
    match protocol {
        0x0000_0000 => "standard",
        0x0000_0001 => "TLS",
        0x0000_0002 => "NLA/CredSSP",
        0x0000_0008 => "NLA-ext",
        _ => "negotiated",
    }
}

/// Neo4j HTTP discovery observe (default :7474) — GET /.
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

/// ClickHouse HTTP observe (default :8123) — `/ping` + optional `SELECT version()`.
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

fn format_bolt_version(v: u32) -> String {
    // Legacy: 0x0000000N → N.0; modern: low bytes = major.minor packed.
    if v <= 0xff {
        return format!("{v}.0");
    }
    let major = (v >> 8) & 0xff;
    let minor = v & 0xff;
    if major > 0 && major < 20 {
        return format!("{major}.{minor}");
    }
    format!("0x{v:08x}")
}

/// RabbitMQ Management UI/API observe (default :15672).
pub async fn observe_rabbitmq(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, raw, body) = http_get_raw(addr, port, "/").await?;
    let lower = body.to_ascii_lowercase();
    let server = http_header_value(&raw, "Server").unwrap_or_default();
    let looks = lower.contains("rabbitmq management")
        || lower.contains("rabbitmq")
        || (server.to_ascii_lowercase().contains("cowboy") && matches!(st, 200 | 301 | 302 | 401));

    // Stronger check via API path (often 401 without creds).
    let mut api_hit = false;
    if let Ok((ast, araw, abody)) = http_get_raw(addr, port, "/api/overview").await {
        let al = abody.to_ascii_lowercase();
        if al.contains("rabbitmq")
            || al.contains("management_version")
            || (ast == 401
                && http_header_value(&araw, "WWW-Authenticate")
                    .is_some_and(|v| v.to_ascii_lowercase().contains("basic")))
        {
            api_hit = true;
        }
        if let Some(v) = json_string_field(&abody, "rabbitmq_version")
            .or_else(|| json_string_field(&abody, "management_version"))
        {
            let detail = format!("RabbitMQ Management {v}");
            emit(Event::Banner {
                addr,
                port,
                banner: detail.clone(),
            });
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "rabbitmq".into(),
                detail: detail.clone(),
                confidence: 0.95,
            });
            emit(Event::ServiceDetected {
                addr,
                port,
                service: ServiceInfo {
                    name: "rabbitmq-mgmt".into(),
                    product: Some("RabbitMQ Management".into()),
                    version: Some(v),
                    extra: Some(detail.clone()),
                    confidence: 0.95,
                },
            });
            return Ok(Some(detail));
        }
    }

    if !looks && !api_hit {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "rabbitmq".into(),
            detail: format!("no RabbitMQ Management markers (status={st})"),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let detail: String = if api_hit {
        "RabbitMQ Management API".into()
    } else {
        "RabbitMQ Management UI".into()
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "rabbitmq".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "rabbitmq-mgmt".into(),
            product: Some("RabbitMQ Management".into()),
            version: None,
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}

/// Grafana HTTP observe (default :3000) — `/api/health` + login markers.
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

/// Kibana HTTP observe (default :5601) — `/api/status` + UI markers.
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

/// Prometheus HTTP observe (default :9090) — `/-/healthy` + `/api/v1/status/buildinfo`.
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

/// Jenkins HTTP observe (often :8080) — `/login` + `X-Jenkins` markers.
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
