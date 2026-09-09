//! kv service observers (shared helpers live in the parent module).

use super::*;

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
