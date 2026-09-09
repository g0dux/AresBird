//! messaging service observers (shared helpers live in the parent module).

use super::*;

/// Kafka: ApiVersions (apiKey=18, v0) observe -- no topics listed.
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

    // Frame: type(1) channel(2) size(4) payload... frame-end(0xCE)
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

/// MQTT 3.1.1: CONNECT -> CONNACK (client id `ares`, clean session).
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

/// NATS: read server `INFO {...}` line on connect.
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

/// ZooKeeper four-letter commands observe (default :2181) -- `ruok` / `srvr`.
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

/// gRPC / HTTP/2 cleartext observe (default :50051) -- preface + grpc Content-Type probe.
pub async fn observe_grpc(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    // 1) HTTP/2 connection preface -- SETTINGS frame (type 0x04, empty) is enough.
    let mut h2_ok = false;
    {
        let mut stream = connect(addr, port).await?;
        let mut preface = Vec::new();
        preface.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        // Empty SETTINGS frame: length=0, type=0x04, flags=0, stream=0
        preface.extend_from_slice(&[0, 0, 0, 0x04, 0, 0, 0, 0, 0]);
        stream.write_all(&preface).await?;
        let mut buf = [0u8; 128];
        if let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            // Look for a SETTINGS frame (type byte at offset 3 of a 9-byte header).
            if n >= 9 {
                for i in 0..n.saturating_sub(8) {
                    if buf[i + 3] == 0x04 {
                        h2_ok = true;
                        break;
                    }
                }
            }
            // GOAWAY / any HTTP/2 frame-looking reply also counts.
            if !h2_ok && n >= 9 && buf[3] <= 0x09 {
                h2_ok = true;
            }
        }
    }

    // 2) HTTP/1.1 POST with application/grpc -- many servers echo grpc-status.
    let mut grpc_hdr = false;
    {
        let mut stream = connect(addr, port).await?;
        let host = addr.to_string();
        let req = format!(
            "POST /grpc.health.v1.Health/Check HTTP/1.1\r\n\
             Host: {host}\r\n\
             User-Agent: AresBird/0.1\r\n\
             Content-Type: application/grpc\r\n\
             Te: trailers\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\r\n"
        );
        let _ = stream.write_all(req.as_bytes()).await;
        let mut buf = vec![0u8; 2048];
        if let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            let text = String::from_utf8_lossy(&buf[..n]);
            let lower = text.to_ascii_lowercase();
            grpc_hdr = lower.contains("application/grpc")
                || lower.contains("grpc-status")
                || lower.contains("grpc-message")
                || http_header_value(&text, "Content-Type")
                    .map(|v| v.to_ascii_lowercase().contains("grpc"))
                    .unwrap_or(false);
        }
    }

    if !h2_ok && !grpc_hdr {
        emit(Event::ProbeResult {
            addr,
            port,
            probe: "grpc".into(),
            detail: "no HTTP/2 or gRPC markers".into(),
            confidence: 0.2,
        });
        return Ok(None);
    }

    let detail = match (h2_ok, grpc_hdr) {
        (true, true) => "gRPC over HTTP/2".to_string(),
        (true, false) => "HTTP/2 cleartext (possible gRPC)".to_string(),
        (false, true) => "gRPC Content-Type response".to_string(),
        _ => unreachable!(),
    };
    let confidence = if grpc_hdr { 0.9 } else { 0.7 };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "grpc".into(),
        detail: detail.clone(),
        confidence,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "grpc".into(),
            product: Some("gRPC".into()),
            version: None,
            extra: Some(detail.clone()),
            confidence,
        },
    });
    Ok(Some(detail))
}

/// Hazelcast REST observe (default :5701) -- `/hazelcast/rest/cluster`.
pub async fn observe_hazelcast(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let (st, body) = http_get_body(addr, port, "/hazelcast/rest/cluster").await?;
    let lower = body.to_ascii_lowercase();
    let looks = st == 200
        && (lower.contains("hazelcast") || lower.contains("members") || lower.contains("cluster"));
    if !looks {
        // Older builds sometimes answer on /hazelcast/health
        let (st2, b2) = http_get_body(addr, port, "/hazelcast/health").await?;
        let l2 = b2.to_ascii_lowercase();
        if !((st2 == 200 || st2 == 503)
            && (l2.contains("hazelcast") || l2.contains("nodestate") || l2.contains("cluster")))
        {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "hazelcast".into(),
                detail: format!("no Hazelcast REST markers (status={st})"),
                confidence: 0.2,
            });
            return Ok(None);
        }
    }

    let detail = if lower.contains("hazelcast") || body.to_ascii_lowercase().contains("hazelcast") {
        let ver = json_string_field(&body, "version");
        match ver {
            Some(v) => format!("Hazelcast {v}"),
            None => "Hazelcast".into(),
        }
    } else {
        "Hazelcast".into()
    };

    emit(Event::Banner {
        addr,
        port,
        banner: detail.clone(),
    });
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "hazelcast".into(),
        detail: detail.clone(),
        confidence: 0.9,
    });
    emit(Event::ServiceDetected {
        addr,
        port,
        service: ServiceInfo {
            name: "hazelcast".into(),
            product: Some("Hazelcast".into()),
            version: json_string_field(&body, "version"),
            extra: Some(detail.clone()),
            confidence: 0.9,
        },
    });
    Ok(Some(detail))
}
