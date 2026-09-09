//! identity service observers (shared helpers live in the parent module).

use super::*;

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
        if ntypes > 0 && ntypes < 16 && sn > ntypes {
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

/// Kerberos V5: AS-REQ over TCP/88 -> parse KRB-ERROR/AS-REP for realm (no password/preauth abuse).
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
    // Ignore extension high-bit probes -- treat lower 31 bits as length when plausible.
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

/// RDP / Terminal Services observe (default :3389) -- TPKT + X.224 CR + negotiation.
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
