//! Observe-only probes for common application services (no auth abuse / no exploits).
//!
//! Split by domain into submodules; shared imports and byte/parse helpers live
//! here and are re-exported (`pub(crate) use`) so each submodule reaches them via
//! `use super::*;`. Public API is unchanged: `observe_*` re-exported below.

pub(crate) use std::net::{IpAddr, SocketAddr};
pub(crate) use std::time::Duration;

pub(crate) use ares_core::event::Event;
pub(crate) use ares_core::model::ServiceInfo;
pub(crate) use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub(crate) use tokio::net::{TcpStream, UdpSocket};
pub(crate) use tokio::time::timeout;

mod cloud;
mod documents;
mod identity;
mod kv;
mod mail;
mod messaging;
mod sql;
mod webui;

pub use cloud::*;
pub use documents::*;
pub use identity::*;
pub use kv::*;
pub use mail::*;
pub use messaging::*;
pub use sql::*;
pub use webui::*;

// ---- shared connection + byte/parse helpers --------------------------------

async fn connect(addr: IpAddr, port: u16) -> anyhow::Result<TcpStream> {
    let sa = SocketAddr::new(addr, port);
    Ok(timeout(Duration::from_secs(3), TcpStream::connect(sa)).await??)
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
    // filter: present objectClass -- context tag 7
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
                if start + len <= buf.len() && (2..=64).contains(&len) {
                    let s = String::from_utf8_lossy(&buf[start..start + len]).to_string();
                    if s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
                        && (s.contains('.')
                            || s.chars()
                                .all(|c| c.is_ascii_uppercase() || c == '-' || c.is_ascii_digit()))
                        && !s.eq_ignore_ascii_case("aresbird")
                        && !s.eq_ignore_ascii_case("krbtgt")
                        && !s.eq_ignore_ascii_case("unknown")
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
    // error-code [6] INTEGER inside KRB-ERROR -- look for CONTEXT 6 then INTEGER
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
                if start + len <= buf.len() && (3..=512).contains(&len) {
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

fn tns_version_request() -> Vec<u8> {
    // Minimal TNS Connect carrying CONNECT_DATA=(COMMAND=version)
    let connect_data = b"(CONNECT_DATA=(COMMAND=version))";
    // Fixed-size TNS Connect header (nspcnt style) + connect data
    // Layout mirrors common oracle-tns probes (compatible with 10g-19c listeners).
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
    // connect data length + offset historically: len then reserved... then data
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

fn format_bolt_version(v: u32) -> String {
    // Legacy: 0x0000000N -> N.0; modern: low bytes = major.minor packed.
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
