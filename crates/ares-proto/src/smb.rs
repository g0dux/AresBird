use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ares_core::event::Event;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Minimal SMB negotiate probe — non-exploiting handshake observe.
///
/// Returns a short dialect label (`SMB1`, `SMB2+`) when a response looks like SMB.
pub async fn smb_negotiate(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    let sa = SocketAddr::new(addr, port);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(sa)).await??;

    let mut payload: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, // NBSS length (patched below)
        0xff, 0x53, 0x4d, 0x42, // SMB magic
        0x72, // Negotiate
        0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02,
    ];
    payload.extend_from_slice(b"NT LM 0.12\x00");
    let len = (payload.len() - 4) as u32;
    payload[1] = ((len >> 16) & 0xff) as u8;
    payload[2] = ((len >> 8) & 0xff) as u8;
    payload[3] = (len & 0xff) as u8;

    stream.write_all(&payload).await?;
    let mut buf = [0u8; 256];
    match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let dialect = classify_smb_reply(&buf[..n]);
            let looks_smb = dialect.is_some();
            let rev = smb2_dialect_revision(&buf[..n]);
            let rev_label = rev.map(smb2_revision_label);
            let detail = match (&dialect, &rev_label) {
                (Some(d), Some(r)) => format!("{d} ({r}) negotiate reply ({n} bytes)"),
                (Some(d), None) => format!("{d} negotiate reply ({n} bytes)"),
                (None, _) => format!("response ({n} bytes)"),
            };
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "smb-negotiate".into(),
                detail: detail.clone(),
                confidence: if looks_smb { 0.85 } else { 0.4 },
            });
            if let Some(ref d) = dialect {
                let version = rev_label.clone().unwrap_or_else(|| d.clone());
                emit(Event::ServiceDetected {
                    addr,
                    port,
                    service: ares_core::ServiceInfo {
                        name: "microsoft-ds".into(),
                        product: Some("SMB".into()),
                        version: Some(version),
                        extra: Some(detail),
                        confidence: 0.85,
                    },
                });
                // Prefer versioned label for OS hint callers when available
                if let Some(r) = rev_label {
                    return Ok(Some(r));
                }
            }
            Ok(dialect)
        }
        _ => {
            emit(Event::ProbeResult {
                addr,
                port,
                probe: "smb-negotiate".into(),
                detail: "no SMB response".into(),
                confidence: 0.2,
            });
            Ok(None)
        }
    }
}

fn classify_smb_reply(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 {
        return None;
    }
    // Canonical NBSS (4-byte length) + SMB header magic
    if buf.len() >= 8 && buf[5] == b'S' && buf[6] == b'M' && buf[7] == b'B' {
        return Some(
            match buf[4] {
                0xff => "SMB1",
                0xfe => "SMB2+",
                0xfd => "SMB2+ encrypted",
                _ => "SMB",
            }
            .into(),
        );
    }
    // Unframed SMB header at offset 0
    if buf.len() >= 4 && buf[1] == b'S' && buf[2] == b'M' && buf[3] == b'B' {
        return Some(match buf[0] {
            0xff => "SMB1".into(),
            0xfe => "SMB2+".into(),
            0xfd => "SMB2+ encrypted".into(),
            _ => "SMB".into(),
        });
    }
    // Lenient: prior heuristic (magic byte at NBSS payload start)
    if buf[4] == 0xff || buf[4] == 0xfe || buf[4] == 0xfd {
        return Some(if buf[4] == 0xff {
            "SMB1".into()
        } else {
            "SMB2+".into()
        });
    }
    None
}

/// Best-effort SMB2 DialectRevision from Negotiate Response body (observe-only).
fn smb2_dialect_revision(buf: &[u8]) -> Option<u16> {
    // NBSS(4) + SMB2 header(64) + StructureSize(2) + SecurityMode(2) = DialectRevision @ 72
    if buf.len() >= 74 && buf[4] == 0xfe && buf[5] == b'S' {
        return Some(u16::from_le_bytes([buf[72], buf[73]]));
    }
    // Unframed SMB2
    if buf.len() >= 70 && buf[0] == 0xfe && buf[1] == b'S' {
        return Some(u16::from_le_bytes([buf[68], buf[69]]));
    }
    None
}

fn smb2_revision_label(rev: u16) -> String {
    match rev {
        0x0202 => "SMB 2.0.2".into(),
        0x0210 => "SMB 2.1".into(),
        0x0300 => "SMB 3.0".into(),
        0x0302 => "SMB 3.0.2".into(),
        0x0311 => "SMB 3.1.1".into(),
        other => format!("SMB2 dialect 0x{other:04x}"),
    }
}
