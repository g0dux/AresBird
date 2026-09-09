use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ares_core::event::Event;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Generic banner grab — read whatever the service sends first; for silent ports send a nudge.
pub async fn grab_banner(addr: IpAddr, port: u16, emit: impl Fn(Event)) -> Option<String> {
    let sa = SocketAddr::new(addr, port);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(sa))
        .await
        .ok()?
        .ok()?;

    // Nudge based on common ports
    let nudge: &[u8] = match port {
        80 | 8080 | 8000 | 8888 | 8008 | 3000 => b"HEAD / HTTP/1.0\r\n\r\n",
        25 | 587 => b"EHLO aresbird.local\r\n",
        21 => b"", // FTP usually speaks first
        110 => b"",
        143 => b"",
        _ => b"",
    };
    if !nudge.is_empty() {
        let _ = stream.write_all(nudge).await;
    }

    let mut buf = [0u8; 1024];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let banner = String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .take(200)
        .collect::<String>();
    if !banner.is_empty() {
        emit(Event::Banner {
            addr,
            port,
            banner: banner.clone(),
        });
        Some(banner)
    } else {
        None
    }
}
