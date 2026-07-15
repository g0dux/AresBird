use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ares_core::event::Event;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Read SSH identification string (banner) without completing a handshake.
pub struct SshBanner;

impl SshBanner {
    pub async fn grab(addr: IpAddr, port: u16, emit: impl Fn(Event)) -> anyhow::Result<String> {
        let sa = SocketAddr::new(addr, port);
        let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(sa)).await??;
        let mut buf = [0u8; 256];
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
        let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
        if banner.starts_with("SSH-") {
            emit(Event::Banner {
                addr,
                port,
                banner: banner.clone(),
            });
            emit(Event::ServiceDetected {
                addr,
                port,
                service: ares_core::ServiceInfo {
                    name: "ssh".into(),
                    product: Some(banner.clone()),
                    version: None,
                    extra: None,
                    confidence: 0.95,
                },
            });
        }
        Ok(banner)
    }
}
