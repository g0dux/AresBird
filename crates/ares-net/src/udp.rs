use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ares_core::event::Event;
use ares_core::model::PortState;
use ares_core::timing::{jitter_delay_ms, shuffle_inplace, TimingProfile};
use futures::stream::{self, StreamExt};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::rate::optional_limiter;

/// Selective UDP scanner for well-known services (DNS/SNMP/NTP/…).
pub struct UdpScanner {
    pub timing: TimingProfile,
}

/// Probes that elicit a response from common UDP services.
fn udp_payload(port: u16) -> &'static [u8] {
    match port {
        53 => {
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        }
        67 | 68 => {
            // DHCP discover-ish (BOOTP minimal)
            b"\x01\x01\x06\x00\x12\x34\x56\x78\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff"
        }
        69 => {
            // TFTP RRQ for "nonexistent" — elicits error from many servers
            b"\x00\x01nonexist\x00octet\x00"
        }
        111 => {
            // RPC Portmap NULL call (rpcbind)
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        }
        123 => &[
            0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        137 => {
            b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
        }
        138 => {
            // NetBIOS datagram header shell
            b"\x11\x02\x00\x44\x00\x00\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        }
        161 => {
            b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
        }
        162 => {
            // SNMP trap coldStart minimal
            b"\x30\x1a\x02\x01\x00\x04\x06public\xa4\x0d\x06\x08\x2b\x06\x01\x02\x01\x01\x03\x00\x40\x01\x00"
        }
        500 | 4500 => {
            // ISAKMP/IKE header shell
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x18"
        }
        514 => b"<14>AresBird udp probe\n",
        520 => {
            // RIP request
            b"\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"
        }
        1900 => {
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
        }
        5353 => {
            b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\t_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
        }
        11211 => b"stats\r\n",
        _ => b"\x00",
    }
}

/// Default UDP inventory set (selective elicit — silent services stay open|filtered without ICMP).
pub const UDP_TOP: &[u16] = &[
    53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 4500, 5353, 11211,
];

impl UdpScanner {
    pub fn new(timing: TimingProfile) -> Self {
        Self { timing }
    }

    pub async fn scan_emit(
        &self,
        addrs: &[IpAddr],
        ports: &[u16],
        cancel: CancellationToken,
        emit: impl Fn(Event) + Send + Sync + 'static,
    ) {
        let concurrency = self.timing.concurrency.clamp(1, 200);
        let sem = Arc::new(Semaphore::new(concurrency));
        let timeout_dur = self.timing.timeout;
        let emit = Arc::new(emit);
        let open = Arc::new(AtomicU64::new(0));
        let open_filtered = Arc::new(AtomicU64::new(0));
        let closed = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        let mut pairs: Vec<(IpAddr, u16)> = addrs
            .iter()
            .flat_map(|a| ports.iter().map(move |p| (*a, *p)))
            .collect();
        let total = pairs.len() as u64;
        if self.timing.shuffle {
            shuffle_inplace(&mut pairs);
        }
        let jitter_ms = self.timing.jitter_ms;
        let rate = optional_limiter(self.timing.rate_pps);

        stream::iter(pairs)
            .for_each_concurrent(concurrency, |(addr, port)| {
                let sem = sem.clone();
                let cancel = cancel.clone();
                let emit = emit.clone();
                let open = open.clone();
                let open_filtered = open_filtered.clone();
                let closed = closed.clone();
                let rate = rate.clone();
                async move {
                    if cancel.is_cancelled() {
                        return;
                    }
                    let Ok(_permit) = sem.acquire().await else {
                        return;
                    };
                    if let Some(ref r) = rate {
                        r.until_ready().await;
                    }
                    if jitter_ms > 0 {
                        let d = jitter_delay_ms(jitter_ms);
                        if d > 0 {
                            tokio::time::sleep(Duration::from_millis(d)).await;
                        }
                    }
                    let state = probe_udp(addr, port, timeout_dur).await;
                    match state {
                        PortState::Open => {
                            open.fetch_add(1, Ordering::Relaxed);
                        }
                        PortState::OpenFiltered => {
                            open_filtered.fetch_add(1, Ordering::Relaxed);
                        }
                        PortState::Closed => {
                            closed.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                    // Always record for store/resume; live renderer filters by --show-*
                    emit(Event::PortResult {
                        addr,
                        port,
                        state,
                        protocol: "udp".into(),
                        rtt_ms: None,
                    });
                }
            })
            .await;

        let elapsed = start.elapsed();
        let o = open.load(Ordering::Relaxed);
        let of = open_filtered.load(Ordering::Relaxed);
        let c = closed.load(Ordering::Relaxed);
        emit(Event::Log {
            level: "info".into(),
            message: format!(
                "udp scan done: open={o} open|filtered={of} closed={c} total={total} (no ICMP ⇒ silent = open|filtered)"
            ),
        });
        emit(Event::Stats {
            pps: if elapsed.as_secs_f64() > 0.0 {
                total as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            },
            open: o,
            closed: c,
            filtered: of,
            elapsed_ms: elapsed.as_millis() as u64,
        });
    }
}

async fn probe_udp(addr: IpAddr, port: u16, timeout_dur: Duration) -> PortState {
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(_) => return PortState::Unknown,
    };
    let dest = SocketAddr::new(addr, port);
    let payload = udp_payload(port);
    if sock.send_to(payload, dest).await.is_err() {
        return PortState::Unknown;
    }
    let mut buf = [0u8; 1500];
    match timeout(timeout_dur, sock.recv_from(&mut buf)).await {
        Ok(Ok(_)) => PortState::Open,
        Ok(Err(_)) => PortState::Closed,
        Err(_) => PortState::OpenFiltered,
    }
}
