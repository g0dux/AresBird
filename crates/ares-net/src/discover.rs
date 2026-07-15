use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ares_core::event::Event;
use ares_core::timing::jitter_delay_ms;
use futures::stream::{self, StreamExt};
use parking_lot::Mutex;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::traceroute::ping_host;

/// Host discovery: ping first (when available), then TCP probes.
/// With `prefer_arp` on Linux+raw, try L2 ARP sweep first for IPv4 targets.
pub async fn host_discover(
    addrs: &[IpAddr],
    probe_ports: &[u16],
    timeout_ms: u64,
    cancel: CancellationToken,
    emit: impl Fn(Event) + Send + Sync + 'static,
) -> Vec<IpAddr> {
    host_discover_opts(
        addrs,
        probe_ports,
        timeout_ms,
        false,
        0,
        false,
        None,
        64,
        cancel,
        emit,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn host_discover_opts(
    addrs: &[IpAddr],
    probe_ports: &[u16],
    timeout_ms: u64,
    prefer_arp: bool,
    jitter_ms: u64,
    shuffle: bool,
    rate_pps: Option<u64>,
    concurrency: usize,
    cancel: CancellationToken,
    emit: impl Fn(Event) + Send + Sync + 'static,
) -> Vec<IpAddr> {
    if prefer_arp {
        #[cfg(all(feature = "raw", target_os = "linux"))]
        {
            let dur = Duration::from_millis(timeout_ms.max(500));
            match crate::arp::arp_sweep(addrs, dur, cancel.clone(), &emit) {
                Ok(up) => {
                    let found: std::collections::HashSet<_> = up.iter().copied().collect();
                    let rest: Vec<_> = addrs
                        .iter()
                        .copied()
                        .filter(|a| !found.contains(a))
                        .collect();
                    if rest.is_empty() || cancel.is_cancelled() {
                        return up;
                    }
                    let mut all = up;
                    all.extend(
                        host_discover_tcp_icmp(
                            &rest,
                            probe_ports,
                            timeout_ms,
                            jitter_ms,
                            shuffle,
                            rate_pps,
                            concurrency,
                            cancel,
                            emit,
                        )
                        .await,
                    );
                    return all;
                }
                Err(e) => {
                    emit(Event::Log {
                        level: "warn".into(),
                        message: format!("arp-sweep failed ({e}) — falling back to icmp/tcp"),
                    });
                }
            }
        }
        #[cfg(not(all(feature = "raw", target_os = "linux")))]
        {
            emit(Event::Log {
                level: "warn".into(),
                message: "discover --arp needs Linux build with ares-net --features raw; using icmp/tcp"
                    .into(),
            });
        }
    }

    host_discover_tcp_icmp(
        addrs,
        probe_ports,
        timeout_ms,
        jitter_ms,
        shuffle,
        rate_pps,
        concurrency,
        cancel,
        emit,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn host_discover_tcp_icmp(
    addrs: &[IpAddr],
    probe_ports: &[u16],
    timeout_ms: u64,
    jitter_ms: u64,
    shuffle: bool,
    rate_pps: Option<u64>,
    concurrency: usize,
    cancel: CancellationToken,
    emit: impl Fn(Event) + Send + Sync + 'static,
) -> Vec<IpAddr> {
    use ares_core::timing::shuffle_inplace;
    use crate::rate::optional_limiter;

    let ports: Vec<u16> = if probe_ports.is_empty() {
        vec![80, 443, 22, 135, 445, 3389, 8080]
    } else {
        probe_ports.to_vec()
    };
    let dur = Duration::from_millis(timeout_ms);
    let mut ordered: Vec<IpAddr> = addrs.to_vec();
    if shuffle {
        shuffle_inplace(&mut ordered);
    }
    let rate = optional_limiter(rate_pps);
    let concurrency = concurrency.max(1).min(512);
    let sem = Arc::new(Semaphore::new(concurrency));
    let up: Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(Vec::new()));
    let emit = Arc::new(emit);

    stream::iter(ordered)
        .for_each_concurrent(concurrency, |addr| {
            let cancel = cancel.clone();
            let sem = sem.clone();
            let rate = rate.clone();
            let emit = emit.clone();
            let up = up.clone();
            let ports = ports.clone();
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
                if cancel.is_cancelled() {
                    return;
                }
                let start = Instant::now();

                if let Some(rtt) = ping_host(addr).await {
                    emit(Event::HostUp {
                        addr,
                        latency_ms: Some(rtt),
                        method: format!("icmp-ping/{rtt}ms"),
                    });
                    up.lock().push(addr);
                    return;
                }

                let mut alive = false;
                let mut method = String::from("tcp-probe");
                for &port in &ports {
                    if cancel.is_cancelled() {
                        break;
                    }
                    let sa = std::net::SocketAddr::new(addr, port);
                    match timeout(dur, TcpStream::connect(sa)).await {
                        Ok(Ok(_)) => {
                            alive = true;
                            method = format!("tcp/{port}");
                            break;
                        }
                        Ok(Err(_)) => {
                            // Immediate refuse ≈ host up (RST)
                            alive = true;
                            method = format!("tcp-rst/{port}");
                            break;
                        }
                        Err(_) => {}
                    }
                }
                if alive {
                    let latency = start.elapsed().as_millis() as u64;
                    emit(Event::HostUp {
                        addr,
                        latency_ms: Some(latency),
                        method,
                    });
                    up.lock().push(addr);
                } else {
                    emit(Event::HostDown { addr });
                }
            }
        })
        .await;

    let mut out = up.lock().clone();
    out.sort();
    out.dedup();
    out
}
