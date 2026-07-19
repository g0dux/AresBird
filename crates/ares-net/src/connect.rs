use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ares_core::event::Event;
use ares_core::model::PortState;
use ares_core::timing::{jitter_delay_ms, shuffle_inplace, AdaptiveController, TimingProfile};
use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub timing: TimingProfile,
    pub show_closed: bool,
    pub show_filtered: bool,
}

impl ScanConfig {
    pub fn from_timing(timing: TimingProfile) -> Self {
        Self {
            timing,
            show_closed: false,
            show_filtered: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub addr: std::net::IpAddr,
    pub port: u16,
    pub state: PortState,
    pub rtt_ms: Option<u64>,
}

pub struct ConnectScanner {
    pub config: ScanConfig,
}

impl ConnectScanner {
    pub fn new(config: ScanConfig) -> Self {
        Self { config }
    }

    pub async fn scan_one(&self, addr: std::net::IpAddr, port: u16) -> PortScanResult {
        scan_connect(addr, port, self.config.timing.timeout).await
    }

    /// Concurrent TCP connect scan with semaphore backpressure. Emits fabric events.
    pub async fn scan_emit(
        &self,
        targets: &[(std::net::IpAddr, u16)],
        cancel: CancellationToken,
        emit: impl Fn(Event) + Send + Sync + 'static,
    ) -> ScanStats {
        let concurrency = self.config.timing.concurrency.max(1);
        let sem = Arc::new(Semaphore::new(concurrency));
        let open = Arc::new(AtomicU64::new(0));
        let closed = Arc::new(AtomicU64::new(0));
        let filtered = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        let timeout_dur = self.config.timing.timeout;
        let retries = self.config.timing.retries;
        let adaptive = self.config.timing.adaptive;
        let jitter_ms = self.config.timing.jitter_ms;
        let controller = AdaptiveController::new();
        let emit = Arc::new(emit);

        let mut ordered: Vec<_> = targets.to_vec();
        if self.config.timing.shuffle {
            shuffle_inplace(&mut ordered);
            emit(Event::Log {
                level: "info".into(),
                message: format!(
                    "stealth: shuffled {} targets (jitter≤{}ms)",
                    ordered.len(),
                    jitter_ms
                ),
            });
        }

        let rate = self
            .config
            .timing
            .rate_pps
            .map(|pps| Arc::new(crate::rate::RateLimiter::new(pps)));

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PortScanResult>();

        let worker_emit = emit.clone();
        let collector = tokio::spawn(async move {
            while let Some(result) = rx.recv().await {
                // Always record port results for resume/diff; renderer filters display.
                worker_emit(Event::PortResult {
                    addr: result.addr,
                    port: result.port,
                    state: result.state,
                    protocol: "tcp".into(),
                    rtt_ms: result.rtt_ms,
                });
            }
        });

        stream::iter(ordered)
            .for_each_concurrent(concurrency, |(addr, port)| {
                let sem = sem.clone();
                let open = open.clone();
                let closed = closed.clone();
                let filtered = filtered.clone();
                let cancel = cancel.clone();
                let rate = rate.clone();
                let tx = tx.clone();
                let controller = controller.clone();

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
                    if adaptive {
                        let scale = controller.concurrency_scale();
                        if scale < 0.99 {
                            // Soft backpressure when filtered ratio is high (scales wait with severity).
                            let pause_ms = ((1.0 - scale) * 220.0) as u64;
                            if pause_ms > 0 {
                                tokio::time::sleep(Duration::from_millis(pause_ms)).await;
                            }
                        }
                    }
                    if jitter_ms > 0 {
                        let delay = jitter_delay_ms(jitter_ms);
                        if delay > 0 {
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                        }
                    }
                    if cancel.is_cancelled() {
                        return;
                    }

                    let mut t = timeout_dur;
                    if adaptive {
                        let scale = controller.timeout_scale();
                        t = Duration::from_secs_f64(
                            (timeout_dur.as_secs_f64() * scale).clamp(0.05, 12.0),
                        );
                    }

                    let mut result = scan_connect(addr, port, t).await;
                    let mut attempt = 0u32;
                    while attempt < retries
                        && result.state == PortState::Filtered
                        && !cancel.is_cancelled()
                    {
                        attempt += 1;
                        result = scan_connect(addr, port, t).await;
                    }

                    match result.state {
                        PortState::Open => {
                            open.fetch_add(1, Ordering::Relaxed);
                            controller.record_open();
                        }
                        PortState::Closed => {
                            closed.fetch_add(1, Ordering::Relaxed);
                            controller.record_closed();
                        }
                        PortState::Filtered => {
                            filtered.fetch_add(1, Ordering::Relaxed);
                            controller.record_filtered();
                        }
                        _ => {}
                    };
                    done_trace(addr, port, &result);
                    let _ = tx.send(result);
                }
            })
            .await;

        drop(tx);
        let _ = collector.await;

        let elapsed = start.elapsed();
        let stats = ScanStats {
            open: open.load(Ordering::Relaxed),
            closed: closed.load(Ordering::Relaxed),
            filtered: filtered.load(Ordering::Relaxed),
            elapsed,
            total: targets.len() as u64,
        };

        emit(Event::Stats {
            pps: if elapsed.as_secs_f64() > 0.0 {
                stats.total as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            },
            open: stats.open,
            closed: stats.closed,
            filtered: stats.filtered,
            elapsed_ms: elapsed.as_millis() as u64,
        });

        stats
    }
}

fn done_trace(addr: std::net::IpAddr, port: u16, result: &PortScanResult) {
    debug!(%addr, port, state = %result.state, "port result");
}

async fn scan_connect(addr: std::net::IpAddr, port: u16, timeout_dur: Duration) -> PortScanResult {
    let sockaddr = std::net::SocketAddr::new(addr, port);
    let start = Instant::now();
    match timeout(timeout_dur, TcpStream::connect(sockaddr)).await {
        Ok(Ok(_stream)) => PortScanResult {
            addr,
            port,
            state: PortState::Open,
            rtt_ms: Some(start.elapsed().as_millis() as u64),
        },
        Ok(Err(_)) => PortScanResult {
            addr,
            port,
            state: PortState::Closed,
            rtt_ms: Some(start.elapsed().as_millis() as u64),
        },
        Err(_) => PortScanResult {
            addr,
            port,
            state: PortState::Filtered,
            rtt_ms: None,
        },
    }
}

#[derive(Debug, Clone)]
pub struct ScanStats {
    pub open: u64,
    pub closed: u64,
    pub filtered: u64,
    pub elapsed: Duration,
    pub total: u64,
}
