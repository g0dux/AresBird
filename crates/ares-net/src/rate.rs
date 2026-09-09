use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::time::sleep;

/// Token-bucket style rate limiter (packets/ops per second).
pub struct RateLimiter {
    pps: u64,
    interval: Duration,
    last: Mutex<Instant>,
    issued: AtomicU64,
}

impl RateLimiter {
    pub fn new(pps: u64) -> Self {
        let pps = pps.max(1);
        Self {
            pps,
            interval: Duration::from_nanos(1_000_000_000 / pps),
            last: Mutex::new(Instant::now()),
            issued: AtomicU64::new(0),
        }
    }

    pub async fn until_ready(&self) {
        let wait = {
            let mut last = self.last.lock();
            let now = Instant::now();
            let elapsed = now.saturating_duration_since(*last);
            if elapsed < self.interval {
                let w = self.interval - elapsed;
                *last = now + w;
                Some(w)
            } else {
                *last = now;
                None
            }
        };
        if let Some(w) = wait {
            sleep(w).await;
        }
        self.issued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn issued(&self) -> u64 {
        self.issued.load(Ordering::Relaxed)
    }

    pub fn pps(&self) -> u64 {
        self.pps
    }
}

/// Shared helper for building Arc rate limiters.
pub fn optional_limiter(pps: Option<u64>) -> Option<Arc<RateLimiter>> {
    pps.map(|p| Arc::new(RateLimiter::new(p)))
}
