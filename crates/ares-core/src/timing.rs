use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    Quiet,
    #[default]
    Normal,
    Fast,
    Insane,
    Stealth,
}

impl ScanMode {
    pub fn profile(self) -> TimingProfile {
        match self {
            ScanMode::Quiet => TimingProfile {
                concurrency: 20,
                timeout: Duration::from_millis(3000),
                rate_pps: Some(50),
                retries: 2,
                adaptive: true,
                jitter_ms: 120,
                shuffle: true,
                path_delay_ms: 250,
            },
            ScanMode::Normal => TimingProfile {
                concurrency: 200,
                timeout: Duration::from_millis(1000),
                rate_pps: Some(500),
                retries: 1,
                adaptive: true,
                jitter_ms: 0,
                shuffle: false,
                path_delay_ms: 120,
            },
            ScanMode::Fast => TimingProfile {
                concurrency: 800,
                timeout: Duration::from_millis(400),
                rate_pps: Some(5000),
                retries: 0,
                adaptive: true,
                jitter_ms: 0,
                shuffle: false,
                path_delay_ms: 50,
            },
            ScanMode::Insane => TimingProfile {
                concurrency: 2000,
                timeout: Duration::from_millis(200),
                rate_pps: None,
                retries: 0,
                adaptive: false,
                jitter_ms: 0,
                shuffle: false,
                path_delay_ms: 0,
            },
            ScanMode::Stealth => TimingProfile {
                concurrency: 8,
                timeout: Duration::from_millis(5000),
                rate_pps: Some(15),
                retries: 2,
                adaptive: true,
                jitter_ms: 600,
                shuffle: true,
                path_delay_ms: 450,
            },
        }
    }

    /// Quiet/stealth use bland browser-like UA; others identify as AresBird.
    pub fn http_user_agent(self) -> &'static str {
        match self {
            ScanMode::Stealth | ScanMode::Quiet => pick_stealth_ua(),
            _ => "AresBird/0.1",
        }
    }
}

const STEALTH_UAS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
];

fn pick_stealth_ua() -> &'static str {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::Instant::now().hash(&mut h);
    STEALTH_UAS[(h.finish() as usize) % STEALTH_UAS.len()]
}

impl std::str::FromStr for ScanMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "quiet" | "q" | "t1" => Ok(ScanMode::Quiet),
            "normal" | "n" | "t3" => Ok(ScanMode::Normal),
            "fast" | "f" | "t4" => Ok(ScanMode::Fast),
            "insane" | "i" | "t5" => Ok(ScanMode::Insane),
            "stealth" | "s" | "t0" | "t2" => Ok(ScanMode::Stealth),
            other => Err(format!("unknown scan mode: {other}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimingProfile {
    pub concurrency: usize,
    pub timeout: Duration,
    pub rate_pps: Option<u64>,
    pub retries: u32,
    pub adaptive: bool,
    /// Max random inter-probe delay in ms (0 = off). Used by stealth/quiet.
    pub jitter_ms: u64,
    /// Shuffle (ip,port) order before scanning.
    pub shuffle: bool,
    /// Suggested delay between HTTP path probes.
    pub path_delay_ms: u64,
}

/// Fisher–Yates shuffle without external RNG crates.
pub fn shuffle_inplace<T>(items: &mut [T]) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    if items.len() < 2 {
        return;
    }
    for i in (1..items.len()).rev() {
        let mut h = DefaultHasher::new();
        std::time::Instant::now().hash(&mut h);
        i.hash(&mut h);
        std::thread::current().id().hash(&mut h);
        let j = (h.finish() as usize) % (i + 1);
        items.swap(i, j);
    }
}

/// Random delay in `0..=max_ms`.
pub fn jitter_delay_ms(max_ms: u64) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    if max_ms == 0 {
        return 0;
    }
    let mut h = DefaultHasher::new();
    std::time::Instant::now().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    h.finish() % (max_ms + 1)
}

/// Runtime adaptive controller — slows down when filtered ratio spikes.
#[derive(Debug, Default)]
pub struct AdaptiveController {
    open: AtomicU64,
    closed: AtomicU64,
    filtered: AtomicU64,
}

impl AdaptiveController {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_open(&self) {
        self.open.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_closed(&self) {
        self.closed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_filtered(&self) {
        self.filtered.fetch_add(1, Ordering::Relaxed);
    }

    pub fn filtered_ratio(&self) -> f64 {
        let o = self.open.load(Ordering::Relaxed);
        let c = self.closed.load(Ordering::Relaxed);
        let f = self.filtered.load(Ordering::Relaxed);
        let total = o + c + f;
        if total == 0 {
            0.0
        } else {
            f as f64 / total as f64
        }
    }

    /// Suggest timeout multiplier based on filtered ratio (1.0 = unchanged).
    pub fn timeout_scale(&self) -> f64 {
        let r = self.filtered_ratio();
        if r > 0.7 {
            2.0
        } else if r > 0.4 {
            1.5
        } else {
            1.0
        }
    }

    /// Suggest concurrency scale (reduce under heavy filtering).
    pub fn concurrency_scale(&self) -> f64 {
        let r = self.filtered_ratio();
        if r > 0.7 {
            0.35
        } else if r > 0.4 {
            0.6
        } else {
            1.0
        }
    }
}
