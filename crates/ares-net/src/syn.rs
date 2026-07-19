//! TCP SYN / connect engine selection.
//!
//! - Default: async TCP connect (portable)
//! - `--syn` on Linux with `--features raw`: raw SYN via pnet
//! - `--syn` elsewhere: high-concurrency short-timeout connect ("syn-compat")

use std::net::IpAddr;

use ares_core::event::Event;
use ares_core::timing::TimingProfile;
use tokio_util::sync::CancellationToken;

use crate::connect::{ConnectScanner, ScanConfig, ScanStats};

#[cfg(all(feature = "raw", target_os = "linux"))]
#[path = "syn_linux.rs"]
mod syn_linux;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanEngineKind {
    Connect,
    /// Best-effort half-open style on non-raw platforms
    SynCompat,
    /// True raw SYN (Linux + feature raw)
    SynRaw,
}

impl ScanEngineKind {
    pub fn resolve(want_syn: bool) -> Self {
        if !want_syn {
            return ScanEngineKind::Connect;
        }
        if cfg!(all(feature = "raw", target_os = "linux")) {
            ScanEngineKind::SynRaw
        } else {
            ScanEngineKind::SynCompat
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ScanEngineKind::Connect => "connect",
            ScanEngineKind::SynCompat => "syn-compat",
            ScanEngineKind::SynRaw => "syn-raw",
        }
    }
}

pub async fn scan_with_engine(
    kind: ScanEngineKind,
    targets: &[(IpAddr, u16)],
    timing: TimingProfile,
    show_closed: bool,
    show_filtered: bool,
    cancel: CancellationToken,
    emit: impl Fn(Event) + Send + Sync + 'static,
) -> ScanStats {
    match kind {
        ScanEngineKind::Connect => {
            let mut cfg = ScanConfig::from_timing(timing);
            cfg.show_closed = show_closed;
            cfg.show_filtered = show_filtered;
            ConnectScanner::new(cfg)
                .scan_emit(targets, cancel, emit)
                .await
        }
        ScanEngineKind::SynCompat => {
            emit(Event::Log {
                level: "info".into(),
                message: "syn-compat: short-timeout high-concurrency connect (raw SYN needs Linux+raw feature)".into(),
            });
            let mut syn_timing = timing;
            syn_timing.timeout = syn_timing
                .timeout
                .min(std::time::Duration::from_millis(250));
            syn_timing.concurrency = syn_timing.concurrency.max(1000);
            syn_timing.retries = 0;
            let mut cfg = ScanConfig::from_timing(syn_timing);
            cfg.show_closed = show_closed;
            cfg.show_filtered = show_filtered;
            ConnectScanner::new(cfg)
                .scan_emit(targets, cancel, emit)
                .await
        }
        ScanEngineKind::SynRaw => {
            #[cfg(all(feature = "raw", target_os = "linux"))]
            {
                match syn_linux::syn_scan_emit(
                    targets,
                    timing,
                    show_closed,
                    show_filtered,
                    cancel.clone(),
                    &emit,
                )
                .await
                {
                    Ok(stats) => stats,
                    Err(e) => {
                        emit(Event::Log {
                            level: "warn".into(),
                            message: format!("syn-raw failed ({e}) — falling back to syn-compat"),
                        });
                        let mut syn_timing = timing;
                        syn_timing.timeout = syn_timing
                            .timeout
                            .min(std::time::Duration::from_millis(250));
                        syn_timing.concurrency = syn_timing.concurrency.max(1000);
                        let mut cfg = ScanConfig::from_timing(syn_timing);
                        cfg.show_closed = show_closed;
                        cfg.show_filtered = show_filtered;
                        ConnectScanner::new(cfg)
                            .scan_emit(targets, cancel, emit)
                            .await
                    }
                }
            }
            #[cfg(not(all(feature = "raw", target_os = "linux")))]
            {
                let _ = (targets, timing, show_closed, show_filtered, cancel, emit);
                unreachable!("SynRaw only selected on linux+raw");
            }
        }
    }
}
