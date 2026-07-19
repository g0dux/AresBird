use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

use crate::model::{PortState, ServiceInfo};

/// Universal fabric events — every network observation/action flows through these.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    JobStarted {
        job_id: Uuid,
        started_at: DateTime<Utc>,
    },
    JobFinished {
        job_id: Uuid,
        finished_at: DateTime<Utc>,
        status: String,
    },
    HostUp {
        addr: IpAddr,
        latency_ms: Option<u64>,
        method: String,
    },
    HostDown {
        addr: IpAddr,
    },
    PortResult {
        addr: IpAddr,
        port: u16,
        state: PortState,
        protocol: String,
        rtt_ms: Option<u64>,
    },
    Banner {
        addr: IpAddr,
        port: u16,
        banner: String,
    },
    ServiceDetected {
        addr: IpAddr,
        port: u16,
        service: ServiceInfo,
    },
    DnsRecord {
        name: String,
        record_type: String,
        value: String,
    },
    TlsCert {
        addr: IpAddr,
        port: u16,
        subject: String,
        issuer: String,
        not_after: String,
    },
    SessionOpened {
        session_id: Uuid,
        addr: IpAddr,
        port: u16,
        protocol: String,
    },
    SessionClosed {
        session_id: Uuid,
    },
    ProbeResult {
        addr: IpAddr,
        port: u16,
        probe: String,
        detail: String,
        confidence: f32,
    },
    MisconfigFinding {
        addr: IpAddr,
        port: Option<u16>,
        finding: String,
        severity: String,
    },
    OsGuess {
        addr: IpAddr,
        os: String,
        confidence: f32,
        /// Observed IP TTL from a reply (SYN-ACK/RST/path), when available.
        #[serde(default)]
        observed_ttl: Option<u8>,
    },
    AsnInfo {
        addr: IpAddr,
        asn: String,
        org: String,
    },
    PathHop {
        target: IpAddr,
        hop: u8,
        addr: Option<IpAddr>,
        rtt_ms: Option<u64>,
        label: String,
    },
    Stats {
        pps: f64,
        open: u64,
        closed: u64,
        filtered: u64,
        elapsed_ms: u64,
    },
    Log {
        level: String,
        message: String,
    },
}

impl Event {
    pub fn is_interesting(&self) -> bool {
        matches!(
            self,
            Event::JobStarted { .. }
                | Event::JobFinished { .. }
                | Event::HostUp { .. }
                | Event::PortResult {
                    state: PortState::Open,
                    ..
                }
                | Event::Banner { .. }
                | Event::ServiceDetected { .. }
                | Event::DnsRecord { .. }
                | Event::TlsCert { .. }
                | Event::MisconfigFinding { .. }
                | Event::OsGuess { .. }
                | Event::ProbeResult { .. }
                | Event::PathHop { .. }
                | Event::AsnInfo { .. }
        )
    }
}

/// Async multi-producer event bus backed by an unbounded channel.
pub struct EventBus {
    tx: tokio::sync::mpsc::UnboundedSender<Event>,
}

impl EventBus {
    pub fn new() -> (Self, tokio::sync::mpsc::UnboundedReceiver<Event>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Self { tx }, rx)
    }

    pub fn emit(&self, event: Event) {
        let _ = self.tx.send(event);
    }

    pub fn sender(&self) -> tokio::sync::mpsc::UnboundedSender<Event> {
        self.tx.clone()
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

/// Collects events into memory for reporting / persistence.
#[derive(Debug, Default, Clone)]
pub struct EventCollector {
    pub events: Vec<Event>,
}

impl EventCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, event: Event) {
        self.events.push(event);
    }

    pub fn interesting(&self) -> Vec<&Event> {
        self.events.iter().filter(|e| e.is_interesting()).collect()
    }

    pub fn open_ports(&self) -> Vec<(IpAddr, u16, String)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::PortResult {
                    addr,
                    port,
                    state: PortState::Open,
                    protocol,
                    ..
                } => Some((*addr, *port, protocol.clone())),
                _ => None,
            })
            .collect()
    }

    pub fn hosts_up(&self) -> Vec<IpAddr> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::HostUp { addr, .. } => Some(*addr),
                _ => None,
            })
            .collect()
    }

    pub fn stats_summary(&self) -> (u64, u64, u64) {
        let mut open = 0u64;
        let mut closed = 0u64;
        let mut filtered = 0u64;
        for e in &self.events {
            if let Event::PortResult { state, .. } = e {
                match state {
                    PortState::Open => open += 1,
                    PortState::Closed => closed += 1,
                    PortState::Filtered => filtered += 1,
                    _ => {}
                }
            }
        }
        (open, closed, filtered)
    }

    /// All (ip, port) pairs that already have a PortResult — used for --resume.
    pub fn scanned_pairs(&self) -> std::collections::HashSet<(IpAddr, u16)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::PortResult { addr, port, .. } => Some((*addr, *port)),
                _ => None,
            })
            .collect()
    }

    /// Misconfig findings for report/JSON summaries (deduped by host+port+message).
    pub fn findings(&self) -> Vec<(IpAddr, Option<u16>, String, String)> {
        use std::collections::HashMap;
        let rank = |s: &str| match s {
            "high" => 4u8,
            "medium" => 3,
            "low" => 2,
            "info" => 1,
            _ => 0,
        };
        let mut best: HashMap<(IpAddr, Option<u16>, String), String> = HashMap::new();
        for e in &self.events {
            if let Event::MisconfigFinding {
                addr,
                port,
                finding,
                severity,
            } = e
            {
                let key = (*addr, *port, finding.clone());
                best.entry(key)
                    .and_modify(|sev| {
                        if rank(severity) > rank(sev) {
                            *sev = severity.clone();
                        }
                    })
                    .or_insert_with(|| severity.clone());
            }
        }
        let mut out: Vec<_> = best
            .into_iter()
            .map(|((addr, port, finding), severity)| (addr, port, severity, finding))
            .collect();
        out.sort_by(|a, b| {
            rank(&b.2)
                .cmp(&rank(&a.2))
                .then(a.0.cmp(&b.0))
                .then(a.1.cmp(&b.1))
                .then(a.3.cmp(&b.3))
        });
        out
    }

    /// Collapse identical finding messages across A/AAAA peers (same port + text).
    /// Returns (representative_addr, port, severity, finding, peer_count).
    pub fn findings_collapsed(&self) -> Vec<(IpAddr, Option<u16>, String, String, usize)> {
        use std::collections::HashMap;
        let rank = |s: &str| match s {
            "high" => 4u8,
            "medium" => 3,
            "low" => 2,
            "info" => 1,
            _ => 0,
        };
        // key: (port, finding) -> (best severity, first addr, set of addrs)
        let mut map: HashMap<
            (Option<u16>, String),
            (String, IpAddr, std::collections::HashSet<IpAddr>),
        > = HashMap::new();
        for (addr, port, severity, finding) in self.findings() {
            let key = (port, finding.clone());
            map.entry(key)
                .and_modify(|(sev, _a, set)| {
                    if rank(&severity) > rank(sev) {
                        *sev = severity.clone();
                    }
                    set.insert(addr);
                })
                .or_insert_with(|| {
                    let mut set = std::collections::HashSet::new();
                    set.insert(addr);
                    (severity, addr, set)
                });
        }
        let mut out: Vec<_> = map
            .into_iter()
            .map(|((port, finding), (severity, addr, set))| {
                (addr, port, severity, finding, set.len())
            })
            .collect();
        out.sort_by(|a, b| {
            rank(&b.2)
                .cmp(&rank(&a.2))
                .then(a.3.cmp(&b.3))
                .then(a.1.cmp(&b.1))
        });
        out
    }
}
