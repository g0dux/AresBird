use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

use crate::model::{PortState, ServiceInfo};

/// Stable schema version for the serialized [`Event`] contract.
///
/// The wire shape of `Event` (serde-tagged with `"type"` in snake_case) is a
/// public contract consumed by NDJSON plugins (see `docs/plugin-abi.md`) and by
/// report exporters. Bump this whenever a change is *not* backward compatible
/// (renaming/removing a variant or a non-`Option` field). Additive changes
/// (new variants, new `#[serde(default)]` fields) keep the same version.
pub const EVENT_SCHEMA_VERSION: u32 = 1;

/// Universal fabric events — every network observation/action flows through these.
///
/// # Wire contract
///
/// Serialized as an internally-tagged enum: each event is a JSON object with a
/// `"type"` field holding the snake_case variant name (see [`Event::kind`]) plus
/// the variant's fields inline. This is the exact shape NDJSON plugins emit and
/// exporters read, so treat variant names and non-optional field names as
/// stable per [`EVENT_SCHEMA_VERSION`].
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
    /// Stable wire discriminator — matches the serde `"type"` tag exactly.
    ///
    /// This is the canonical name plugins and exporters key on; it is part of
    /// the [`EVENT_SCHEMA_VERSION`] contract and must not change for an existing
    /// variant without a version bump.
    pub fn kind(&self) -> &'static str {
        match self {
            Event::JobStarted { .. } => "job_started",
            Event::JobFinished { .. } => "job_finished",
            Event::HostUp { .. } => "host_up",
            Event::HostDown { .. } => "host_down",
            Event::PortResult { .. } => "port_result",
            Event::Banner { .. } => "banner",
            Event::ServiceDetected { .. } => "service_detected",
            Event::DnsRecord { .. } => "dns_record",
            Event::TlsCert { .. } => "tls_cert",
            Event::SessionOpened { .. } => "session_opened",
            Event::SessionClosed { .. } => "session_closed",
            Event::ProbeResult { .. } => "probe_result",
            Event::MisconfigFinding { .. } => "misconfig_finding",
            Event::OsGuess { .. } => "os_guess",
            Event::AsnInfo { .. } => "asn_info",
            Event::PathHop { .. } => "path_hop",
            Event::Stats { .. } => "stats",
            Event::Log { .. } => "log",
        }
    }

    /// Every wire discriminator, in declaration order. Handy for tooling that
    /// wants to enumerate or document the contract (schemas, filters, docs).
    pub const KINDS: &'static [&'static str] = &[
        "job_started",
        "job_finished",
        "host_up",
        "host_down",
        "port_result",
        "banner",
        "service_detected",
        "dns_record",
        "tls_cert",
        "session_opened",
        "session_closed",
        "probe_result",
        "misconfig_finding",
        "os_guess",
        "asn_info",
        "path_hop",
        "stats",
        "log",
    ];

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
        type FindingAgg = (String, IpAddr, std::collections::HashSet<IpAddr>);
        let mut map: HashMap<(Option<u16>, String), FindingAgg> = HashMap::new();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_events() -> Vec<Event> {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let id = Uuid::nil();
        vec![
            Event::JobStarted {
                job_id: id,
                started_at: Utc::now(),
            },
            Event::JobFinished {
                job_id: id,
                finished_at: Utc::now(),
                status: "completed".into(),
            },
            Event::HostUp {
                addr: ip,
                latency_ms: Some(1),
                method: "tcp".into(),
            },
            Event::HostDown { addr: ip },
            Event::PortResult {
                addr: ip,
                port: 80,
                state: PortState::Open,
                protocol: "tcp".into(),
                rtt_ms: Some(2),
            },
            Event::Banner {
                addr: ip,
                port: 80,
                banner: "srv".into(),
            },
            Event::ServiceDetected {
                addr: ip,
                port: 80,
                service: ServiceInfo {
                    name: "http".into(),
                    product: None,
                    version: None,
                    extra: None,
                    confidence: 0.9,
                },
            },
            Event::DnsRecord {
                name: "a".into(),
                record_type: "A".into(),
                value: "127.0.0.1".into(),
            },
            Event::TlsCert {
                addr: ip,
                port: 443,
                subject: "s".into(),
                issuer: "i".into(),
                not_after: "n".into(),
            },
            Event::SessionOpened {
                session_id: id,
                addr: ip,
                port: 6379,
                protocol: "redis".into(),
            },
            Event::SessionClosed { session_id: id },
            Event::ProbeResult {
                addr: ip,
                port: 80,
                probe: "http".into(),
                detail: "d".into(),
                confidence: 0.5,
            },
            Event::MisconfigFinding {
                addr: ip,
                port: Some(80),
                finding: "f".into(),
                severity: "high".into(),
            },
            Event::OsGuess {
                addr: ip,
                os: "linux".into(),
                confidence: 0.4,
                observed_ttl: Some(64),
            },
            Event::AsnInfo {
                addr: ip,
                asn: "AS1".into(),
                org: "org".into(),
            },
            Event::PathHop {
                target: ip,
                hop: 1,
                addr: Some(ip),
                rtt_ms: Some(1),
                label: "l".into(),
            },
            Event::Stats {
                pps: 1.0,
                open: 1,
                closed: 0,
                filtered: 0,
                elapsed_ms: 10,
            },
            Event::Log {
                level: "info".into(),
                message: "m".into(),
            },
        ]
    }

    #[test]
    fn kind_matches_serde_tag() {
        for ev in sample_events() {
            let json = serde_json::to_value(&ev).expect("serialize");
            let tag = json
                .get("type")
                .and_then(|t| t.as_str())
                .expect("tagged with type");
            assert_eq!(tag, ev.kind(), "kind() must equal serde tag for {ev:?}");
        }
    }

    #[test]
    fn kinds_list_is_complete_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for ev in sample_events() {
            assert!(
                Event::KINDS.contains(&ev.kind()),
                "KINDS missing {}",
                ev.kind()
            );
            assert!(seen.insert(ev.kind()), "duplicate kind {}", ev.kind());
        }
        // Every declared sample maps to a distinct kind, and the constant list
        // has no extras beyond what the enum produces.
        assert_eq!(seen.len(), Event::KINDS.len(), "KINDS length drift");
    }

    #[test]
    fn round_trips_through_json() {
        for ev in sample_events() {
            let s = serde_json::to_string(&ev).expect("serialize");
            let back: Event = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(back.kind(), ev.kind());
        }
    }
}
