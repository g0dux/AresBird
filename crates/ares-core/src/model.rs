use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    Unknown,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
            PortState::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra: Option<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub rtt_ms: Option<u64>,
    pub service: Option<ServiceInfo>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub addr: IpAddr,
    pub hostname: Option<String>,
    pub up: bool,
    pub latency_ms: Option<u64>,
    pub discovery_method: Option<String>,
    pub ports: BTreeMap<u16, Port>,
    pub os_guess: Option<String>,
    pub os_confidence: Option<f32>,
    pub asn: Option<String>,
    pub asn_org: Option<String>,
    #[serde(default)]
    pub cdn: Option<String>,
    #[serde(default)]
    pub ptr: Option<String>,
    #[serde(default)]
    pub http_title: Option<String>,
    #[serde(default)]
    pub tls_subject: Option<String>,
    #[serde(default)]
    pub tls_fp: Option<String>,
    #[serde(default)]
    pub alpn: Option<String>,
    /// Best-effort observed reply TTL (from SYN-raw / path), for OS correlation.
    #[serde(default)]
    pub observed_ttl: Option<u8>,
    /// Misconfig / exposure findings attached to this host.
    #[serde(default)]
    pub findings: Vec<HostFinding>,
}

/// Compact finding stored on a host in the asset graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostFinding {
    pub port: Option<u16>,
    pub severity: String,
    pub finding: String,
}

/// One hop of a traceroute-style path toward a target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathHopRecord {
    pub hop: u8,
    pub addr: Option<IpAddr>,
    pub rtt_ms: Option<u64>,
    pub label: String,
}

impl Host {
    pub fn new(addr: IpAddr) -> Self {
        Self {
            addr,
            hostname: None,
            up: false,
            latency_ms: None,
            discovery_method: None,
            ports: BTreeMap::new(),
            os_guess: None,
            os_confidence: None,
            asn: None,
            asn_org: None,
            cdn: None,
            ptr: None,
            http_title: None,
            tls_subject: None,
            tls_fp: None,
            alpn: None,
            observed_ttl: None,
            findings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub addr: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub opened_at: DateTime<Utc>,
    pub closed: bool,
    /// Optional note (e.g. cookie count / paths browsed).
    #[serde(default)]
    pub note: Option<String>,
    /// Ordered observe transcript lines (e.g. `GET / → 200`).
    #[serde(default)]
    pub transcript: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub detail: String,
    pub confidence: f32,
    pub collected_at: DateTime<Utc>,
}

/// A scan/interaction target specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSpec {
    pub raw: String,
}

impl TargetSpec {
    pub fn new(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }
}
