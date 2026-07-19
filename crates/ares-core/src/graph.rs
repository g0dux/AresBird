use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

use crate::event::Event;
use crate::model::{Host, HostFinding, PathHopRecord, Port, PortState, ServiceInfo, Session};

/// Living asset/session graph — the source of truth for the fabric.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AssetGraph {
    pub hosts: HashMap<IpAddr, Host>,
    pub sessions: HashMap<Uuid, Session>,
    pub dns: HashMap<String, Vec<String>>,
    /// Traceroute-style hops keyed by destination.
    #[serde(default)]
    pub paths: HashMap<IpAddr, Vec<PathHopRecord>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Lightweight export of names, hosts, and edges for reports / Mermaid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphExport {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub kind: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub label: String,
}

impl AssetGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, event: &Event) {
        self.updated_at = Some(Utc::now());
        match event {
            Event::HostUp {
                addr,
                latency_ms,
                method,
            } => {
                let host = self.hosts.entry(*addr).or_insert_with(|| Host::new(*addr));
                host.up = true;
                host.latency_ms = *latency_ms;
                host.discovery_method = Some(method.clone());
            }
            Event::HostDown { addr } => {
                let host = self.hosts.entry(*addr).or_insert_with(|| Host::new(*addr));
                host.up = false;
            }
            Event::PortResult {
                addr,
                port,
                state,
                protocol,
                rtt_ms,
            } => {
                let host = self.hosts.entry(*addr).or_insert_with(|| Host::new(*addr));
                if *state == PortState::Open {
                    host.up = true;
                }
                host.ports.insert(
                    *port,
                    Port {
                        port: *port,
                        protocol: protocol.clone(),
                        state: state.clone(),
                        rtt_ms: *rtt_ms,
                        service: None,
                        banner: None,
                    },
                );
            }
            Event::Banner { addr, port, banner } => {
                let host = self.hosts.entry(*addr).or_insert_with(|| Host::new(*addr));
                host.up = true;
                let p = host.ports.entry(*port).or_insert_with(|| Port {
                    port: *port,
                    protocol: "tcp".into(),
                    state: PortState::Open,
                    rtt_ms: None,
                    service: None,
                    banner: None,
                });
                p.banner = Some(banner.clone());
            }
            Event::ServiceDetected {
                addr,
                port,
                service,
            } => {
                let host = self.hosts.entry(*addr).or_insert_with(|| Host::new(*addr));
                host.up = true;
                let p = host.ports.entry(*port).or_insert_with(|| Port {
                    port: *port,
                    protocol: "tcp".into(),
                    state: PortState::Open,
                    rtt_ms: None,
                    service: None,
                    banner: None,
                });
                p.service = Some(service.clone());
            }
            Event::DnsRecord {
                name,
                record_type,
                value,
            } => {
                self.dns
                    .entry(name.clone())
                    .or_default()
                    .push(value.clone());
                if record_type.eq_ignore_ascii_case("PTR") {
                    if let Some(addr) = parse_inaddr_arpa(name) {
                        let host = self.hosts.entry(addr).or_insert_with(|| Host::new(addr));
                        host.ptr = Some(value.clone());
                        if host.hostname.is_none() {
                            host.hostname = Some(value.clone());
                        }
                    }
                } else if record_type.eq_ignore_ascii_case("A")
                    || record_type.eq_ignore_ascii_case("AAAA")
                {
                    if let Ok(addr) = value.parse::<IpAddr>() {
                        let host = self.hosts.entry(addr).or_insert_with(|| Host::new(addr));
                        let clean = name.trim_end_matches('.').to_string();
                        if host.hostname.is_none() {
                            host.hostname = Some(clean);
                        }
                    }
                }
            }
            Event::ProbeResult {
                addr,
                port,
                probe,
                detail,
                ..
            } => {
                let host = self.hosts.entry(*addr).or_insert_with(|| Host::new(*addr));
                host.up = true;
                match probe.as_str() {
                    "cdn-detect" => {
                        let cdn = detail
                            .split('(')
                            .next()
                            .unwrap_or(detail)
                            .trim()
                            .to_string();
                        host.cdn = Some(cdn);
                    }
                    "http-title" => {
                        host.http_title = Some(detail.clone());
                        ensure_open_port(host, *port, "tcp");
                    }
                    "http-get" | "https-get" | "h2-cleartext" => {
                        ensure_open_port(host, *port, "tcp");
                    }
                    "http-redirect" | "http-redirect-chain" => {
                        ensure_open_port(host, *port, "tcp");
                    }
                    "h2-alpn" => {
                        ensure_open_port(host, *port, "tcp");
                        if let Some(alpn) = detail.strip_prefix("ALPN negotiated: ") {
                            host.alpn = Some(alpn.to_string());
                        }
                    }
                    "tls-alpn" => {
                        if let Some(alpn) = detail.strip_prefix("ALPN=") {
                            host.alpn = Some(alpn.to_string());
                        }
                        ensure_open_port(host, *port, "tcp");
                    }
                    "tls-fp" => {
                        if let Some(fp) = detail.strip_prefix("sha256=") {
                            host.tls_fp = Some(fp.to_string());
                        }
                        ensure_open_port(host, *port, "tcp");
                    }
                    "tls-cert" => {
                        // new: subj=... fp=...  | legacy: subj≈... fp=...
                        if let Some(fp) = detail.split(" fp=").nth(1) {
                            host.tls_fp = Some(fp.to_string());
                        }
                        if let Some(rest) = detail.strip_prefix("subj=") {
                            if let Some(subj) = rest.split(" issuer=").next() {
                                host.tls_subject = Some(subj.to_string());
                            }
                        } else if let Some(rest) = detail.strip_prefix("subj≈") {
                            if let Some((subj, _)) = rest.split_once(" fp=") {
                                host.tls_subject = Some(subj.to_string());
                            }
                        }
                        ensure_open_port(host, *port, "tcp");
                    }
                    "tls-version" | "tls-versions" | "tls-cipher" | "tls-sni" | "tls-handshake" => {
                        ensure_open_port(host, *port, "tcp");
                    }
                    _ => {}
                }
            }
            Event::TlsCert {
                addr,
                port,
                subject,
                issuer,
                ..
            } => {
                let host = self.hosts.entry(*addr).or_insert_with(|| Host::new(*addr));
                host.up = true;
                host.tls_subject = Some(subject.clone());
                if let Some(fp) = issuer.strip_prefix("sha256:") {
                    host.tls_fp = Some(fp.to_string());
                }
                ensure_open_port(host, *port, "tcp");
            }
            Event::SessionOpened {
                session_id,
                addr,
                port,
                protocol,
            } => {
                self.sessions.insert(
                    *session_id,
                    Session {
                        id: *session_id,
                        addr: *addr,
                        port: *port,
                        protocol: protocol.clone(),
                        opened_at: Utc::now(),
                        closed: false,
                        note: None,
                        transcript: Vec::new(),
                    },
                );
            }
            Event::SessionClosed { session_id } => {
                if let Some(s) = self.sessions.get_mut(session_id) {
                    s.closed = true;
                }
            }
            Event::OsGuess {
                addr,
                os,
                confidence,
                observed_ttl,
            } => {
                let host = self.hosts.entry(*addr).or_insert_with(|| Host::new(*addr));
                if let Some(ttl) = observed_ttl {
                    // Keep first strong TTL; prefer higher when both set.
                    host.observed_ttl = Some(match host.observed_ttl {
                        Some(prev) => (*ttl).max(prev),
                        None => *ttl,
                    });
                }
                let better = host.os_confidence.map(|c| *confidence > c).unwrap_or(true);
                if better {
                    host.os_guess = Some(os.clone());
                    host.os_confidence = Some(*confidence);
                }
            }
            Event::AsnInfo { addr, asn, org } => {
                let host = self.hosts.entry(*addr).or_insert_with(|| Host::new(*addr));
                host.asn = Some(asn.clone());
                host.asn_org = Some(org.clone());
            }
            Event::MisconfigFinding {
                addr,
                port,
                finding,
                severity,
            } => {
                let host = self.hosts.entry(*addr).or_insert_with(|| Host::new(*addr));
                host.up = true;
                if let Some(p) = port {
                    ensure_open_port(host, *p, "tcp");
                }
                let entry = HostFinding {
                    port: *port,
                    severity: severity.clone(),
                    finding: finding.clone(),
                };
                if !host.findings.iter().any(|f| f == &entry) {
                    host.findings.push(entry);
                }
            }
            Event::PathHop {
                target,
                hop,
                addr,
                rtt_ms,
                label,
            } => {
                let hops = self.paths.entry(*target).or_default();
                let rec = PathHopRecord {
                    hop: *hop,
                    addr: *addr,
                    rtt_ms: *rtt_ms,
                    label: label.clone(),
                };
                if let Some(existing) = hops.iter_mut().find(|h| h.hop == *hop) {
                    *existing = rec;
                } else {
                    hops.push(rec);
                    hops.sort_by_key(|h| h.hop);
                }
                // Also ensure hop routers exist as hosts when known.
                if let Some(hop_addr) = addr {
                    let _ = self
                        .hosts
                        .entry(*hop_addr)
                        .or_insert_with(|| Host::new(*hop_addr));
                }
                let _ = self
                    .hosts
                    .entry(*target)
                    .or_insert_with(|| Host::new(*target));
            }
            _ => {}
        }
    }

    pub fn apply_all(&mut self, events: &[Event]) {
        for e in events {
            self.apply(e);
        }
    }

    /// Merge another graph into this one (workspace cognition).
    /// Open beats filtered/closed; richer service/banner/OS wins; findings unioned.
    pub fn merge_from(&mut self, other: &AssetGraph) {
        self.updated_at = Some(Utc::now());
        for (addr, oh) in &other.hosts {
            let host = self.hosts.entry(*addr).or_insert_with(|| Host::new(*addr));
            host.up = host.up || oh.up;
            if host.hostname.is_none() {
                host.hostname = oh.hostname.clone();
            }
            if oh.latency_ms.is_some()
                && (host.latency_ms.is_none() || oh.latency_ms < host.latency_ms)
            {
                host.latency_ms = oh.latency_ms;
            }
            if host.discovery_method.is_none() {
                host.discovery_method = oh.discovery_method.clone();
            }
            merge_opt_str(&mut host.asn, &oh.asn);
            merge_opt_str(&mut host.asn_org, &oh.asn_org);
            merge_opt_str(&mut host.cdn, &oh.cdn);
            merge_opt_str(&mut host.ptr, &oh.ptr);
            merge_opt_str(&mut host.http_title, &oh.http_title);
            merge_opt_str(&mut host.tls_subject, &oh.tls_subject);
            merge_opt_str(&mut host.tls_fp, &oh.tls_fp);
            merge_opt_str(&mut host.alpn, &oh.alpn);
            if let Some(ttl) = oh.observed_ttl {
                host.observed_ttl = Some(match host.observed_ttl {
                    Some(prev) => prev.max(ttl),
                    None => ttl,
                });
            }
            let better_os = oh
                .os_confidence
                .map(|c| host.os_confidence.map(|p| c > p).unwrap_or(true))
                .unwrap_or(false);
            if better_os {
                host.os_guess = oh.os_guess.clone();
                host.os_confidence = oh.os_confidence;
            }
            for (port, op) in &oh.ports {
                match host.ports.get_mut(port) {
                    Some(ep) => merge_port(ep, op),
                    None => {
                        host.ports.insert(*port, op.clone());
                    }
                }
            }
            for f in &oh.findings {
                if !host.findings.iter().any(|x| x == f) {
                    host.findings.push(f.clone());
                }
            }
        }
        for (name, addrs) in &other.dns {
            let entry = self.dns.entry(name.clone()).or_default();
            for a in addrs {
                if !entry.contains(a) {
                    entry.push(a.clone());
                }
            }
        }
        for (dest, hops) in &other.paths {
            let entry = self.paths.entry(*dest).or_default();
            for h in hops {
                if let Some(existing) = entry.iter_mut().find(|x| x.hop == h.hop) {
                    if h.addr.is_some() || existing.addr.is_none() {
                        *existing = h.clone();
                    }
                } else {
                    entry.push(h.clone());
                }
            }
            entry.sort_by_key(|h| h.hop);
        }
        for (id, os) in &other.sessions {
            match self.sessions.get_mut(id) {
                Some(es) => {
                    if os.closed {
                        es.closed = true;
                    }
                    if es.note.is_none() {
                        es.note = os.note.clone();
                    }
                    if os.transcript.len() > es.transcript.len() {
                        es.transcript = os.transcript.clone();
                    }
                }
                None => {
                    self.sessions.insert(*id, os.clone());
                }
            }
        }
    }

    pub fn open_services(&self) -> Vec<(IpAddr, u16, Option<ServiceInfo>)> {
        let mut out = Vec::new();
        for (addr, host) in &self.hosts {
            for (port, p) in &host.ports {
                if p.state == PortState::Open {
                    out.push((*addr, *port, p.service.clone()));
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        out
    }

    /// Total misconfig findings attached to hosts.
    pub fn finding_count(&self) -> usize {
        self.hosts.values().map(|h| h.findings.len()).sum()
    }

    /// Build a node/edge view: DNS→IP, IP→open port, path hops.
    pub fn export_relations(&self) -> GraphExport {
        let mut nodes: HashMap<String, GraphNode> = HashMap::new();
        let mut edges = Vec::new();

        let push_node =
            |nodes: &mut HashMap<String, GraphNode>, id: String, kind: &str, label: String| {
                nodes.entry(id.clone()).or_insert(GraphNode {
                    id,
                    kind: kind.into(),
                    label,
                });
            };

        for (addr, host) in &self.hosts {
            let id = host_node_id(*addr);
            let label = match &host.hostname {
                Some(h) => format!("{h}\n{addr}"),
                None => addr.to_string(),
            };
            push_node(&mut nodes, id.clone(), "host", label);
            for (port, p) in &host.ports {
                if p.state != PortState::Open {
                    continue;
                }
                let pid = port_node_id(*addr, *port);
                let svc = p
                    .service
                    .as_ref()
                    .map(|s| s.name.as_str())
                    .unwrap_or("open");
                push_node(&mut nodes, pid.clone(), "port", format!("{port}/{svc}"));
                edges.push(GraphEdge {
                    from: id.clone(),
                    to: pid,
                    kind: "exposes".into(),
                    label: p.protocol.clone(),
                });
            }
            if !host.findings.is_empty() {
                let fid = format!("find_{}", sanitize_id(&addr.to_string()));
                push_node(
                    &mut nodes,
                    fid.clone(),
                    "findings",
                    format!("{} finding(s)", host.findings.len()),
                );
                edges.push(GraphEdge {
                    from: id,
                    to: fid,
                    kind: "has_finding".into(),
                    label: host.findings.len().to_string(),
                });
            }
        }

        for (name, values) in &self.dns {
            let nid = dns_node_id(name);
            push_node(&mut nodes, nid.clone(), "dns", name.clone());
            for v in values {
                if let Ok(addr) = v.parse::<IpAddr>() {
                    let hid = host_node_id(addr);
                    push_node(
                        &mut nodes,
                        hid.clone(),
                        "host",
                        self.hosts
                            .get(&addr)
                            .and_then(|h| h.hostname.clone())
                            .map(|h| format!("{h}\n{addr}"))
                            .unwrap_or_else(|| addr.to_string()),
                    );
                    edges.push(GraphEdge {
                        from: nid.clone(),
                        to: hid,
                        kind: "resolves".into(),
                        label: "A/AAAA".into(),
                    });
                } else {
                    // CNAME / MX / TXT → string node
                    let cid = format!("val_{}", sanitize_id(v));
                    push_node(&mut nodes, cid.clone(), "dns_value", v.clone());
                    edges.push(GraphEdge {
                        from: nid.clone(),
                        to: cid,
                        kind: "dns".into(),
                        label: String::new(),
                    });
                }
            }
        }

        for (target, hops) in &self.paths {
            let tid = host_node_id(*target);
            push_node(&mut nodes, tid.clone(), "host", target.to_string());
            let mut prev = None::<String>;
            for h in hops {
                let cur = match h.addr {
                    Some(a) => {
                        let id = host_node_id(a);
                        push_node(&mut nodes, id.clone(), "host", a.to_string());
                        id
                    }
                    None => {
                        let id = format!("hop_{}_{}", sanitize_id(&target.to_string()), h.hop);
                        push_node(&mut nodes, id.clone(), "hop", format!("* ({})", h.label));
                        id
                    }
                };
                if let Some(p) = prev {
                    edges.push(GraphEdge {
                        from: p,
                        to: cur.clone(),
                        kind: "path".into(),
                        label: format!("hop {}", h.hop),
                    });
                }
                prev = Some(cur);
            }
            if let Some(last) = prev {
                if last != tid {
                    edges.push(GraphEdge {
                        from: last,
                        to: tid,
                        kind: "path".into(),
                        label: "dst".into(),
                    });
                }
            }
        }

        let mut nodes: Vec<_> = nodes.into_values().collect();
        nodes.sort_by(|a, b| a.id.cmp(&b.id));
        edges.sort_by(|a, b| a.from.cmp(&b.from).then(a.to.cmp(&b.to)));
        GraphExport { nodes, edges }
    }

    /// Mermaid flowchart for tickets / Notion / GitHub.
    pub fn to_mermaid(&self) -> String {
        let exp = self.export_relations();
        let mut out = String::from("flowchart LR\n");
        for n in &exp.nodes {
            let label = n.label.replace('"', "'").replace('\n', "<br/>");
            out.push_str(&format!("  {}[\"{}\"]\n", n.id, label));
        }
        for e in &exp.edges {
            if e.label.is_empty() {
                out.push_str(&format!("  {} --> {}\n", e.from, e.to));
            } else {
                let lab = e.label.replace('"', "'");
                out.push_str(&format!("  {} -->|\"{}\"| {}\n", e.from, lab, e.to));
            }
        }
        out
    }
}

fn merge_opt_str(dst: &mut Option<String>, src: &Option<String>) {
    if dst.is_none() {
        *dst = src.clone();
    }
}

fn port_state_rank(s: &PortState) -> u8 {
    match s {
        PortState::Open => 5,
        PortState::OpenFiltered => 4,
        PortState::Filtered => 3,
        PortState::Closed => 2,
        PortState::Unknown => 1,
    }
}

fn merge_port(dst: &mut Port, src: &Port) {
    if port_state_rank(&src.state) > port_state_rank(&dst.state) {
        dst.state = src.state.clone();
    }
    if dst.rtt_ms.is_none() {
        dst.rtt_ms = src.rtt_ms;
    }
    if dst.banner.is_none()
        || src.banner.as_ref().map(|b| b.len()).unwrap_or(0)
            > dst.banner.as_ref().map(|b| b.len()).unwrap_or(0)
    {
        if src.banner.is_some() {
            dst.banner = src.banner.clone();
        }
    }
    match (&dst.service, &src.service) {
        (None, Some(s)) => dst.service = Some(s.clone()),
        (Some(a), Some(b)) if b.confidence > a.confidence => dst.service = Some(b.clone()),
        _ => {}
    }
}

fn host_node_id(addr: IpAddr) -> String {
    format!("host_{}", sanitize_id(&addr.to_string()))
}

fn port_node_id(addr: IpAddr, port: u16) -> String {
    format!("port_{}_{}", sanitize_id(&addr.to_string()), port)
}

fn dns_node_id(name: &str) -> String {
    format!("dns_{}", sanitize_id(name))
}

fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn ensure_open_port(host: &mut Host, port: u16, protocol: &str) {
    if port == 0 {
        return;
    }
    let p = host.ports.entry(port).or_insert_with(|| Port {
        port,
        protocol: protocol.into(),
        state: PortState::Open,
        rtt_ms: None,
        service: None,
        banner: None,
    });
    p.state = PortState::Open;
}

/// Parse `d.c.b.a.in-addr.arpa` (optional trailing '.') into IPv4.
fn parse_inaddr_arpa(name: &str) -> Option<IpAddr> {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let stripped = n.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<&str> = stripped.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a: u8 = parts[3].parse().ok()?;
    let b: u8 = parts[2].parse().ok()?;
    let c: u8 = parts[1].parse().ok()?;
    let d: u8 = parts[0].parse().ok()?;
    Some(IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn findings_and_dns_link_into_export() {
        let mut g = AssetGraph::new();
        let addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        g.apply(&Event::DnsRecord {
            name: "app.example".into(),
            record_type: "A".into(),
            value: "1.2.3.4".into(),
        });
        g.apply(&Event::PortResult {
            addr,
            port: 80,
            state: PortState::Open,
            protocol: "tcp".into(),
            rtt_ms: Some(1),
        });
        g.apply(&Event::MisconfigFinding {
            addr,
            port: Some(80),
            finding: "open redis".into(),
            severity: "high".into(),
        });
        assert_eq!(g.hosts[&addr].hostname.as_deref(), Some("app.example"));
        assert_eq!(g.finding_count(), 1);
        let exp = g.export_relations();
        assert!(exp.edges.iter().any(|e| e.kind == "resolves"));
        assert!(exp.edges.iter().any(|e| e.kind == "exposes"));
        assert!(exp.edges.iter().any(|e| e.kind == "has_finding"));
        let md = g.to_mermaid();
        assert!(md.contains("flowchart LR"));
        assert!(md.contains("app.example"));
    }

    #[test]
    fn merge_from_prefers_open_and_unions_findings() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut base = AssetGraph::new();
        base.apply(&Event::PortResult {
            addr,
            port: 80,
            state: PortState::Filtered,
            protocol: "tcp".into(),
            rtt_ms: None,
        });
        let mut other = AssetGraph::new();
        other.apply(&Event::PortResult {
            addr,
            port: 80,
            state: PortState::Open,
            protocol: "tcp".into(),
            rtt_ms: Some(2),
        });
        other.apply(&Event::MisconfigFinding {
            addr,
            port: Some(80),
            finding: "missing hsts".into(),
            severity: "medium".into(),
        });
        base.merge_from(&other);
        assert_eq!(base.hosts[&addr].ports[&80].state, PortState::Open);
        assert_eq!(base.finding_count(), 1);
    }
}
