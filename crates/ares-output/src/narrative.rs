//! Finding narrative (why) and talk handoff suggestions.

use std::net::IpAddr;

use ares_core::event::{Event, EventCollector};
use ares_core::graph::AssetGraph;
use ares_core::model::PortState;

use crate::diff::{filter_findings_collapsed, severity_rank};

/// One precursor step explaining how a finding was reached.
#[derive(Debug, Clone)]
pub struct NarrativeStep {
    pub kind: String,
    pub detail: String,
}

/// Walk recent events for the same host(/port) before the finding.
pub fn evidence_chain(
    collector: &EventCollector,
    addr: IpAddr,
    port: Option<u16>,
    finding: &str,
    max_steps: usize,
) -> Vec<NarrativeStep> {
    let max_steps = max_steps.max(1);
    // Find the last matching MisconfigFinding index.
    let mut end = collector.events.len();
    for (i, e) in collector.events.iter().enumerate().rev() {
        if let Event::MisconfigFinding {
            addr: a,
            port: p,
            finding: f,
            ..
        } = e
        {
            if *a == addr && *p == port && f == finding {
                end = i;
                break;
            }
        }
    }

    let mut steps = Vec::new();
    for e in collector.events[..end].iter().rev() {
        if steps.len() >= max_steps {
            break;
        }
        let step = match e {
            Event::PortResult {
                addr: a,
                port: p,
                state,
                ..
            } if *a == addr && port.map(|x| x == *p).unwrap_or(true) => Some(NarrativeStep {
                kind: "port".into(),
                detail: format!("{p}/tcp → {state}"),
            }),
            Event::ServiceDetected {
                addr: a,
                port: p,
                service,
            } if *a == addr && port.map(|x| x == *p).unwrap_or(true) => Some(NarrativeStep {
                kind: "service".into(),
                detail: format!(
                    "{p} → {} ({:.0}%)",
                    service.name,
                    service.confidence * 100.0
                ),
            }),
            Event::Banner {
                addr: a,
                port: p,
                banner,
            } if *a == addr && port.map(|x| x == *p).unwrap_or(true) => Some(NarrativeStep {
                kind: "banner".into(),
                detail: banner.chars().take(60).collect(),
            }),
            Event::TlsCert {
                addr: a,
                port: p,
                subject,
                ..
            } if *a == addr && port.map(|x| x == *p).unwrap_or(true) => Some(NarrativeStep {
                kind: "tls".into(),
                detail: subject.chars().take(60).collect(),
            }),
            Event::ProbeResult {
                addr: a,
                port: p,
                probe,
                detail,
                ..
            } if *a == addr && port.map(|x| x == *p).unwrap_or(true) => Some(NarrativeStep {
                kind: "probe".into(),
                detail: format!("{probe}: {}", detail.chars().take(50).collect::<String>()),
            }),
            _ => None,
        };
        if let Some(s) = step {
            // Prefer unique kinds (keep first = most recent before finding)
            if !steps.iter().any(|x: &NarrativeStep| x.kind == s.kind) {
                steps.push(s);
            }
        }
    }
    steps.reverse(); // chronological
    steps
}

/// Format a short "why" line for table/terminal.
pub fn format_why(steps: &[NarrativeStep]) -> String {
    if steps.is_empty() {
        return String::new();
    }
    steps
        .iter()
        .map(|s| format!("{}={}", s.kind, s.detail))
        .collect::<Vec<_>>()
        .join(" → ")
}

#[derive(Debug, Clone)]
pub struct TalkHandoff {
    pub cmd: String,
    pub reason: String,
}

/// Suggest next `ares talk` commands from findings + open services.
pub fn suggest_talk_handoffs(
    collector: &EventCollector,
    graph: &AssetGraph,
    min_severity_rank: u8,
) -> Vec<TalkHandoff> {
    let findings =
        filter_findings_collapsed(collector.findings_collapsed(), min_severity_rank);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (addr, port, severity, finding, _) in &findings {
        if severity_rank(severity) < min_severity_rank {
            continue;
        }
        let host = addr.to_string();
        let p = port.unwrap_or(0);
        let lower = finding.to_ascii_lowercase();
        let svc = graph
            .hosts
            .get(addr)
            .and_then(|h| port.and_then(|pp| h.ports.get(&pp)))
            .and_then(|pr| pr.service.as_ref())
            .map(|s| s.name.to_ascii_lowercase());

        let suggestion = handoff_for(&host, p, &lower, svc.as_deref());
        if let Some(h) = suggestion {
            if seen.insert(h.cmd.clone()) {
                out.push(h);
            }
        }
    }

    // Also suggest from open known observe ports without findings (light).
    if out.is_empty() {
        for (addr, port, svc) in graph.open_services() {
            let host = addr.to_string();
            let name = svc.as_ref().map(|s| s.name.to_ascii_lowercase());
            if let Some(h) = handoff_for(&host, port, "", name.as_deref()) {
                if matches!(
                    name.as_deref(),
                    Some("http" | "https" | "redis" | "ssh" | "mongodb" | "jenkins")
                ) && seen.insert(h.cmd.clone())
                {
                    out.push(h);
                }
            }
            if out.len() >= 5 {
                break;
            }
        }
    }

    out.truncate(8);
    out
}

fn handoff_for(host: &str, port: u16, finding_l: &str, svc: Option<&str>) -> Option<TalkHandoff> {
    let proto = infer_proto(port, finding_l, svc)?;
    let (cmd, reason) = match proto.as_str() {
        "http" | "https" => {
            let scheme = if proto == "https" || port == 443 || port == 8443 {
                "https"
            } else {
                "http"
            };
            let p = if port == 0 {
                if scheme == "https" { 443 } else { 80 }
            } else {
                port
            };
            let why = finding_or_svc(finding_l, svc);
            (
                format!("ares talk {scheme}://{host}:{p}/ --session"),
                format!("HTTP surface ({why})"),
            )
        }
        "http-repl" => (
            format!("ares talk http://{host}:{port}/ --repl"),
            "interactive HTTP observe".into(),
        ),
        other => {
            let why = finding_or_svc(finding_l, svc);
            (
                format!("ares talk {host} --proto {other}"),
                format!("{other} observe ({why})"),
            )
        }
    };
    Some(TalkHandoff { cmd, reason })
}

fn finding_or_svc(finding_l: &str, svc: Option<&str>) -> String {
    if !finding_l.is_empty() {
        finding_l.chars().take(40).collect()
    } else {
        svc.unwrap_or("open").to_string()
    }
}

fn infer_proto(port: u16, finding_l: &str, svc: Option<&str>) -> Option<String> {
    let blob = format!("{} {}", finding_l, svc.unwrap_or(""));
    if blob.contains("redis") || port == 6379 {
        return Some("redis".into());
    }
    if blob.contains("mongo") || port == 27017 {
        return Some("mongodb".into());
    }
    if blob.contains("jenkins") || port == 8080 && blob.contains("jenkins") {
        return Some("jenkins".into());
    }
    if blob.contains("grafana") || port == 3000 {
        return Some("grafana".into());
    }
    if blob.contains("elastic") || port == 9200 {
        return Some("elasticsearch".into());
    }
    if blob.contains("docker") || port == 2375 {
        return Some("docker".into());
    }
    if blob.contains("etcd") || port == 2379 {
        return Some("etcd".into());
    }
    if blob.contains("consul") || port == 8500 {
        return Some("consul".into());
    }
    if blob.contains("ssh") || port == 22 {
        return Some("ssh".into());
    }
    if blob.contains("smb") || port == 445 {
        return Some("smb".into());
    }
    if blob.contains("mysql") || port == 3306 {
        return Some("mysql".into());
    }
    if blob.contains("postgres") || port == 5432 {
        return Some("postgres".into());
    }
    if matches!(port, 80 | 8080 | 8000 | 8888) || blob.contains("http") || blob.contains("header")
        || blob.contains("cors") || blob.contains("cookie") || blob.contains("path ")
    {
        return Some("http".into());
    }
    if matches!(port, 443 | 8443) || blob.contains("tls") || blob.contains("https") {
        return Some("https".into());
    }
    // Service name direct
    if let Some(s) = svc {
        if !s.is_empty() && s != "unknown" {
            return Some(s.to_string());
        }
    }
    let _ = PortState::Open; // keep import used if optimized away
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::model::{PortState, ServiceInfo};
    use std::net::Ipv4Addr;

    #[test]
    fn evidence_orders_port_then_probe() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut c = EventCollector::new();
        c.push(Event::PortResult {
            addr,
            port: 80,
            state: PortState::Open,
            protocol: "tcp".into(),
            rtt_ms: Some(1),
        });
        c.push(Event::ProbeResult {
            addr,
            port: 80,
            probe: "http-headers".into(),
            detail: "missing HSTS".into(),
            confidence: 0.9,
        });
        c.push(Event::MisconfigFinding {
            addr,
            port: Some(80),
            finding: "Missing Strict-Transport-Security".into(),
            severity: "medium".into(),
        });
        let chain = evidence_chain(
            &c,
            addr,
            Some(80),
            "Missing Strict-Transport-Security",
            4,
        );
        assert!(chain.iter().any(|s| s.kind == "port"));
        assert!(chain.iter().any(|s| s.kind == "probe"));
    }

    #[test]
    fn handoff_redis() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut c = EventCollector::new();
        c.push(Event::MisconfigFinding {
            addr,
            port: Some(6379),
            finding: "Redis without AUTH".into(),
            severity: "high".into(),
        });
        let mut g = AssetGraph::new();
        g.apply(&Event::PortResult {
            addr,
            port: 6379,
            state: PortState::Open,
            protocol: "tcp".into(),
            rtt_ms: None,
        });
        g.apply(&Event::ServiceDetected {
            addr,
            port: 6379,
            service: ServiceInfo {
                name: "redis".into(),
                product: None,
                version: None,
                extra: None,
                confidence: 0.9,
            },
        });
        let hs = suggest_talk_handoffs(&c, &g, 0);
        assert!(hs.iter().any(|h| h.cmd.contains("--proto redis")));
    }
}
