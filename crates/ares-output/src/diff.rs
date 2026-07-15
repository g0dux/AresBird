use ares_core::event::{Event, EventCollector};
use ares_core::model::PortState;
use serde::Serialize;
use std::collections::BTreeSet;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize)]
pub struct DiffReport {
    pub added_open: Vec<(IpAddr, u16)>,
    pub removed_open: Vec<(IpAddr, u16)>,
    pub new_hosts: Vec<IpAddr>,
    pub gone_hosts: Vec<IpAddr>,
    pub new_findings: Vec<String>,
    pub gone_findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingDiffRow {
    pub severity: String,
    pub host: IpAddr,
    pub port: Option<u16>,
    pub finding: String,
    pub peers: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingsDiffReport {
    pub added: Vec<FindingDiffRow>,
    pub removed: Vec<FindingDiffRow>,
    pub unchanged: usize,
}

pub fn diff_collectors(a: &EventCollector, b: &EventCollector) -> DiffReport {
    let open_a: BTreeSet<(IpAddr, u16)> = a
        .events
        .iter()
        .filter_map(|e| match e {
            Event::PortResult {
                addr,
                port,
                state: PortState::Open,
                ..
            } => Some((*addr, *port)),
            _ => None,
        })
        .collect();
    let open_b: BTreeSet<(IpAddr, u16)> = b
        .events
        .iter()
        .filter_map(|e| match e {
            Event::PortResult {
                addr,
                port,
                state: PortState::Open,
                ..
            } => Some((*addr, *port)),
            _ => None,
        })
        .collect();

    let hosts_a: BTreeSet<IpAddr> = a.hosts_up().into_iter().collect();
    let hosts_b: BTreeSet<IpAddr> = b.hosts_up().into_iter().collect();

    let findings_a: BTreeSet<String> = finding_keys(a);
    let findings_b: BTreeSet<String> = finding_keys(b);

    DiffReport {
        added_open: open_b.difference(&open_a).copied().collect(),
        removed_open: open_a.difference(&open_b).copied().collect(),
        new_hosts: hosts_b.difference(&hosts_a).copied().collect(),
        gone_hosts: hosts_a.difference(&hosts_b).copied().collect(),
        new_findings: findings_b.difference(&findings_a).cloned().collect(),
        gone_findings: findings_a.difference(&findings_b).cloned().collect(),
    }
}

fn finding_keys(c: &EventCollector) -> BTreeSet<String> {
    c.findings_collapsed()
        .into_iter()
        .map(|(_addr, port, severity, finding, _peers)| {
            let p = port
                .map(|x| x.to_string())
                .unwrap_or_else(|| "-".into());
            format!("{severity}|{p}|{finding}")
        })
        .collect()
}

/// Rank for severity thresholds (`info` < `low` < `medium` < `high`).
pub fn severity_rank(s: &str) -> u8 {
    match s.to_ascii_lowercase().as_str() {
        "high" | "critical" => 4,
        "medium" | "med" | "warn" | "warning" => 3,
        "low" => 2,
        "info" | "informational" | "note" => 1,
        _ => 0,
    }
}

pub fn parse_min_severity(s: &str) -> anyhow::Result<u8> {
    let r = severity_rank(s);
    if r == 0 && !s.eq_ignore_ascii_case("none") && !s.is_empty() {
        anyhow::bail!("unknown severity '{s}' (use info|low|medium|high)");
    }
    Ok(r)
}

pub fn meets_min_severity(severity: &str, min_rank: u8) -> bool {
    severity_rank(severity) >= min_rank
}

pub fn filter_findings_collapsed(
    rows: Vec<(std::net::IpAddr, Option<u16>, String, String, usize)>,
    min_rank: u8,
) -> Vec<(std::net::IpAddr, Option<u16>, String, String, usize)> {
    rows.into_iter()
        .filter(|(_, _, sev, _, _)| meets_min_severity(sev, min_rank))
        .collect()
}

pub fn filter_diff_by_severity(mut diff: FindingsDiffReport, min_rank: u8) -> FindingsDiffReport {
    diff.added
        .retain(|r| meets_min_severity(&r.severity, min_rank));
    diff.removed
        .retain(|r| meets_min_severity(&r.severity, min_rank));
    // unchanged is approximate after filter — recompute from remaining impossible without keys;
    // leave as-is for display (full-run unchanged count) or zero when filtering heavily.
    if min_rank > 1 {
        diff.unchanged = 0;
    }
    diff
}

/// Diff collapsed findings between two runs (A = baseline, B = current).
pub fn diff_findings(a: &EventCollector, b: &EventCollector) -> FindingsDiffReport {
    let map_a: std::collections::BTreeMap<String, FindingDiffRow> = a
        .findings_collapsed()
        .into_iter()
        .map(|(host, port, severity, finding, peers)| {
            let key = format!(
                "{}|{}|{}",
                severity,
                port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                finding
            );
            (
                key,
                FindingDiffRow {
                    severity,
                    host,
                    port,
                    finding,
                    peers,
                },
            )
        })
        .collect();
    let map_b: std::collections::BTreeMap<String, FindingDiffRow> = b
        .findings_collapsed()
        .into_iter()
        .map(|(host, port, severity, finding, peers)| {
            let key = format!(
                "{}|{}|{}",
                severity,
                port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                finding
            );
            (
                key,
                FindingDiffRow {
                    severity,
                    host,
                    port,
                    finding,
                    peers,
                },
            )
        })
        .collect();

    let keys_a: BTreeSet<_> = map_a.keys().cloned().collect();
    let keys_b: BTreeSet<_> = map_b.keys().cloned().collect();
    let added: Vec<_> = keys_b
        .difference(&keys_a)
        .filter_map(|k| map_b.get(k).cloned())
        .collect();
    let removed: Vec<_> = keys_a
        .difference(&keys_b)
        .filter_map(|k| map_a.get(k).cloned())
        .collect();
    let unchanged = keys_a.intersection(&keys_b).count();

    FindingsDiffReport {
        added,
        removed,
        unchanged,
    }
}

/// CSV for findings diff (+/-/unchanged count in header comment is not RFC; use columns).
pub fn findings_diff_to_csv(diff: &FindingsDiffReport) -> String {
    findings_diff_to_csv_filtered(diff, false)
}

/// If `added_only`, omit removed rows (for --new-only export).
pub fn findings_diff_to_csv_filtered(diff: &FindingsDiffReport, added_only: bool) -> String {
    let mut out = String::from("change,severity,host,port,peers,finding\n");
    for row in &diff.added {
        out.push_str(&format!(
            "added,{},{},{},{},{}\n",
            csv_cell(&row.severity),
            csv_cell(&row.host.to_string()),
            csv_cell(
                &row.port
                    .map(|p| p.to_string())
                    .unwrap_or_default()
            ),
            row.peers,
            csv_cell(&row.finding),
        ));
    }
    if !added_only {
        for row in &diff.removed {
            out.push_str(&format!(
                "removed,{},{},{},{},{}\n",
                csv_cell(&row.severity),
                csv_cell(&row.host.to_string()),
                csv_cell(
                    &row.port
                        .map(|p| p.to_string())
                        .unwrap_or_default()
                ),
                row.peers,
                csv_cell(&row.finding),
            ));
        }
    }
    out
}

fn csv_cell(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
