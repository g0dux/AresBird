//! Aggregate finding metrics by taxonomy category / CWE / severity / rule.

use std::collections::BTreeMap;

use ares_core::EventCollector;
use serde::Serialize;

use crate::diff::severity_rank;
use crate::taxonomy::classify;

#[derive(Debug, Clone, Serialize, Default)]
pub struct MetricsReport {
    pub total: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub by_category: BTreeMap<String, usize>,
    pub by_cwe: BTreeMap<String, usize>,
    pub by_rule: BTreeMap<String, usize>,
    pub top_rules: Vec<RuleCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleCount {
    pub rule_id: String,
    pub count: usize,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
}

/// Build a metrics summary from collapsed findings (severity >= `min_rank`).
pub fn findings_metrics(collector: &EventCollector, min_rank: u8) -> MetricsReport {
    let mut report = MetricsReport::default();
    let mut rule_meta: BTreeMap<String, (String, Option<String>)> = BTreeMap::new();

    for (_addr, _port, severity, finding, _peers) in collector.findings_collapsed() {
        if severity_rank(&severity) < min_rank {
            continue;
        }
        report.total += 1;
        *report.by_severity.entry(severity).or_insert(0) += 1;
        let class = classify(&finding);
        *report
            .by_category
            .entry(class.category.to_string())
            .or_insert(0) += 1;
        *report.by_rule.entry(class.id.to_string()).or_insert(0) += 1;
        rule_meta
            .entry(class.id.to_string())
            .or_insert_with(|| (class.category.to_string(), class.cwe.map(|s| s.to_string())));
        if let Some(cwe) = class.cwe {
            *report.by_cwe.entry(cwe.to_string()).or_insert(0) += 1;
        }
    }

    let mut top: Vec<RuleCount> = report
        .by_rule
        .iter()
        .map(|(id, &count)| {
            let (category, cwe) = rule_meta
                .get(id)
                .cloned()
                .unwrap_or_else(|| ("other".into(), None));
            RuleCount {
                rule_id: id.clone(),
                count,
                category,
                cwe,
            }
        })
        .collect();
    top.sort_by(|a, b| b.count.cmp(&a.count).then(a.rule_id.cmp(&b.rule_id)));
    report.top_rules = top;
    report
}

/// Human-readable table for CLI.
pub fn format_metrics_table(m: &MetricsReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("Findings total: {}\n", m.total));
    if !m.by_severity.is_empty() {
        out.push_str("\nBy severity:\n");
        // Prefer high → info order when present.
        for key in ["high", "medium", "low", "info"] {
            if let Some(v) = m.by_severity.get(key) {
                out.push_str(&format!("  {key:<8} {v}\n"));
            }
        }
        for (k, v) in &m.by_severity {
            if !matches!(k.as_str(), "high" | "medium" | "low" | "info") {
                out.push_str(&format!("  {k:<8} {v}\n"));
            }
        }
    }
    if !m.by_category.is_empty() {
        out.push_str("\nBy category:\n");
        for (k, v) in &m.by_category {
            out.push_str(&format!("  {k:<12} {v}\n"));
        }
    }
    if !m.by_cwe.is_empty() {
        out.push_str("\nBy CWE:\n");
        for (k, v) in &m.by_cwe {
            out.push_str(&format!("  {k:<12} {v}\n"));
        }
    }
    if !m.top_rules.is_empty() {
        out.push_str("\nTop rules:\n");
        for r in m.top_rules.iter().take(15) {
            let cwe = r.cwe.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "  {:>4}  {:<28}  {:<10}  {}\n",
                r.count, r.rule_id, r.category, cwe
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::event::Event;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn aggregates_by_category_and_cwe() {
        let mut c = EventCollector::new();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for (port, sev, msg) in [
            (6379, "high", "Redis responds without AUTH (PONG)"),
            (
                443,
                "medium",
                "Missing security header: strict-transport-security",
            ),
            (80, "info", "HTTP cleartext service"),
        ] {
            c.push(Event::MisconfigFinding {
                addr: ip,
                port: Some(port),
                finding: msg.into(),
                severity: sev.into(),
            });
        }
        let m = findings_metrics(&c, 0);
        assert_eq!(m.total, 3);
        assert_eq!(m.by_category.get("exposure"), Some(&1));
        assert_eq!(m.by_category.get("web"), Some(&2));
        assert!(m.by_cwe.contains_key("CWE-306"));
        assert!(m.by_cwe.contains_key("CWE-319"));
        assert!(!m.top_rules.is_empty());
        assert!(!m.top_rules[0].rule_id.is_empty());
    }
}
