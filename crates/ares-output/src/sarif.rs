//! SARIF 2.1.0 export for findings — consumable by GitHub code scanning,
//! Azure DevOps, and other static-analysis result viewers.
//!
//! Findings are read from an [`EventCollector`] (collapsed across A/AAAA peers),
//! classified via [`crate::taxonomy`], and enriched with remediation help from
//! [`crate::remediation`]. The wire finding text is preserved verbatim in each
//! result message so SARIF stays consistent with CSV/Markdown exports.

use std::collections::BTreeMap;

use ares_core::EventCollector;
use serde::Serialize;

use crate::diff::severity_rank;
use crate::remediation::remediation_for;
use crate::taxonomy::{classify, FindingClass};

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFO_URI: &str = "https://github.com/g0dux/AresBird";

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: Tool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
struct Driver {
    name: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    version: &'static str,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
struct Rule {
    id: &'static str,
    name: &'static str,
    #[serde(rename = "shortDescription")]
    short_description: Text,
    #[serde(rename = "fullDescription")]
    full_description: Text,
    help: Text,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: RuleConfig,
    properties: RuleProps,
}

#[derive(Serialize)]
struct RuleConfig {
    level: &'static str,
}

#[derive(Serialize)]
struct RuleProps {
    #[serde(skip_serializing_if = "Option::is_none")]
    cwe: Option<&'static str>,
    tags: Vec<&'static str>,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: &'static str,
    level: &'static str,
    message: Text,
    locations: Vec<Location>,
    properties: ResultProps,
}

#[derive(Serialize)]
struct ResultProps {
    host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    severity: String,
    peers: usize,
}

#[derive(Serialize)]
struct Location {
    #[serde(rename = "logicalLocations")]
    logical_locations: Vec<LogicalLocation>,
}

#[derive(Serialize)]
struct LogicalLocation {
    #[serde(rename = "fullyQualifiedName")]
    fully_qualified_name: String,
    kind: &'static str,
}

#[derive(Serialize)]
struct Text {
    text: String,
}

fn text(s: impl Into<String>) -> Text {
    Text { text: s.into() }
}

/// SARIF severity level for a finding severity string.
fn level_for(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// Render all findings (severity >= `min_rank`) as a SARIF 2.1.0 document.
pub fn findings_to_sarif_min(collector: &EventCollector, min_rank: u8) -> String {
    let findings: Vec<(String, Option<u16>, String, String, usize)> = collector
        .findings_collapsed()
        .into_iter()
        .filter(|(_, _, sev, _, _)| severity_rank(sev) >= min_rank)
        .map(|(addr, port, sev, finding, peers)| (addr.to_string(), port, sev, finding, peers))
        .collect();

    // Collect the rules actually referenced, keyed by stable id (sorted output).
    let mut rules_by_id: BTreeMap<&'static str, FindingClass> = BTreeMap::new();
    let mut results = Vec::with_capacity(findings.len());

    for (host, port, severity, finding, peers) in &findings {
        let class = classify(finding);
        rules_by_id.entry(class.id).or_insert(class);

        let fqn = match port {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        results.push(SarifResult {
            rule_id: class.id,
            level: level_for(severity),
            message: text(finding.clone()),
            locations: vec![Location {
                logical_locations: vec![LogicalLocation {
                    fully_qualified_name: fqn,
                    kind: "resource",
                }],
            }],
            properties: ResultProps {
                host: host.clone(),
                port: *port,
                severity: severity.clone(),
                peers: *peers,
            },
        });
    }

    let rules = rules_by_id
        .into_values()
        .map(|class| {
            let help = remediation_for(class.title)
                .or_else(|| example_finding_help(class.id))
                .unwrap_or("Review exposure and restrict access to trusted networks.");
            Rule {
                id: class.id,
                name: class.title,
                short_description: text(class.title),
                full_description: text(class.title),
                help: text(help),
                default_configuration: RuleConfig {
                    level: default_level(class),
                },
                properties: RuleProps {
                    cwe: class.cwe,
                    tags: rule_tags(class),
                },
            }
        })
        .collect();

    let log = SarifLog {
        schema: SCHEMA,
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: Tool {
                driver: Driver {
                    name: "AresBird",
                    information_uri: INFO_URI,
                    version: env!("CARGO_PKG_VERSION"),
                    rules,
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&log).unwrap_or_else(|_| "{}".into())
}

/// SARIF for all findings regardless of severity.
pub fn findings_to_sarif(collector: &EventCollector) -> String {
    findings_to_sarif_min(collector, 0)
}

fn default_level(class: FindingClass) -> &'static str {
    match class.category {
        "exposure" | "tls" => "error",
        "web" => "warning",
        _ => "note",
    }
}

fn rule_tags(class: FindingClass) -> Vec<&'static str> {
    let mut tags = vec!["security", class.category];
    if class.cwe.is_some() {
        tags.push("external/cwe");
    }
    tags
}

/// Fallback help keyed on rule id when the title doesn't match a remediation hint.
fn example_finding_help(id: &str) -> Option<&'static str> {
    match id {
        "service-missing-auth" => {
            Some("Require authentication and restrict the listener to private networks.")
        }
        "service-exposed" | "service-network-exposed" => {
            Some("Restrict source IPs / security groups; expose only via VPN or jump host.")
        }
        "http-missing-security-header" => {
            Some("Add the missing header at the reverse proxy or app security middleware.")
        }
        "http-risky-method" => Some("Disable TRACE/TRACK; scope OPTIONS to CORS preflight needs."),
        "http-info-disclosure" => {
            Some("Strip Server/X-Powered-By/X-Runtime/X-Debug headers at the edge.")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::event::Event;
    use std::net::{IpAddr, Ipv4Addr};

    fn collector_with(findings: &[(u16, &str, &str)]) -> EventCollector {
        let mut c = EventCollector::new();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for (port, sev, msg) in findings {
            c.push(Event::MisconfigFinding {
                addr: ip,
                port: Some(*port),
                finding: (*msg).to_string(),
                severity: (*sev).to_string(),
            });
        }
        c
    }

    #[test]
    fn emits_valid_sarif_shape() {
        let c = collector_with(&[
            (6379, "high", "Redis responds without AUTH (PONG)"),
            (
                443,
                "medium",
                "Missing security header: strict-transport-security",
            ),
        ]);
        let sarif = findings_to_sarif(&c);
        let v: serde_json::Value = serde_json::from_str(&sarif).expect("valid json");

        assert_eq!(v["version"], "2.1.0");
        let run = &v["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "AresBird");
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        // High severity maps to SARIF error.
        assert!(results
            .iter()
            .any(|r| r["level"] == "error" && r["ruleId"] == "service-missing-auth"));
        // Rules are emitted for referenced ids and carry CWE properties.
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert!(rules
            .iter()
            .any(|r| r["id"] == "http-missing-hsts" && r["properties"]["cwe"] == "CWE-319"));
    }

    #[test]
    fn min_rank_filters_low_severity() {
        let c = collector_with(&[
            (80, "info", "HTTP cleartext service"),
            (6379, "high", "Redis responds without AUTH (PONG)"),
        ]);
        // min_rank for "medium" should drop the info finding.
        let sarif = findings_to_sarif_min(&c, crate::diff::severity_rank("medium"));
        let v: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["properties"]["severity"], "high");
    }
}
