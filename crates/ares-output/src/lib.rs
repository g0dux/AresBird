//! Smart output: tables, JSON, NDJSON, diff, SQLite persistence.

pub mod diff;
pub mod metrics;
pub mod narrative;
pub mod remediation;
pub mod render;
pub mod sarif;
pub mod store;
pub mod taxonomy;

pub use diff::{
    diff_collectors, diff_findings, filter_diff_by_severity, filter_findings_collapsed,
    findings_diff_to_csv, findings_diff_to_csv_filtered, meets_min_severity, parse_min_severity,
    severity_rank, DiffReport, FindingsDiffReport,
};
pub use metrics::{findings_metrics, format_metrics_table, MetricsReport, RuleCount};
pub use narrative::{
    evidence_chain, format_why, suggest_talk_handoffs, NarrativeStep, TalkHandoff,
};
pub use remediation::remediation_for;
pub use render::{
    enriched_findings, findings_to_csv, findings_to_csv_min, render_markdown, EnrichedFinding,
    OutputFormat, Renderer,
};
pub use sarif::{findings_to_sarif, findings_to_sarif_min};
pub use store::{RunMeta, RunStats, RunStore};
pub use taxonomy::{classify, FindingClass};
