//! Smart output: tables, JSON, NDJSON, diff, SQLite persistence.

pub mod diff;
pub mod narrative;
pub mod render;
pub mod store;

pub use diff::{
    diff_collectors, diff_findings, filter_diff_by_severity, filter_findings_collapsed,
    findings_diff_to_csv, findings_diff_to_csv_filtered, meets_min_severity, parse_min_severity,
    severity_rank, DiffReport, FindingsDiffReport,
};
pub use narrative::{
    evidence_chain, format_why, suggest_talk_handoffs, NarrativeStep, TalkHandoff,
};
pub use render::{findings_to_csv, findings_to_csv_min, render_markdown, OutputFormat, Renderer};
pub use store::{RunMeta, RunStats, RunStore};
