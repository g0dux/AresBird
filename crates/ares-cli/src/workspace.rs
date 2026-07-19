//! Living workspace graph merge helpers.

use ares_core::{AssetGraph, EventCollector};
use ares_output::RunStore;

/// Resolve workspace id: CLI flag → `ARES_WORKSPACE` → `default`.
pub fn resolve_workspace_id(cli: Option<&str>) -> String {
    if let Some(s) = cli.map(str::trim).filter(|s| !s.is_empty()) {
        return s.to_string();
    }
    std::env::var("ARES_WORKSPACE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".into())
}

/// Load prior workspace, merge `graph`, upsert. Returns host count in merged graph.
pub fn merge_and_save(
    workspace_id: &str,
    collector: &EventCollector,
    graph: &AssetGraph,
    quiet: bool,
) -> anyhow::Result<()> {
    let store = RunStore::open_default()?;
    let mut merged = store.load_workspace(workspace_id)?;
    merged.merge_from(graph);
    // Prefer accumulating events lightly: empty collector is fine for workspace row.
    let mut events = EventCollector::new();
    events.events.extend(collector.events.iter().cloned());
    let id = store.upsert_workspace(workspace_id, &events, &merged)?;
    if !quiet {
        eprintln!(
            "[workspace] merged → {workspace_id} ({} hosts, run {id})",
            merged.hosts.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_prefers_cli() {
        assert_eq!(resolve_workspace_id(Some("lab")), "lab");
        assert_eq!(resolve_workspace_id(Some("  lab  ")), "lab");
    }

    #[test]
    fn resolve_falls_back_default() {
        // Clear env for this test process slot — may race if parallel tests set ARES_WORKSPACE.
        let prev = std::env::var_os("ARES_WORKSPACE");
        std::env::remove_var("ARES_WORKSPACE");
        assert_eq!(resolve_workspace_id(None), "default");
        assert_eq!(resolve_workspace_id(Some("")), "default");
        match prev {
            Some(v) => std::env::set_var("ARES_WORKSPACE", v),
            None => std::env::remove_var("ARES_WORKSPACE"),
        }
    }
}
