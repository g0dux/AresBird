//! `ares probe` / `ares test` handlers (extracted from main).

use std::path::PathBuf;
use std::sync::Arc;

use ares_core::parse_ports;
use ares_core::timing::ScanMode;
use ares_output::{
    diff_findings, filter_diff_by_severity, filter_findings_collapsed,
    findings_diff_to_csv_filtered, parse_min_severity, OutputFormat, Renderer, RunStore,
};
use ares_plugin_api::PluginRegistry;
use ares_proto::post_json;

use crate::args::NotifyOn;
use crate::pipeline;
use crate::run_module_opts;
use crate::script_pack;
use crate::workspace;

#[allow(clippy::too_many_arguments)]
pub async fn probe(
    registry: &PluginRegistry,
    profile: String,
    targets: Vec<String>,
    fail_on_new: bool,
    min_severity: String,
    script_pack: Option<String>,
    mode: ScanMode,
    mut renderer: Renderer,
    format: OutputFormat,
    save: bool,
    quiet: bool,
    ephemeral: bool,
    workspace_id: &str,
) -> anyhow::Result<()> {
    if targets.is_empty() {
        anyhow::bail!("ares probe needs at least one target");
    }
    let save = save || fail_on_new;
    let min_rank = parse_min_severity(&min_severity)?;
    renderer = renderer.with_min_finding_rank(min_rank);
    let pipe = pipeline::probe_pipeline(&profile, targets)?;
    let name = pipe
        .name
        .clone()
        .unwrap_or_else(|| format!("probe-{profile}"));
    let baseline = if fail_on_new {
        let store = RunStore::open_default()?;
        store
            .latest_named(&name)?
            .or(store.latest_named("active-misconfig")?)
    } else {
        None
    };
    if !quiet {
        eprintln!("ares probe {profile} → {name}");
    }
    let (mut collector, mut graph) = pipeline::run_pipeline_owned(
        pipe, &name, mode, &renderer, registry, true, false, None, None,
    )
    .await?;
    if let Some(pack_id) = script_pack {
        let open: Vec<script_pack::OpenPort> = collector
            .open_ports()
            .into_iter()
            .map(|(addr, port, protocol)| script_pack::OpenPort {
                addr,
                port,
                protocol,
            })
            .collect();
        let graph_arc = Arc::new(parking_lot::Mutex::new(graph));
        let collector_arc = Arc::new(parking_lot::Mutex::new(collector));
        let cancel = tokio_util::sync::CancellationToken::new();
        let emit_graph = graph_arc.clone();
        let emit_collector = collector_arc.clone();
        let live = Arc::new(
            Renderer::new(renderer.format, renderer.color)
                .with_quiet(quiet)
                .with_min_finding_rank(min_rank),
        );
        let emit: Arc<dyn Fn(ares_core::Event) + Send + Sync> =
            Arc::new(move |event: ares_core::Event| {
                emit_graph.lock().apply(&event);
                emit_collector.lock().push(event.clone());
                live.print_event_live(&event);
            });
        let _ = script_pack::run_script_pack(&pack_id, &open, mode, quiet, emit, cancel).await?;
        collector = collector_arc.lock().clone();
        graph = graph_arc.lock().clone();
        renderer.render_summary(&collector, &graph);
    }
    if save {
        let store = RunStore::open_default()?;
        let id = store.save(&name, &collector, &graph)?;
        if !quiet {
            eprintln!("saved run {id}");
        } else {
            eprintln!("# saved {id}");
        }
    }
    if !ephemeral {
        workspace::merge_and_save(workspace_id, &collector, &graph, quiet)?;
    }
    if fail_on_new {
        if let Some(bid) = baseline {
            let new_count = print_findings_delta(bid, &collector, true, format, quiet, min_rank)?;
            if new_count > 0 {
                std::process::exit(2);
            }
        } else if !quiet {
            eprintln!("fail-on-new: no baseline yet (saved as first run)");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn test(
    registry: &PluginRegistry,
    targets: Vec<String>,
    ports: String,
    no_path_probes: bool,
    path_delay_ms: u64,
    path_profile: String,
    paths_file: Option<PathBuf>,
    baseline: Option<String>,
    compare: bool,
    new_only: bool,
    fail_on_new: bool,
    fail_on_any: bool,
    min_severity: String,
    notify: Option<String>,
    notify_on: NotifyOn,
    mode: ScanMode,
    mut renderer: Renderer,
    format: OutputFormat,
    save: bool,
    quiet: bool,
    ephemeral: bool,
    workspace_id: &str,
) -> anyhow::Result<()> {
    let port_list = parse_ports(&ports)?;
    let min_rank = parse_min_severity(&min_severity)?;
    renderer = renderer.with_min_finding_rank(min_rank);
    let mut extra = serde_json::Map::new();
    extra.insert(
        "path_probes".into(),
        serde_json::Value::Bool(!no_path_probes),
    );
    extra.insert(
        "path_delay_ms".into(),
        serde_json::Value::from(path_delay_ms),
    );
    extra.insert(
        "path_profile".into(),
        serde_json::Value::String(path_profile),
    );
    if let Some(pf) = paths_file {
        extra.insert(
            "paths_file".into(),
            serde_json::Value::String(pf.display().to_string()),
        );
    }

    // --fail-on-new implies compare when no explicit baseline.
    let compare = compare || (fail_on_new && baseline.is_none());

    // Resolve baseline BEFORE save so --compare hits the previous run.
    let baseline_id = if let Some(b) = baseline {
        Some(uuid::Uuid::parse_str(&b)?)
    } else if compare {
        let store = RunStore::open_default()?;
        store.latest_named("active-misconfig")?
    } else {
        None
    };

    if compare && baseline_id.is_none() && !quiet {
        eprintln!(
            "[!] --compare/--fail-on-new: no prior active-misconfig run (this run becomes baseline)"
        );
    }

    let suppress = (new_only || fail_on_new) && baseline_id.is_some();
    let (collector, _graph) = run_module_opts(
        registry,
        "active-misconfig",
        targets,
        port_list,
        mode,
        &renderer,
        true,
        save,
        extra,
        suppress,
        ephemeral,
        workspace_id,
    )
    .await?;

    let mut new_count = 0usize;
    if let Some(bid) = baseline_id {
        new_count = print_findings_delta(
            bid,
            &collector,
            new_only || fail_on_new,
            format,
            quiet,
            min_rank,
        )?;
    } else if (new_only || fail_on_new) && !quiet {
        eprintln!("[!] --new-only/--fail-on-new ignored without a baseline run yet");
    }

    let current_ge = filter_findings_collapsed(collector.findings_collapsed(), min_rank);
    let any_count = current_ge.len();

    if let Some(url) = notify.as_deref() {
        let fire = match notify_on {
            NotifyOn::Always => true,
            NotifyOn::Any => any_count > 0,
            NotifyOn::New => {
                if baseline_id.is_some() {
                    new_count > 0
                } else {
                    any_count > 0
                }
            }
        };
        if fire {
            let findings_json: Vec<serde_json::Value> =
                if let (Some(bid), NotifyOn::New) = (baseline_id.as_ref(), &notify_on) {
                    // Prefer delta keys already printed; rebuild from current - baseline.
                    let store = RunStore::open_default()?;
                    let (base, _) = store.load(*bid)?;
                    let diff = filter_diff_by_severity(diff_findings(&base, &collector), min_rank);
                    diff.added
                        .iter()
                        .map(|r| {
                            serde_json::json!({
                                "severity": r.severity,
                                "host": r.host.to_string(),
                                "port": r.port,
                                "finding": r.finding,
                                "peers": r.peers,
                            })
                        })
                        .collect()
                } else {
                    current_ge
                        .iter()
                        .map(|(host, port, sev, finding, peers)| {
                            serde_json::json!({
                                "severity": sev,
                                "host": host.to_string(),
                                "port": port,
                                "finding": finding,
                                "peers": peers,
                            })
                        })
                        .collect()
                };
            let payload = serde_json::json!({
                "source": "aresbird",
                "module": "active-misconfig",
                "min_severity": min_severity,
                "notify_on": format!("{notify_on:?}").to_ascii_lowercase(),
                "new_count": new_count,
                "finding_count": findings_json.len(),
                "baseline": baseline_id.map(|u| u.to_string()),
                "findings": findings_json,
            });
            match post_json(url, &payload).await {
                Ok(status) if !quiet => {
                    eprintln!("[notify] webhook HTTP {status}");
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("[notify] webhook failed: {e}");
                }
            }
        } else if !quiet {
            eprintln!("[notify] skipped (condition --notify-on {notify_on:?} not met)");
        }
    }

    if fail_on_any && any_count > 0 {
        eprintln!("error: {any_count} finding(s) ≥ {min_severity} (--fail-on-any)");
        std::process::exit(2);
    }
    if fail_on_new && baseline_id.is_some() && new_count > 0 {
        eprintln!("error: {new_count} new finding(s) ≥ {min_severity} vs baseline (--fail-on-new)");
        std::process::exit(2);
    }
    Ok(())
}

/// Prints findings delta; returns count of newly added findings (after severity filter).
fn print_findings_delta(
    baseline_id: uuid::Uuid,
    current: &ares_core::EventCollector,
    new_only: bool,
    format: OutputFormat,
    quiet: bool,
    min_rank: u8,
) -> anyhow::Result<usize> {
    let store = RunStore::open_default()?;
    let (baseline, _) = store.load(baseline_id)?;
    let diff = filter_diff_by_severity(diff_findings(&baseline, current), min_rank);
    let new_count = diff.added.len();
    if !quiet {
        eprintln!(
            "baseline {baseline_id}: +{} new, -{} gone (≥ min-severity)",
            new_count,
            diff.removed.len(),
        );
    }
    match format {
        OutputFormat::Csv => {
            print!("{}", findings_diff_to_csv_filtered(&diff, new_only));
        }
        OutputFormat::Json => {
            if new_only {
                println!("{}", serde_json::to_string_pretty(&diff.added)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            }
        }
        _ => {
            if new_only {
                println!("NEW FINDINGS (+{new_count})");
                if diff.added.is_empty() {
                    println!("(none)");
                }
                for r in &diff.added {
                    let p = r.port.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
                    println!("  + [{}] {}:{}  {}", r.severity, r.host, p, r.finding);
                }
            } else {
                println!(
                    "Findings vs baseline: +{} added, -{} removed",
                    new_count,
                    diff.removed.len(),
                );
                if !diff.added.is_empty() {
                    println!("\nADDED");
                    for r in &diff.added {
                        let p = r.port.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
                        println!("  + [{}] {}:{}  {}", r.severity, r.host, p, r.finding);
                    }
                }
                if !diff.removed.is_empty() {
                    println!("\nREMOVED");
                    for r in &diff.removed {
                        let p = r.port.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
                        println!("  - [{}] {}:{}  {}", r.severity, r.host, p, r.finding);
                    }
                }
            }
        }
    }
    Ok(new_count)
}
