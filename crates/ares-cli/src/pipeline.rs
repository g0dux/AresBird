use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use ares_core::event::Event;
use ares_core::job::Job;
use ares_core::parse_ports;
use ares_core::timing::ScanMode;
use ares_core::{AssetGraph, EventCollector};
use ares_output::{OutputFormat, Renderer, RunStore};
use ares_plugin_api::{ModuleCtx, PluginRegistry};
use chrono::Utc;
use parking_lot::Mutex;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct PipelineFile {
    pub name: Option<String>,
    pub mode: Option<String>,
    #[serde(default)]
    pub vars: HashMap<String, String>,
    pub targets: Vec<String>,
    pub steps: Vec<PipelineStep>,
}

#[derive(Debug, Deserialize)]
pub struct PipelineStep {
    pub module: String,
    pub ports: Option<String>,
    #[serde(default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
    /// Skip step unless predicates pass (AND of present keys).
    #[serde(default)]
    pub when: Option<WhenClause>,
    /// `abort` (default) | `continue` | `skip_rest`
    #[serde(default)]
    pub on_fail: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WhenClause {
    /// Require at least one open port in the graph.
    pub open_any: Option<bool>,
    /// Minimum number of open (host,port) pairs.
    pub min_open: Option<usize>,
    /// At least one of these ports must be open somewhere.
    pub open_ports: Option<Vec<u16>>,
    /// Graph findings count ≥ N.
    pub findings_gte: Option<usize>,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_pipeline(
    file: &Path,
    cli_mode: ScanMode,
    renderer: &Renderer,
    registry: &PluginRegistry,
    active_allowed: bool,
    save: bool,
    resume: Option<&str>,
    from_step: Option<usize>,
    cli_vars: &[(String, String)],
) -> anyhow::Result<(EventCollector, AssetGraph)> {
    let text = std::fs::read_to_string(file)?;
    let mut pipe: PipelineFile = serde_yaml::from_str(&text)?;

    // Merge vars: file defaults ← CLI `--var`
    for (k, v) in cli_vars {
        pipe.vars.insert(k.clone(), v.clone());
    }
    apply_vars(&mut pipe);

    let display_name = pipe
        .name
        .clone()
        .unwrap_or_else(|| file.to_str().unwrap_or("unnamed").to_string());

    run_pipeline_owned(
        pipe,
        &display_name,
        cli_mode,
        renderer,
        registry,
        active_allowed,
        save,
        resume,
        from_step,
    )
    .await
}

/// Built-in intent profiles for `ares probe`.
pub fn probe_pipeline(profile: &str, targets: Vec<String>) -> anyhow::Result<PipelineFile> {
    let profile = profile.trim().to_ascii_lowercase();
    let steps = match profile.as_str() {
        "web" => vec![
            step("discover", None, None, None),
            step("scan", Some("web"), None, None),
            step(
                "service",
                Some("open"),
                Some(WhenClause {
                    open_any: Some(true),
                    ..Default::default()
                }),
                None,
            ),
            {
                let mut s = step(
                    "active-misconfig",
                    Some("open:web"),
                    Some(WhenClause {
                        open_ports: Some(vec![80, 443, 8080, 8443]),
                        ..Default::default()
                    }),
                    Some("continue"),
                );
                s.extra
                    .insert("path_probes".into(), serde_json::json!(true));
                s.extra
                    .insert("path_profile".into(), serde_json::json!("web"));
                s
            },
        ],
        "apps" => vec![
            step("discover", None, None, None),
            step("scan", Some("apps"), None, None),
            step(
                "service",
                Some("open"),
                Some(WhenClause {
                    open_any: Some(true),
                    ..Default::default()
                }),
                None,
            ),
            step(
                "active-misconfig",
                Some("open:apps"),
                Some(WhenClause {
                    open_any: Some(true),
                    ..Default::default()
                }),
                Some("continue"),
            ),
        ],
        "infra" => vec![
            step("discover", None, None, None),
            step("scan", Some("infra"), None, None),
            step(
                "service",
                Some("open"),
                Some(WhenClause {
                    open_any: Some(true),
                    ..Default::default()
                }),
                None,
            ),
            {
                let mut s = step(
                    "active-misconfig",
                    Some("open:infra"),
                    Some(WhenClause {
                        open_any: Some(true),
                        ..Default::default()
                    }),
                    Some("continue"),
                );
                s.extra
                    .insert("path_probes".into(), serde_json::json!(false));
                s
            },
        ],
        "quick" => vec![
            step("scan", Some("top100"), None, None),
            step(
                "service",
                Some("open"),
                Some(WhenClause {
                    open_any: Some(true),
                    ..Default::default()
                }),
                None,
            ),
        ],
        other => anyhow::bail!("unknown probe profile '{other}' (web|apps|infra|quick)"),
    };

    Ok(PipelineFile {
        name: Some(format!("probe-{profile}")),
        mode: None,
        vars: HashMap::new(),
        targets,
        steps,
    })
}

fn step(
    module: &str,
    ports: Option<&str>,
    when: Option<WhenClause>,
    on_fail: Option<&str>,
) -> PipelineStep {
    PipelineStep {
        module: module.into(),
        ports: ports.map(|s| s.into()),
        extra: serde_json::Map::new(),
        when,
        on_fail: on_fail.map(|s| s.into()),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_pipeline_owned(
    pipe: PipelineFile,
    display_name: &str,
    cli_mode: ScanMode,
    renderer: &Renderer,
    registry: &PluginRegistry,
    active_allowed: bool,
    save: bool,
    resume: Option<&str>,
    from_step: Option<usize>,
) -> anyhow::Result<(EventCollector, AssetGraph)> {
    run_pipeline_owned_ex(
        pipe,
        display_name,
        cli_mode,
        renderer,
        registry,
        active_allowed,
        save,
        resume,
        from_step,
        None,
        true,
        false,
    )
    .await
}

/// Shared state for `ares watch` (poll while job runs).
pub struct WatchShared {
    pub graph: Arc<Mutex<AssetGraph>>,
    pub collector: Arc<Mutex<EventCollector>>,
    pub cancel: tokio_util::sync::CancellationToken,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_pipeline_owned_ex(
    pipe: PipelineFile,
    display_name: &str,
    cli_mode: ScanMode,
    renderer: &Renderer,
    registry: &PluginRegistry,
    active_allowed: bool,
    save: bool,
    resume: Option<&str>,
    from_step: Option<usize>,
    shared: Option<WatchShared>,
    live_print: bool,
    suppress_summary: bool,
) -> anyhow::Result<(EventCollector, AssetGraph)> {
    let mode = pipe
        .mode
        .as_deref()
        .map(|s| s.parse().unwrap_or(cli_mode))
        .unwrap_or(cli_mode);

    let (graph, collector, cancel, own_ctrlc) = if let Some(s) = shared {
        (s.graph, s.collector, s.cancel, false)
    } else {
        (
            Arc::new(Mutex::new(AssetGraph::new())),
            Arc::new(Mutex::new(EventCollector::new())),
            tokio_util::sync::CancellationToken::new(),
            true,
        )
    };

    let mut skip_pairs: Option<serde_json::Value> = None;
    if let Some(rid) = resume {
        let store = RunStore::open_default()?;
        let id = Uuid::parse_str(rid)?;
        let (prior_c, prior_g) = store.load(id)?;
        let skip: Vec<serde_json::Value> = prior_c
            .scanned_pairs()
            .into_iter()
            .map(|(a, p)| serde_json::json!({ "addr": a.to_string(), "port": p }))
            .collect();
        if live_print {
            eprintln!(
                "pipeline resume from {id}: {} pairs already scanned, seeding graph",
                skip.len()
            );
        }
        skip_pairs = Some(serde_json::Value::Array(skip));
        {
            let mut c = collector.lock();
            c.events.extend(prior_c.events);
        }
        {
            let mut g = graph.lock();
            *g = prior_g;
        }
    }

    let mut job = Job::new(pipe.name.as_deref().unwrap_or("pipeline"), mode);
    job.mark_running();
    let job_id = job.id;
    if own_ctrlc {
        let cancel_c = cancel.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("\n[!] cancelling pipeline job {job_id}…");
            cancel_c.cancel();
        });
    }

    if live_print {
        eprintln!("pipeline: {display_name} (job {job_id})");
    }

    let live = Arc::new(
        Renderer::new(renderer.format, renderer.color)
            .with_quiet(renderer.quiet || !live_print)
            .with_port_visibility(renderer.show_closed, renderer.show_filtered)
            .with_min_finding_rank(renderer.min_finding_rank),
    );
    let start_idx = from_step.unwrap_or(0);
    let mut step_errors = 0usize;
    let mut skip_rest = false;

    // Shared emit for job lifecycle
    {
        let emit_graph = graph.clone();
        let emit_collector = collector.clone();
        let emit_live = live.clone();
        let emit: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(move |event| {
            emit_graph.lock().apply(&event);
            emit_collector.lock().push(event.clone());
            emit_live.print_event_live(&event);
        });
        emit(Event::JobStarted {
            job_id,
            started_at: job.started_at.unwrap_or_else(Utc::now),
        });
        emit(Event::Log {
            level: "info".into(),
            message: format!("intent/pipeline starting: {display_name}"),
        });
    }

    for (i, step) in pipe.steps.iter().enumerate() {
        if i < start_idx {
            if live_print {
                eprintln!("↷ skip step {} ({})", i, step.module);
            }
            continue;
        }
        if skip_rest || cancel.is_cancelled() {
            break;
        }

        {
            let g = graph.lock();
            if let Some(when) = &step.when {
                if !eval_when(when, &g) {
                    if live_print {
                        eprintln!("↷ skip step [{i}] {} (when)", step.module);
                    }
                    continue;
                }
            }
        }

        let module = registry
            .get(&step.module)
            .ok_or_else(|| anyhow::anyhow!("unknown module in pipeline: {}", step.module))?;

        let ports = {
            let g = graph.lock();
            resolve_ports(step.ports.as_deref(), &g)?
        };

        {
            let emit_graph = graph.clone();
            let emit_collector = collector.clone();
            let emit_live = live.clone();
            let emit: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(move |event| {
                emit_graph.lock().apply(&event);
                emit_collector.lock().push(event.clone());
                emit_live.print_event_live(&event);
            });
            let open_n = graph.lock().open_services().len();
            emit(Event::Log {
                level: "info".into(),
                message: format!("step [{i}] {} ({} open so far)…", step.module, open_n),
            });
        }

        let emit_graph = graph.clone();
        let emit_collector = collector.clone();
        let emit_live = live.clone();
        let emit: Arc<dyn Fn(ares_core::Event) + Send + Sync> = Arc::new(move |event| {
            emit_graph.lock().apply(&event);
            emit_collector.lock().push(event.clone());
            emit_live.print_event_live(&event);
        });

        let mut extra = step.extra.clone();
        if step.module == "scan" {
            if let Some(ref skip) = skip_pairs {
                extra.insert("skip_pairs".into(), skip.clone());
            }
        }

        let ctx = ModuleCtx {
            cancel: cancel.clone(),
            mode,
            targets: pipe.targets.clone(),
            ports,
            graph: graph.clone(),
            emit,
            active_allowed,
            extra,
        };

        if live_print {
            eprintln!("→ step [{i}] {}", module.name());
        }
        if let Err(e) = module.run(ctx).await {
            if cancel.is_cancelled() {
                break;
            }
            let policy = step
                .on_fail
                .as_deref()
                .unwrap_or("abort")
                .to_ascii_lowercase();
            match policy.as_str() {
                "continue" => {
                    step_errors += 1;
                    if live_print {
                        eprintln!("! step [{i}] {} failed (continue): {e}", step.module);
                    }
                    continue;
                }
                "skip_rest" => {
                    step_errors += 1;
                    if live_print {
                        eprintln!("! step [{i}] {} failed (skip_rest): {e}", step.module);
                    }
                    skip_rest = true;
                    continue;
                }
                _ => {
                    job.mark_failed(e.to_string());
                    let emit_graph = graph.clone();
                    let emit_collector = collector.clone();
                    let emit_live = live.clone();
                    let emit: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(move |event| {
                        emit_graph.lock().apply(&event);
                        emit_collector.lock().push(event.clone());
                        emit_live.print_event_live(&event);
                    });
                    emit(Event::JobFinished {
                        job_id,
                        finished_at: Utc::now(),
                        status: format!("failed: {e}"),
                    });
                    return Err(e);
                }
            }
        }
    }

    let cancelled = cancel.is_cancelled();
    let status = if cancelled {
        job.mark_cancelled();
        "cancelled".to_string()
    } else if step_errors > 0 {
        job.mark_completed();
        format!("completed_with_errors ({step_errors})")
    } else {
        job.mark_completed();
        "completed".to_string()
    };
    {
        let emit_graph = graph.clone();
        let emit_collector = collector.clone();
        let emit_live = live.clone();
        let emit: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(move |event| {
            emit_graph.lock().apply(&event);
            emit_collector.lock().push(event.clone());
            emit_live.print_event_live(&event);
        });
        emit(Event::JobFinished {
            job_id,
            finished_at: job.finished_at.unwrap_or_else(Utc::now),
            status,
        });
    }

    let collector_out = collector.lock().clone();
    let graph_out = graph.lock().clone();
    if !suppress_summary && !matches!(renderer.format, OutputFormat::Jsonl) {
        renderer.render_summary(&collector_out, &graph_out);
    }

    if save {
        let store = RunStore::open_default()?;
        let id = store.save(
            pipe.name.as_deref().unwrap_or("pipeline"),
            &collector_out,
            &graph_out,
        )?;
        if live_print {
            eprintln!("saved run {id}");
        }
    }

    if live_print {
        if cancelled {
            eprintln!("pipeline job {job_id} cancelled — partial results above");
        } else if step_errors > 0 {
            eprintln!("pipeline finished with {step_errors} step error(s)");
        }
    }

    Ok((collector_out, graph_out))
}

fn eval_when(when: &WhenClause, graph: &AssetGraph) -> bool {
    let opens = graph.open_services();
    if let Some(true) = when.open_any {
        if opens.is_empty() {
            return false;
        }
    }
    if let Some(false) = when.open_any {
        if !opens.is_empty() {
            return false;
        }
    }
    if let Some(min) = when.min_open {
        if opens.len() < min {
            return false;
        }
    }
    if let Some(need) = &when.open_ports {
        let have: std::collections::HashSet<u16> = opens.iter().map(|(_, p, _)| *p).collect();
        if !need.iter().any(|p| have.contains(p)) {
            return false;
        }
    }
    if let Some(min_f) = when.findings_gte {
        if graph.finding_count() < min_f {
            return false;
        }
    }
    true
}

/// Resolve ports: `open`, `open:web`, `open:80,443`, or normal presets/lists.
pub fn resolve_ports(spec: Option<&str>, graph: &AssetGraph) -> anyhow::Result<Vec<u16>> {
    let Some(raw) = spec.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(ares_core::TOP100.to_vec());
    };
    let lower = raw.to_ascii_lowercase();
    if lower == "open" {
        let mut ports: Vec<u16> = graph
            .open_services()
            .into_iter()
            .map(|(_, p, _)| p)
            .collect();
        ports.sort_unstable();
        ports.dedup();
        return Ok(ports);
    }
    if let Some(rest) = lower.strip_prefix("open:") {
        let filter = parse_ports(rest)?;
        let open: std::collections::HashSet<u16> = graph
            .open_services()
            .into_iter()
            .map(|(_, p, _)| p)
            .collect();
        let mut out: Vec<u16> = filter.into_iter().filter(|p| open.contains(p)).collect();
        out.sort_unstable();
        out.dedup();
        return Ok(out);
    }
    Ok(parse_ports(raw)?)
}

fn apply_vars(pipe: &mut PipelineFile) {
    if pipe.vars.is_empty() {
        return;
    }
    let vars = pipe.vars.clone();
    if let Some(n) = pipe.name.take() {
        pipe.name = Some(subst(&n, &vars));
    }
    if let Some(m) = pipe.mode.take() {
        pipe.mode = Some(subst(&m, &vars));
    }
    for t in &mut pipe.targets {
        *t = subst(t, &vars);
    }
    for step in &mut pipe.steps {
        step.module = subst(&step.module, &vars);
        if let Some(p) = step.ports.take() {
            step.ports = Some(subst(&p, &vars));
        }
        if let Some(f) = step.on_fail.take() {
            step.on_fail = Some(subst(&f, &vars));
        }
        subst_json_map(&mut step.extra, &vars);
    }
}

fn subst(s: &str, vars: &HashMap<String, String>) -> String {
    let mut out = s.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("${{{k}}}"), v);
        // also allow $key without braces for simple tokens
        out = out.replace(&format!("${k}"), v);
    }
    out
}

fn subst_json_map(
    map: &mut serde_json::Map<String, serde_json::Value>,
    vars: &HashMap<String, String>,
) {
    for v in map.values_mut() {
        subst_json_value(v, vars);
    }
}

fn subst_json_value(v: &mut serde_json::Value, vars: &HashMap<String, String>) {
    match v {
        serde_json::Value::String(s) => *s = subst(s, vars),
        serde_json::Value::Array(arr) => {
            for item in arr {
                subst_json_value(item, vars);
            }
        }
        serde_json::Value::Object(obj) => subst_json_map(obj, vars),
        _ => {}
    }
}
