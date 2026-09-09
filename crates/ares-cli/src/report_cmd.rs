//! `ares report` command handlers (extracted from main).

use std::str::FromStr;

use ares_output::{
    diff_collectors, diff_findings, filter_diff_by_severity, findings_diff_to_csv,
    findings_to_csv_min, parse_min_severity, OutputFormat, Renderer, RunStore,
};

use crate::args::{BaselineCmd, ReportCmd};
use crate::collector_from_graph_findings;

pub fn handle(action: ReportCmd, color: bool, workspace_id: &str) -> anyhow::Result<()> {
    match action {
        ReportCmd::List { limit, name } => {
            let store = RunStore::open_default()?;
            println!(
                "store: {}  ({} runs)",
                store.path().display(),
                store.count()?
            );
            for m in store.list_meta(limit, name.as_deref())? {
                println!(
                    "{}  {}  {:<24}  events={}",
                    m.id,
                    m.created_at.to_rfc3339(),
                    m.name,
                    m.event_count
                );
            }
        }
        ReportCmd::Show { run_id } => {
            let store = RunStore::open_default()?;
            let id = if let Some(rid) = run_id {
                uuid::Uuid::parse_str(&rid)?
            } else {
                let runs = store.list(1)?;
                let Some((id, _, _)) = runs.first() else {
                    anyhow::bail!("no stored runs");
                };
                *id
            };
            let s = store.stats(id)?;
            let (_collector, graph) = store.load(id)?;
            println!("store: {}", store.path().display());
            println!("id:         {}", s.id);
            println!("name:       {}", s.name);
            println!("created:    {}", s.created_at.to_rfc3339());
            println!("events:     {}", s.event_count);
            println!("hosts_up:   {}", s.hosts_up);
            println!("ports_open: {}", s.ports_open);
            println!(
                "findings:   {} (graph: {})",
                s.findings,
                graph.finding_count()
            );
            println!("os_guesses: {}", s.os_guesses);
            println!("dns_names:  {}", graph.dns.len());
            println!("paths:      {}", graph.paths.len());
            println!("sessions:   {}", graph.sessions.len());
            // Top hosts with findings
            let mut with_f: Vec<_> = graph
                .hosts
                .values()
                .filter(|h| !h.findings.is_empty())
                .collect();
            with_f.sort_by_key(|b| std::cmp::Reverse(b.findings.len()));
            for h in with_f.into_iter().take(8) {
                let name = h.hostname.as_deref().unwrap_or("-");
                println!("  Â· {} ({name}): {} finding(s)", h.addr, h.findings.len());
            }
        }
        ReportCmd::Workspace { name } => {
            let wid = name
                .as_deref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| workspace_id.to_string());
            let store = RunStore::open_default()?;
            let graph = store.load_workspace(&wid)?;
            let store_name = RunStore::workspace_name(&wid);
            println!("workspace:  {wid} ({store_name})");
            println!("store:      {}", store.path().display());
            println!("hosts:      {}", graph.hosts.len());
            println!(
                "hosts_up:   {}",
                graph.hosts.values().filter(|h| h.up).count()
            );
            println!(
                "ports_open: {}",
                graph
                    .hosts
                    .values()
                    .map(|h| {
                        h.ports
                            .values()
                            .filter(|p| p.state == ares_core::model::PortState::Open)
                            .count()
                    })
                    .sum::<usize>()
            );
            println!("findings:   {}", graph.finding_count());
            println!("dns_names:  {}", graph.dns.len());
            println!("paths:      {}", graph.paths.len());
            println!("sessions:   {}", graph.sessions.len());
            let mut hosts: Vec<_> = graph.hosts.values().collect();
            hosts.sort_by_key(|a| a.addr);
            for h in hosts.into_iter().take(12) {
                let opens: Vec<_> = h
                    .ports
                    .values()
                    .filter(|p| p.state == ares_core::model::PortState::Open)
                    .map(|p| p.port.to_string())
                    .collect();
                println!(
                    "  Â· {} up={} open=[{}] findings={}",
                    h.addr,
                    h.up,
                    opens.join(","),
                    h.findings.len()
                );
            }
        }
        ReportCmd::Delete { run_id } => {
            let store = RunStore::open_default()?;
            let id = uuid::Uuid::parse_str(&run_id)?;
            if store.delete(id)? {
                println!("deleted {id}");
            } else {
                anyhow::bail!("run not found: {id}");
            }
        }
        ReportCmd::Prune { keep, name } => {
            let store = RunStore::open_default()?;
            let before = store.count()?;
            let deleted = if let Some(n) = name.as_deref() {
                store.prune_named(n, keep)?
            } else {
                store.prune_keep(keep)?
            };
            println!(
                "pruned {deleted} run(s); keep={keep}{}; now {} total",
                name.as_deref()
                    .map(|n| format!(" name={n}"))
                    .unwrap_or_default(),
                before.saturating_sub(deleted)
            );
        }
        ReportCmd::Last {
            format,
            min_severity,
        } => {
            let store = RunStore::open_default()?;
            let runs = store.list(1)?;
            let Some((id, _, _)) = runs.first() else {
                anyhow::bail!("no stored runs");
            };
            let (collector, graph) = store.load(*id)?;
            let fmt = OutputFormat::from_str(&format).unwrap_or(OutputFormat::Table);
            let min_rank = parse_min_severity(&min_severity)?;
            Renderer::new(fmt, color)
                .with_min_finding_rank(min_rank)
                .render_summary(&collector, &graph);
        }
        ReportCmd::Diff { run_a, run_b } => {
            let store = RunStore::open_default()?;
            let id_a = uuid::Uuid::parse_str(&run_a)?;
            let id_b = uuid::Uuid::parse_str(&run_b)?;
            let (a, _) = store.load(id_a)?;
            let (b, _) = store.load(id_b)?;
            let diff = diff_collectors(&a, &b);
            println!("{}", serde_json::to_string_pretty(&diff)?);
        }
        ReportCmd::DiffFindings {
            run_a,
            run_b,
            format,
            out,
            min_severity,
        } => {
            let store = RunStore::open_default()?;
            let id_a = uuid::Uuid::parse_str(&run_a)?;
            let id_b = uuid::Uuid::parse_str(&run_b)?;
            let (a, _) = store.load(id_a)?;
            let (b, _) = store.load(id_b)?;
            let min_rank = parse_min_severity(&min_severity)?;
            let diff = filter_diff_by_severity(diff_findings(&a, &b), min_rank);
            let fmt = OutputFormat::from_str(&format).unwrap_or(OutputFormat::Table);
            if matches!(fmt, OutputFormat::Csv) || out.is_some() {
                let csv = findings_diff_to_csv(&diff);
                if let Some(path) = out {
                    std::fs::write(&path, &csv)?;
                    eprintln!(
                        "findings diff {id_a} â†’ {id_b}: +{} -{} ~{} â†’ {}",
                        diff.added.len(),
                        diff.removed.len(),
                        diff.unchanged,
                        path.display()
                    );
                } else {
                    print!("{csv}");
                }
            } else if matches!(fmt, OutputFormat::Json) {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                println!(
                    "Findings diff {id_a} â†’ {id_b}: +{} added, -{} removed, {} unchanged",
                    diff.added.len(),
                    diff.removed.len(),
                    diff.unchanged
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
        ReportCmd::Export {
            run_id,
            format,
            out,
            min_severity,
        } => {
            let store = RunStore::open_default()?;
            let id = if let Some(rid) = run_id {
                uuid::Uuid::parse_str(&rid)?
            } else {
                let runs = store.list(1)?;
                let Some((id, _, _)) = runs.first() else {
                    anyhow::bail!("no stored runs");
                };
                *id
            };
            let (collector, graph) = store.load(id)?;
            let min_rank = parse_min_severity(&min_severity)?;
            let fmt = OutputFormat::from_str(&format).unwrap_or(OutputFormat::Csv);
            match (&out, fmt) {
                (Some(path), OutputFormat::Csv) | (Some(path), OutputFormat::Plain) => {
                    std::fs::write(path, findings_to_csv_min(&collector, min_rank))?;
                    eprintln!("exported findings from {id} â†’ {}", path.display());
                }
                (Some(path), OutputFormat::Json) => {
                    let findings = ares_output::enriched_findings(&collector, min_rank);
                    let json = serde_json::to_string_pretty(&findings)?;
                    std::fs::write(path, json)?;
                    eprintln!("exported findings JSON from {id} â†’ {}", path.display());
                }
                (Some(path), OutputFormat::Markdown) => {
                    let md = ares_output::render_markdown(&collector, &graph, min_rank);
                    std::fs::write(path, md)?;
                    eprintln!("exported markdown from {id} â†’ {}", path.display());
                }
                (Some(path), OutputFormat::Sarif) => {
                    let sarif = ares_output::findings_to_sarif_min(&collector, min_rank);
                    std::fs::write(path, sarif)?;
                    eprintln!("exported SARIF from {id} â†’ {}", path.display());
                }
                (None, OutputFormat::Sarif) => {
                    print!(
                        "{}",
                        ares_output::findings_to_sarif_min(&collector, min_rank)
                    );
                }
                (None, OutputFormat::Csv) => {
                    print!("{}", findings_to_csv_min(&collector, min_rank));
                }
                (None, other) => {
                    Renderer::new(other, color)
                        .with_min_finding_rank(min_rank)
                        .render_summary(&collector, &graph);
                }
                (Some(_), OutputFormat::Jsonl | OutputFormat::Table) => {
                    anyhow::bail!(
                        "--out supports csv/json/md/sarif (use --format csv|json|md|sarif)"
                    );
                }
            }
        }
        ReportCmd::Metrics {
            run_id,
            workspace: use_ws,
            name,
            format,
            min_severity,
        } => {
            let store = RunStore::open_default()?;
            let min_rank = parse_min_severity(&min_severity)?;
            let collector = if use_ws {
                let wid = name
                    .as_deref()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| workspace_id.to_string());
                let graph = store.load_workspace(&wid)?;
                collector_from_graph_findings(&graph)
            } else {
                let id = if let Some(rid) = run_id {
                    uuid::Uuid::parse_str(&rid)?
                } else {
                    let runs = store.list(1)?;
                    let Some((id, _, _)) = runs.first() else {
                        anyhow::bail!("no stored runs (try --workspace)");
                    };
                    *id
                };
                store.load(id)?.0
            };
            let metrics = ares_output::findings_metrics(&collector, min_rank);
            match format.to_ascii_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&metrics)?),
                _ => print!("{}", ares_output::format_metrics_table(&metrics)),
            }
        }
        ReportCmd::Graph {
            run_id,
            workspace: use_ws,
            workspace_name,
            format,
            out,
        } => {
            let store = RunStore::open_default()?;
            let (label, graph) = if use_ws {
                let wid = workspace_name
                    .as_deref()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| workspace_id.to_string());
                let g = store.load_workspace(&wid)?;
                (format!("workspace:{wid}"), g)
            } else {
                let id = if let Some(rid) = run_id {
                    uuid::Uuid::parse_str(&rid)?
                } else {
                    let runs = store.list(1)?;
                    let Some((id, _, _)) = runs.first() else {
                        anyhow::bail!("no stored runs (try --workspace)");
                    };
                    *id
                };
                let (_collector, g) = store.load(id)?;
                (id.to_string(), g)
            };
            let body = match format.to_ascii_lowercase().as_str() {
                "json" => serde_json::to_string_pretty(&graph.export_relations())?,
                "mermaid" | "md" | "mmd" => graph.to_mermaid(),
                other => anyhow::bail!("unknown graph format `{other}` â€” use mermaid|json"),
            };
            if let Some(path) = out {
                std::fs::write(&path, &body)?;
                eprintln!(
                    "graph from {label} ({format}, {} nodes) â†’ {}",
                    graph.export_relations().nodes.len(),
                    path.display()
                );
            } else {
                print!("{body}");
            }
        }
        ReportCmd::Baseline { action } => {
            const PIN: &str = "pinned-baseline";
            let store = RunStore::open_default()?;
            match action {
                BaselineCmd::Set { run_id } => {
                    let id = if let Some(rid) = run_id {
                        uuid::Uuid::parse_str(&rid)?
                    } else {
                        let runs = store.list(20)?;
                        let Some((id, _, _)) = runs
                            .iter()
                            .find(|(_, name, _)| name != PIN)
                            .or_else(|| runs.first())
                        else {
                            anyhow::bail!("no stored runs to pin");
                        };
                        *id
                    };
                    let (collector, graph) = store.load(id)?;
                    let _ = store.prune_named(PIN, 0)?;
                    let pin_id = store.save(PIN, &collector, &graph)?;
                    println!("pinned baseline â† run {id}");
                    println!("baseline id:  {pin_id}");
                    println!("name:         {PIN}");
                    println!("tip: ares report delta   # compare latest vs this baseline");
                }
                BaselineCmd::Show => {
                    if let Some(bid) = store.latest_named(PIN)? {
                        let s = store.stats(bid)?;
                        println!("pinned baseline: {bid}");
                        println!("created:         {}", s.created_at.to_rfc3339());
                        println!("events:          {}", s.event_count);
                        println!("findings:        {}", s.findings);
                        println!("ports_open:      {}", s.ports_open);
                    } else {
                        println!("no pinned baseline (ares report baseline set)");
                    }
                }
                BaselineCmd::Clear => {
                    let n = store.prune_named(PIN, 0)?;
                    println!("cleared {n} pinned baseline run(s)");
                }
            }
        }
        ReportCmd::Delta {
            current,
            format,
            out,
            min_severity,
            fail_on_new,
        } => {
            const PIN: &str = "pinned-baseline";
            let store = RunStore::open_default()?;
            let Some(base_id) = store.latest_named(PIN)? else {
                anyhow::bail!("no pinned baseline â€” run: ares report baseline set");
            };
            let cur_id = if let Some(rid) = current {
                uuid::Uuid::parse_str(&rid)?
            } else {
                let runs = store.list(30)?;
                let Some((id, _, _)) = runs.iter().find(|(_, name, _)| name != PIN) else {
                    anyhow::bail!("no current run to compare");
                };
                *id
            };
            let min_rank = parse_min_severity(&min_severity)?;
            let (base, _) = store.load(base_id)?;
            let (cur, _) = store.load(cur_id)?;
            let mut diff = diff_findings(&base, &cur);
            diff = filter_diff_by_severity(diff, min_rank);
            let new_n = diff.added.len();
            if matches!(format.as_str(), "csv") {
                let csv = findings_diff_to_csv(&diff);
                if let Some(path) = out {
                    std::fs::write(&path, &csv)?;
                    eprintln!("delta csv â†’ {}", path.display());
                } else {
                    print!("{csv}");
                }
            } else {
                println!("baseline: {base_id}");
                println!("current:  {cur_id}");
                println!(
                    "delta:    +{} new  -{} gone  ={} same  (min={min_severity})",
                    diff.added.len(),
                    diff.removed.len(),
                    diff.unchanged
                );
                if !diff.added.is_empty() {
                    println!("\nNEW:");
                    for r in &diff.added {
                        let p = r.port.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
                        println!(
                            "  + [{}] {}:{} (peers={}) {}",
                            r.severity, r.host, p, r.peers, r.finding
                        );
                        if let Some(fix) = ares_output::remediation_for(&r.finding) {
                            println!("      fix â†’ {fix}");
                        }
                    }
                }
                if !diff.removed.is_empty() {
                    println!("\nGONE:");
                    for r in &diff.removed {
                        let p = r.port.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
                        println!("  - [{}] {}:{} {}", r.severity, r.host, p, r.finding);
                    }
                }
                if let Some(path) = out {
                    let mut body = format!(
                        "# AresBird delta\n\nbaseline: `{base_id}`\ncurrent: `{cur_id}`\n\n## New ({})\n\n",
                        diff.added.len()
                    );
                    for r in &diff.added {
                        let p = r.port.map(|x| x.to_string()).unwrap_or_else(|| "-".into());
                        body.push_str(&format!(
                            "- **{}** `{}:{p}` â€” {}\n",
                            r.severity, r.host, r.finding
                        ));
                        if let Some(fix) = ares_output::remediation_for(&r.finding) {
                            body.push_str(&format!("  - fix: {fix}\n"));
                        }
                    }
                    std::fs::write(&path, body)?;
                    eprintln!("wrote delta notes â†’ {}", path.display());
                }
            }
            if fail_on_new && new_n > 0 {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}
