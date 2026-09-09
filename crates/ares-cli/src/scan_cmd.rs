//! `ares discover` / `ares scan` handlers (extracted from main).

use std::sync::Arc;

use ares_core::parse_ports;
use ares_core::timing::ScanMode;
use ares_output::{Renderer, RunStore};
use ares_plugin_api::PluginRegistry;

use crate::run_module;
use crate::script_pack;
use crate::workspace;

#[allow(clippy::too_many_arguments)]
pub async fn discover(
    registry: &PluginRegistry,
    targets: Vec<String>,
    arp: bool,
    ports: Option<String>,
    mode: ScanMode,
    renderer: &Renderer,
    save: bool,
    ephemeral: bool,
    workspace_id: &str,
) -> anyhow::Result<()> {
    let mut extra = serde_json::Map::new();
    if arp {
        extra.insert("arp".into(), serde_json::Value::Bool(true));
    }
    let probe = if let Some(p) = ports {
        parse_ports(&p)?
    } else {
        vec![]
    };
    run_module(
        registry,
        "discover",
        targets,
        probe,
        mode,
        renderer,
        false,
        save,
        extra,
        ephemeral,
        workspace_id,
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn scan(
    registry: &PluginRegistry,
    targets: Vec<String>,
    ports: String,
    udp: bool,
    udp_ports: Option<String>,
    show_closed: bool,
    show_filtered: bool,
    service: bool,
    syn: bool,
    discover: bool,
    pn: bool,
    resume: Option<String>,
    script_pack: Option<String>,
    mode: ScanMode,
    renderer: Renderer,
    save: bool,
    quiet: bool,
    ephemeral: bool,
    workspace_id: &str,
) -> anyhow::Result<()> {
    let port_list = parse_ports(&ports)?;
    let mut extra = serde_json::Map::new();
    extra.insert("udp".into(), serde_json::Value::Bool(udp));
    if let Some(up) = udp_ports {
        let list = parse_ports(&up)?;
        extra.insert(
            "udp_ports".into(),
            serde_json::Value::Array(list.into_iter().map(serde_json::Value::from).collect()),
        );
    }
    extra.insert("show_closed".into(), serde_json::Value::Bool(show_closed));
    extra.insert(
        "show_filtered".into(),
        serde_json::Value::Bool(show_filtered),
    );
    extra.insert("syn".into(), serde_json::Value::Bool(syn));
    extra.insert("discover".into(), serde_json::Value::Bool(discover));
    extra.insert("pn".into(), serde_json::Value::Bool(pn));

    let renderer = renderer.with_port_visibility(show_closed, show_filtered);

    let mut prior_collector = None;
    let mut prior_graph = None;
    if let Some(rid) = resume {
        let store = RunStore::open_default()?;
        let id = uuid::Uuid::parse_str(&rid)?;
        let (collector, graph) = store.load(id)?;
        let skip: Vec<serde_json::Value> = collector
            .scanned_pairs()
            .into_iter()
            .map(|(a, p)| serde_json::json!({ "addr": a.to_string(), "port": p }))
            .collect();
        eprintln!("resume from {id}: {} pairs already scanned", skip.len());
        extra.insert("skip_pairs".into(), serde_json::Value::Array(skip));
        prior_collector = Some(collector);
        prior_graph = Some(graph);
    }

    let (collector, graph) = run_module(
        registry,
        "scan",
        targets.clone(),
        port_list.clone(),
        mode,
        &renderer,
        true,
        false,
        extra,
        ephemeral,
        workspace_id,
    )
    .await?;

    let (mut collector, mut graph) =
        if let (Some(mut prior_c), Some(mut prior_g)) = (prior_collector, prior_graph) {
            for e in &collector.events {
                prior_g.apply(e);
                prior_c.push(e.clone());
            }
            (prior_c, prior_g)
        } else {
            (collector, graph)
        };

    if service {
        let ports = collector
            .open_ports()
            .into_iter()
            .map(|(_, p, _)| p)
            .collect::<Vec<_>>();
        let (svc_c, svc_g) = run_module(
            registry,
            "service",
            targets.clone(),
            if ports.is_empty() {
                port_list.clone()
            } else {
                ports
            },
            mode,
            &renderer,
            true,
            false,
            serde_json::Map::new(),
            ephemeral,
            workspace_id,
        )
        .await?;
        for e in &svc_c.events {
            graph.apply(e);
            collector.push(e.clone());
        }
        let _ = svc_g;
    }

    let pack_opt = script_pack.clone();
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
        let cancel_c = cancel.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            cancel_c.cancel();
        });
        let emit_graph = graph_arc.clone();
        let emit_collector = collector_arc.clone();
        let live = Arc::new(
            Renderer::new(renderer.format, renderer.color)
                .with_quiet(quiet)
                .with_port_visibility(show_closed, show_filtered)
                .with_min_finding_rank(renderer.min_finding_rank),
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
        if !ephemeral {
            workspace::merge_and_save(workspace_id, &collector, &graph, quiet)?;
        }
    }

    if save {
        let store = RunStore::open_default()?;
        let save_name = match (service, pack_opt.is_some()) {
            (true, true) => "scan+service+scripts",
            (true, false) => "scan+service",
            (false, true) => "scan+scripts",
            (false, false) => "scan",
        };
        let id = store.save(save_name, &collector, &graph)?;
        if !quiet {
            eprintln!("saved run {id}");
        } else {
            eprintln!("# saved {id}");
        }
    }

    if pack_opt.is_some() {
        renderer.render_summary(&collector, &graph);
    }

    Ok(())
}
