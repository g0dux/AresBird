//! Live TUI for pipeline/probe runs (`ares watch`).

use std::io::stdout;
use std::sync::Arc;
use std::time::Duration;

use ares_core::event::Event;
use ares_core::timing::ScanMode;
use ares_core::{AssetGraph, EventCollector};
use ares_output::{filter_findings_collapsed, suggest_talk_handoffs, OutputFormat, Renderer};
use ares_plugin_api::PluginRegistry;
use crossterm::event::{self, Event as CEvent, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use parking_lot::Mutex;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Terminal;
use tokio_util::sync::CancellationToken;

use crate::pipeline::{self, WatchShared};
use crate::workspace;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SevFilter {
    All,
    MediumPlus,
    High,
}

impl SevFilter {
    fn rank(self) -> u8 {
        match self {
            SevFilter::All => 0,
            SevFilter::MediumPlus => 2,
            SevFilter::High => 3,
        }
    }
    fn label(self) -> &'static str {
        match self {
            SevFilter::All => "all",
            SevFilter::MediumPlus => "≥medium",
            SevFilter::High => "high",
        }
    }
    fn cycle(self) -> Self {
        match self {
            SevFilter::All => SevFilter::MediumPlus,
            SevFilter::MediumPlus => SevFilter::High,
            SevFilter::High => SevFilter::All,
        }
    }
}

pub struct WatchOpts {
    pub mode: ScanMode,
    pub save: bool,
    pub ephemeral: bool,
    pub workspace: String,
    pub min_severity_rank: u8,
}

pub async fn watch_probe(
    profile: &str,
    targets: Vec<String>,
    registry: &PluginRegistry,
    opts: WatchOpts,
) -> anyhow::Result<()> {
    let pipe = pipeline::probe_pipeline(profile, targets)?;
    let name = pipe
        .name
        .clone()
        .unwrap_or_else(|| format!("probe-{profile}"));
    watch_pipeline_inner(pipe, &name, registry, opts).await
}

pub async fn watch_pipeline_file(
    file: &std::path::Path,
    registry: &PluginRegistry,
    opts: WatchOpts,
    cli_vars: &[(String, String)],
) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(file)?;
    let mut pipe: pipeline::PipelineFile = serde_yaml::from_str(&text)?;
    for (k, v) in cli_vars {
        pipe.vars.insert(k.clone(), v.clone());
    }
    // apply_vars is private — re-run via public pipeline::run after var subst by calling probe path
    // Duplicate minimal subst:
    pipeline_apply_vars(&mut pipe);
    let display = pipe
        .name
        .clone()
        .unwrap_or_else(|| file.display().to_string());
    watch_pipeline_inner(pipe, &display, registry, opts).await
}

fn pipeline_apply_vars(pipe: &mut pipeline::PipelineFile) {
    if pipe.vars.is_empty() {
        return;
    }
    let vars = pipe.vars.clone();
    let subst = |s: &str| -> String {
        let mut out = s.to_string();
        for (k, v) in &vars {
            out = out.replace(&format!("${{{k}}}"), v);
            out = out.replace(&format!("${k}"), v);
        }
        out
    };
    if let Some(n) = pipe.name.take() {
        pipe.name = Some(subst(&n));
    }
    if let Some(m) = pipe.mode.take() {
        pipe.mode = Some(subst(&m));
    }
    for t in &mut pipe.targets {
        *t = subst(t);
    }
    for step in &mut pipe.steps {
        step.module = subst(&step.module);
        if let Some(p) = step.ports.take() {
            step.ports = Some(subst(&p));
        }
        if let Some(f) = step.on_fail.take() {
            step.on_fail = Some(subst(&f));
        }
    }
}

async fn watch_pipeline_inner(
    pipe: pipeline::PipelineFile,
    display_name: &str,
    registry: &PluginRegistry,
    opts: WatchOpts,
) -> anyhow::Result<()> {
    let graph = Arc::new(Mutex::new(AssetGraph::new()));
    let collector = Arc::new(Mutex::new(EventCollector::new()));
    let cancel = CancellationToken::new();
    let shared = WatchShared {
        graph: graph.clone(),
        collector: collector.clone(),
        cancel: cancel.clone(),
    };

    let renderer = Renderer::new(OutputFormat::Table, true)
        .with_quiet(true)
        .with_min_finding_rank(opts.min_severity_rank);

    let registry = registry.clone();
    let mode = opts.mode;
    let save = opts.save;
    let display = display_name.to_string();
    let job = tokio::spawn(async move {
        pipeline::run_pipeline_owned_ex(
            pipe,
            &display,
            mode,
            &renderer,
            &registry,
            true,
            save,
            None,
            None,
            Some(shared),
            false,
            true,
        )
        .await
    });

    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let mut sev = SevFilter::All;
    let mut filter_cdn = false;
    let mut filter_port: Option<u16> = None;
    let mut port_input = String::new();
    let mut entering_port = false;
    let mut done_msg: Option<String> = None;

    let ui_result: anyhow::Result<()> = loop {
        if job.is_finished() && done_msg.is_none() {
            done_msg = Some("job finished — press q to exit".into());
        }

        terminal.draw(|f| {
            draw_ui(
                f,
                display_name,
                &graph,
                &collector,
                sev,
                filter_cdn,
                filter_port,
                entering_port,
                &port_input,
                done_msg.as_deref(),
            );
        })?;

        if event::poll(Duration::from_millis(120))? {
            if let CEvent::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if entering_port {
                    match key.code {
                        KeyCode::Enter => {
                            filter_port = port_input.parse().ok();
                            entering_port = false;
                        }
                        KeyCode::Esc => {
                            entering_port = false;
                            port_input.clear();
                        }
                        KeyCode::Backspace => {
                            port_input.pop();
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() && port_input.len() < 5 => {
                            port_input.push(c);
                        }
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        cancel.cancel();
                        break Ok(());
                    }
                    KeyCode::Char('s') => sev = sev.cycle(),
                    KeyCode::Char('c') => filter_cdn = !filter_cdn,
                    KeyCode::Char('p') => {
                        entering_port = true;
                        port_input.clear();
                    }
                    KeyCode::Char('P') => {
                        filter_port = None;
                        port_input.clear();
                    }
                    KeyCode::Char('?') | KeyCode::Char('h') => {
                        done_msg =
                            Some("s=sev cycle · c=CDN · p=port filter · P=clear · q=quit".into());
                    }
                    _ => {}
                }
            }
        }

        if job.is_finished() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    let join = job.await;
    match join {
        Ok(Ok((collector_out, graph_out))) => {
            if !opts.ephemeral {
                workspace::merge_and_save(&opts.workspace, &collector_out, &graph_out, false)?;
            }
            let renderer = Renderer::new(OutputFormat::Table, true)
                .with_min_finding_rank(opts.min_severity_rank);
            renderer.render_summary(&collector_out, &graph_out);
            let handoffs =
                suggest_talk_handoffs(&collector_out, &graph_out, opts.min_severity_rank);
            if !handoffs.is_empty() {
                eprintln!("NEXT:");
                for h in handoffs {
                    eprintln!("  → {}  # {}", h.cmd, h.reason);
                }
            }
            ui_result?;
            Ok(())
        }
        Ok(Err(e)) => {
            ui_result?;
            Err(e)
        }
        Err(e) => {
            ui_result?;
            Err(anyhow::anyhow!("watch job join: {e}"))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_ui(
    f: &mut ratatui::Frame<'_>,
    title: &str,
    graph: &Arc<Mutex<AssetGraph>>,
    collector: &Arc<Mutex<EventCollector>>,
    sev: SevFilter,
    filter_cdn: bool,
    filter_port: Option<u16>,
    entering_port: bool,
    port_input: &str,
    done_msg: Option<&str>,
) {
    let g = graph.lock();
    let c = collector.lock();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Percentage(30),
            Constraint::Percentage(35),
            Constraint::Percentage(35),
        ])
        .split(f.area());

    let opens = g.open_services().len();
    let findings_n = g.finding_count();
    let hosts = g.hosts.len();
    let status = format!(
        "AresBird watch · {title}\n\
         hosts={hosts} open={opens} findings={findings_n}  | sev={} cdn={} port={}\n\
         keys: [s] severity  [c] CDN filter  [p] port  [P] clear port  [?] help  [q] quit{}",
        sev.label(),
        if filter_cdn { "on" } else { "off" },
        filter_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".into()),
        if entering_port {
            format!("  port> {port_input}_")
        } else {
            done_msg.map(|m| format!("  ({m})")).unwrap_or_default()
        }
    );
    f.render_widget(
        Paragraph::new(status).block(
            Block::default()
                .borders(Borders::ALL)
                .title("status · help on ?"),
        ),
        chunks[0],
    );

    // Open ports
    let mut port_items = Vec::new();
    for (addr, port, svc) in g.open_services() {
        if let Some(fp) = filter_port {
            if port != fp {
                continue;
            }
        }
        if filter_cdn {
            if let Some(h) = g.hosts.get(&addr) {
                if h.cdn.is_none() {
                    continue;
                }
            } else {
                continue;
            }
        }
        let name = svc.as_ref().map(|s| s.name.as_str()).unwrap_or("-");
        port_items.push(ListItem::new(format!("{addr}:{port}  {name}")));
    }
    if port_items.is_empty() {
        port_items.push(ListItem::new("(no open ports yet)"));
    }
    f.render_widget(
        List::new(port_items).block(Block::default().borders(Borders::ALL).title("open ports")),
        chunks[1],
    );

    // Findings
    let findings = filter_findings_collapsed(c.findings_collapsed(), sev.rank());
    let mut find_items = Vec::new();
    for (addr, port, severity, finding, _) in &findings {
        if let Some(fp) = filter_port {
            if *port != Some(fp) {
                continue;
            }
        }
        if filter_cdn {
            if let Some(h) = g.hosts.get(addr) {
                if h.cdn.is_none() {
                    continue;
                }
            } else {
                continue;
            }
        }
        let color = match severity.as_str() {
            "high" => Color::Red,
            "medium" => Color::Yellow,
            "low" => Color::Blue,
            _ => Color::Gray,
        };
        let port_s = port.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
        find_items.push(ListItem::new(Line::from(vec![
            Span::styled(
                format!("{severity:<7}"),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                " {addr}:{port_s}  {}",
                finding.chars().take(70).collect::<String>()
            )),
        ])));
    }
    if find_items.is_empty() {
        find_items.push(ListItem::new("(no findings yet)"));
    }
    f.render_widget(
        List::new(find_items).block(Block::default().borders(Borders::ALL).title("findings")),
        chunks[2],
    );

    // Event tail
    let mut logs = Vec::new();
    for e in c.events.iter().rev().take(40) {
        let line = match e {
            Event::Log { level, message } => format!("[{level}] {message}"),
            Event::PortResult {
                addr, port, state, ..
            } => format!("port {addr}:{port} {state}"),
            Event::MisconfigFinding {
                addr,
                port,
                finding,
                severity,
            } => format!(
                "! {severity} {addr}:{} {finding}",
                port.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
            ),
            Event::JobStarted { .. } => "job started".into(),
            Event::JobFinished { status, .. } => format!("job {status}"),
            Event::Stats {
                pps,
                open,
                closed,
                filtered,
                elapsed_ms,
            } => {
                format!("stats {pps}pps open={open} closed={closed} filt={filtered} {elapsed_ms}ms")
            }
            _ => continue,
        };
        logs.push(ListItem::new(line));
        if logs.len() >= 18 {
            break;
        }
    }
    logs.reverse();
    if logs.is_empty() {
        logs.push(ListItem::new("(waiting for events…)"));
    }
    f.render_widget(
        List::new(logs).block(Block::default().borders(Borders::ALL).title("events")),
        chunks[3],
    );
}
