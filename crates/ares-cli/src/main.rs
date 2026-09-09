//! AresBird CLI — network interaction Swiss-army knife.

mod args;
mod brand;
mod pipeline;
mod probe_cmd;
mod report_cmd;
mod scan_cmd;
mod script_pack;
mod serve;
mod talk_repl;
mod watch;
mod workspace;
use crate::args::*;

use std::str::FromStr;
use std::sync::Arc;

use ares_core::event::Event;
use ares_core::job::Job;
use ares_core::parse_ports;
use ares_core::timing::ScanMode;
use ares_modules::builtin_registry;
use ares_output::{parse_min_severity, OutputFormat, Renderer, RunStore};
use ares_plugin_api::{register_discovered, Capability, ModuleCtx, PluginRegistry};
use chrono::Utc;
use clap::{Parser, ValueEnum};
use parking_lot::Mutex;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "ares",
    version,
    about = "AresBird — network interaction engine",
    long_about = "AresBird is a high-performance network interaction Swiss-army knife.\n\
Scan, talk, recon and active probes over the network fabric."
)]
struct Cli {
    /// Output format
    #[arg(long, global = true, default_value = "table")]
    format: String,

    /// Disable colors
    #[arg(long, global = true)]
    plain: bool,

    /// Increase verbosity (-v, -vv)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Scan timing mode
    #[arg(long, short = 'm', global = true, default_value = "normal")]
    mode: String,

    /// Persist run to local SQLite store
    #[arg(long, global = true)]
    save: bool,

    /// Suppress live event stream (auto for --format csv)
    #[arg(long, short = 'q', global = true)]
    quiet: bool,

    /// Do not read/write the living workspace graph
    #[arg(long, global = true)]
    ephemeral: bool,

    /// Living workspace name (default: env ARES_WORKSPACE or `default`)
    #[arg(long, global = true, env = "ARES_WORKSPACE")]
    workspace: Option<String>,

    #[command(subcommand)]
    command: Box<Commands>,
}

fn main() -> anyhow::Result<()> {
    // Windows default stack (~1 MiB) overflows on the large clap Commands + async state machine.
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024)
        .build()?;
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    init_tracing(cli.verbose);

    let mode = ScanMode::from_str(&cli.mode).unwrap_or(ScanMode::Normal);
    let format = OutputFormat::from_str(&cli.format).unwrap_or(OutputFormat::Table);
    let color = !cli.plain && std::env::var_os("NO_COLOR").is_none();
    let quiet = cli.quiet
        || matches!(
            format,
            OutputFormat::Csv | OutputFormat::Markdown | OutputFormat::Sarif
        );
    if quiet {
        std::env::set_var("ARES_QUIET", "1");
    }
    let workspace_id = workspace::resolve_workspace_id(cli.workspace.as_deref());
    let ephemeral = cli.ephemeral;
    let renderer = Renderer::new(format, color).with_quiet(quiet);
    let show_banner = !quiet && matches!(format, OutputFormat::Table | OutputFormat::Plain);
    if show_banner {
        brand::print_banner(color);
    }
    let mut registry = builtin_registry();
    let plugins_root = ares_plugin_api::resolve_plugins_root();
    let external = register_discovered(&mut registry, &plugins_root);
    if !quiet {
        if external > 0 {
            eprintln!(
                "loaded {external} external plugin(s) from {}",
                plugins_root.display()
            );
        } else if plugins_root.exists() {
            eprintln!(
                "no external plugins loaded from {} (ARES_PLUGIN_PREFER_COMMAND=1 to force script)",
                plugins_root.display()
            );
        }
    }

    match *cli.command {
        Commands::Version => {
            println!("{} {}", brand::PRODUCT, env!("CARGO_PKG_VERSION"));
            println!("fabric: {}", brand::PRODUCT_TAGLINE);
            println!("api: v{}", ares_plugin_api::API_VERSION);
            println!("modules: {}", registry.list().len());
            println!("tls: rustls + cert scrape (version/cipher/ALPN/SAN/expiry) + SNI");
            println!("fp: ares fp <host>  (TLS + HTTPS GET + banners + OS hints)");
            println!("path: OS traceroute/tracert + TCP TTL fallback");
            println!(
                "plugins: script + native ABI v{}",
                ares_plugin_api::NATIVE_ABI_VERSION
            );
            println!("syn: --syn => syn-compat (Windows) | syn-raw+arp (Linux --features raw)");
            println!(
                "udp: selective elicit; no reply = open|filtered (no ICMP unreachable on Windows)"
            );
            println!("scan: --discover then live hosts; --pn skips discover; --script-pack <id>");
            println!("scripts: ares scripts list  (packs/ NSE-style observe packs)");
            println!("probe: ares probe web|apps|infra|quick <targets>");
            println!("watch: ares watch probe|pipeline …  (live TUI)");
            println!("talk --repl: http|https|redis|ssh observe sessions");
            println!("workspace: living graph (ARES_WORKSPACE / --workspace; --ephemeral skips)");
            println!("arp: ares discover --arp (Linux+raw L2 sweep)");
            println!("mode: quiet|normal|fast|insane|stealth (jitter+shuffle+slow paths)");
            println!("ports: top100|top1000|apps|infra|web|all  (see: ares proto list)");
            println!(
                "protos: {} observes  (ares proto list)",
                PROTO_CATALOG.len()
            );
        }
        Commands::Doctor => {
            println!("{} doctor", brand::PRODUCT);
            println!("version:     {}", env!("CARGO_PKG_VERSION"));
            println!("api:         v{}", ares_plugin_api::API_VERSION);
            println!("modules:     {}", registry.list().len());
            println!("plugins dir: {}", plugins_root.display());
            let packs_root = script_pack::resolve_packs_root();
            let pack_n = script_pack::list_packs(&packs_root).len();
            println!("packs dir:   {} ({} pack(s))", packs_root.display(), pack_n);
            if let Ok(exe) = std::env::current_exe() {
                println!("binary:      {}", exe.display());
            }
            #[cfg(windows)]
            {
                if let Some(local) = dirs::data_local_dir() {
                    let dbg = local.join("aresbird-target").join("debug").join("ares.exe");
                    let rel = local
                        .join("aresbird-target")
                        .join("release")
                        .join("ares.exe");
                    println!(
                        "build tip:   {}",
                        if rel.exists() {
                            rel.display().to_string()
                        } else if dbg.exists() {
                            dbg.display().to_string()
                        } else {
                            "cargo build -p ares-cli --release  → %LOCALAPPDATA%\\aresbird-target\\release\\ares.exe".to_string()
                        }
                    );
                }
            }
            let raw = cfg!(all(feature = "raw", target_os = "linux"));
            println!(
                "raw/syn:     {}",
                if raw {
                    "available (Linux+raw) — true half-open SYN"
                } else {
                    "syn-compat only (aggressive connect; NOT half-open). Linux: --features raw"
                }
            );
            #[cfg(windows)]
            {
                println!("windows:     TCP connect scan; --syn = syn-compat (not Nmap -sS)");
                println!("windows:     UDP silence → open|filtered (no ICMP port-unreachable)");
                println!("windows:     traceroute = TCP TTL / OS tracert best-effort");
                println!("windows:     set CARGO_TARGET_DIR=%LOCALAPPDATA%\\aresbird-target (SAC)");
            }
            #[cfg(not(windows))]
            {
                println!("platform:    ICMP/UDP semantics depend on privileges + OS stack");
            }
            println!("modes:       quiet|normal|fast|insane|stealth");
            println!("path profiles: default|api|web|all");
            println!("fingerprint: soft OS hints (TTL/banner/SMB) — not Nmap -O");
            println!("talk --repl: http|https|redis duplex; ssh = observe-only (no shell)");
            println!("install:     cargo install --path crates/ares-cli  OR GitHub Releases");
            println!(
                "packs:       default | web | infra | cloud | db | exposure  (ares scripts list)"
            );
            println!("baseline:    ares report baseline set | ares report delta");
            for (k, label) in [
                ("ARES_DATA_DIR", "store directory"),
                ("ARES_STORE_PATH", "runs.db path"),
                ("ARES_WORKSPACE", "living workspace id"),
                ("ARES_PACKS_DIR", "NSE script packs root"),
                ("ARES_PLUGIN_PREFER_COMMAND", "prefer script plugins"),
                ("ARES_QUIET", "quiet output"),
                ("ARES_NOTIFY_URL", "CI webhook (scripts)"),
            ] {
                match std::env::var(k) {
                    Ok(v) => println!("env {k}: {v} ({label})"),
                    Err(_) => println!("env {k}: (unset) — {label}"),
                }
            }
            println!(
                "workspace:   {workspace_id}{}",
                if ephemeral { " (ephemeral)" } else { "" }
            );
            match RunStore::open_default() {
                Ok(store) => match store.count() {
                    Ok(n) => println!("store:       {} ({} runs)", store.path().display(), n),
                    Err(e) => println!("store:       {} (count err: {e})", store.path().display()),
                },
                Err(e) => println!("store:       open failed ({e})"),
            }
            println!(
                "hint: ares scripts list | ares probe quick 127.0.0.1 | ares report workspace"
            );
            #[cfg(windows)]
            println!(
                "PATH tip:    $env:Path = \"$env:LOCALAPPDATA\\aresbird-target\\debug;$env:Path\""
            );
        }
        Commands::Serve {
            bind,
            token,
            allow_remote_no_auth,
            tls_cert,
            tls_key,
        } => {
            serve::run(serve::ServeOpts {
                bind,
                token,
                workspace: workspace_id,
                allow_remote_no_auth,
                tls_cert,
                tls_key,
            })
            .await?;
        }
        Commands::Plugin { action } => match action {
            PluginCmd::List { cap } => {
                let filter_cap =
                    cap.as_deref()
                        .and_then(|s| match s.to_ascii_lowercase().as_str() {
                            "passive" => Some(Capability::Passive),
                            "discover" | "recon" => Some(Capability::Discover),
                            "scan" => Some(Capability::Scan),
                            "interact" | "talk" => Some(Capability::Interact),
                            "active" | "activetest" | "test" | "misconfig" => {
                                Some(Capability::ActiveTest)
                            }
                            _ => None,
                        });
                if cap.is_some() && filter_cap.is_none() {
                    anyhow::bail!(
                        "unknown capability `{cap}` — use passive|discover|scan|interact|active",
                        cap = cap.as_deref().unwrap_or("")
                    );
                }
                println!("{:<20} {:<40} DESCRIPTION", "NAME", "CAPABILITIES");
                for m in registry.list() {
                    if let Some(c) = filter_cap {
                        if !m.capabilities().contains(&c) {
                            continue;
                        }
                    }
                    let caps: Vec<_> = m.capabilities().iter().map(|c| format!("{c:?}")).collect();
                    println!(
                        "{:<20} {:<40} {}",
                        m.name(),
                        caps.join(","),
                        m.description()
                    );
                }
                let discovered = ares_plugin_api::discover_plugin_dir(&plugins_root);
                if !discovered.is_empty() {
                    println!(
                        "\nDiscovered plugin manifests in {}:",
                        plugins_root.display()
                    );
                    for d in discovered {
                        let caps = d.manifest.capabilities.join(",");
                        println!(
                            "  - {} [{}] ({})",
                            d.manifest.name,
                            if caps.is_empty() { "passive" } else { &caps },
                            d.dir.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                        );
                    }
                }
            }
            PluginCmd::Info { name } => {
                if let Some(m) = registry.get(&name) {
                    println!("name: {}", m.name());
                    println!("description: {}", m.description());
                    println!("api: {}", m.api_version());
                    println!("capabilities: {:?}", m.capabilities());
                    println!("permissions: {:?}", m.permissions());
                }
                let discovered = ares_plugin_api::discover_plugin_dir(&plugins_root);
                if let Some(d) = discovered.iter().find(|d| {
                    d.manifest.name == name || d.manifest.aliases.iter().any(|a| a == &name)
                }) {
                    println!("manifest: {}", d.dir.join("plugin.json").display());
                    if let Some(v) = &d.manifest.version {
                        println!("version: {v}");
                    }
                    if let Some(a) = &d.manifest.author {
                        println!("author: {a}");
                    }
                    if !d.manifest.aliases.is_empty() {
                        println!("aliases: {}", d.manifest.aliases.join(", "));
                    }
                    if let Some(c) = &d.manifest.command {
                        println!("command: {c}");
                    }
                    if let Some(l) = &d.manifest.library {
                        println!("library: {l}");
                    }
                    if let Some(p) = &d.manifest.prefer {
                        println!("prefer: {p}");
                    }
                    if let Some(e) = &d.manifest.emit {
                        println!("emit: {e}");
                    }
                    if !d.manifest.default_ports.is_empty() {
                        println!("default_ports: {:?}", d.manifest.default_ports);
                    }
                    if registry.get(&name).is_none() {
                        println!("(not loaded into registry — check library/command)");
                    }
                } else if registry.get(&name).is_none() {
                    anyhow::bail!("unknown module: {name}");
                }
            }
            PluginCmd::Run {
                name,
                targets,
                ports,
                extra,
            } => {
                let extra_map = if let Some(raw) = extra {
                    let v: serde_json::Value = serde_json::from_str(&raw)
                        .map_err(|e| anyhow::anyhow!("--extra must be JSON object: {e}"))?;
                    match v {
                        serde_json::Value::Object(m) => m,
                        _ => anyhow::bail!("--extra must be a JSON object"),
                    }
                } else {
                    serde_json::Map::new()
                };
                run_module(
                    &registry,
                    &name,
                    targets,
                    ports,
                    mode,
                    &renderer,
                    true,
                    cli.save,
                    extra_map,
                    ephemeral,
                    &workspace_id,
                )
                .await?;
            }
        },
        Commands::Report { action } => {
            report_cmd::handle(action, color, &workspace_id)?;
        }
        Commands::Pipeline { action } => match action {
            PipelineCmd::Run {
                file,
                resume,
                from_step,
                vars,
            } => {
                let mut cli_vars = Vec::new();
                for v in vars {
                    let (k, val) = v
                        .split_once('=')
                        .ok_or_else(|| anyhow::anyhow!("--var expects KEY=VALUE, got `{v}`"))?;
                    cli_vars.push((k.to_string(), val.to_string()));
                }
                pipeline::run_pipeline(
                    &file,
                    mode,
                    &renderer,
                    &registry,
                    true,
                    cli.save,
                    resume.as_deref(),
                    from_step,
                    &cli_vars,
                )
                .await
                .and_then(|(c, g)| {
                    if !ephemeral {
                        workspace::merge_and_save(&workspace_id, &c, &g, quiet)?;
                    }
                    Ok(())
                })?;
            }
        },
        Commands::Probe {
            profile,
            targets,
            fail_on_new,
            min_severity,
            script_pack,
        } => {
            probe_cmd::probe(
                &registry,
                profile,
                targets,
                fail_on_new,
                min_severity,
                script_pack,
                mode,
                renderer.clone(),
                format,
                cli.save,
                quiet,
                ephemeral,
                &workspace_id,
            )
            .await?;
        }
        Commands::Watch { action } => match action {
            WatchCmd::Probe {
                profile,
                targets,
                min_severity,
            } => {
                if targets.is_empty() {
                    anyhow::bail!("ares watch probe needs at least one target");
                }
                let min_rank = parse_min_severity(&min_severity)?;
                watch::watch_probe(
                    &profile,
                    targets,
                    &registry,
                    watch::WatchOpts {
                        mode,
                        save: cli.save,
                        ephemeral,
                        workspace: workspace_id.clone(),
                        min_severity_rank: min_rank,
                    },
                )
                .await?;
            }
            WatchCmd::Pipeline {
                file,
                vars,
                min_severity,
            } => {
                let min_rank = parse_min_severity(&min_severity)?;
                let mut cli_vars = Vec::new();
                for v in vars {
                    let (k, val) = v
                        .split_once('=')
                        .ok_or_else(|| anyhow::anyhow!("--var expects KEY=VALUE, got `{v}`"))?;
                    cli_vars.push((k.to_string(), val.to_string()));
                }
                watch::watch_pipeline_file(
                    &file,
                    &registry,
                    watch::WatchOpts {
                        mode,
                        save: cli.save,
                        ephemeral,
                        workspace: workspace_id.clone(),
                        min_severity_rank: min_rank,
                    },
                    &cli_vars,
                )
                .await?;
            }
        },
        Commands::Discover {
            targets,
            arp,
            ports,
        } => {
            scan_cmd::discover(
                &registry,
                targets,
                arp,
                ports,
                mode,
                &renderer,
                cli.save,
                ephemeral,
                &workspace_id,
            )
            .await?;
        }
        Commands::Scan {
            targets,
            ports,
            udp,
            udp_ports,
            show_closed,
            show_filtered,
            service,
            syn,
            discover,
            pn,
            resume,
            script_pack,
        } => {
            scan_cmd::scan(
                &registry,
                targets,
                ports,
                udp,
                udp_ports,
                show_closed,
                show_filtered,
                service,
                syn,
                discover,
                pn,
                resume,
                script_pack,
                mode,
                renderer.clone(),
                cli.save,
                quiet,
                ephemeral,
                &workspace_id,
            )
            .await?;
        }
        Commands::Scripts { action } => match action {
            ScriptsCmd::List { pack } => {
                let root = script_pack::resolve_packs_root();
                println!("packs root: {}", root.display());
                let packs = script_pack::list_packs(&root);
                if packs.is_empty() {
                    println!("(no packs found — expected packs/<id>/pack.json)");
                }
                for (id, meta) in &packs {
                    if let Some(f) = pack.as_deref() {
                        if id != f {
                            continue;
                        }
                    }
                    println!(
                        "\n{id}  v{}  safe={}  {}",
                        meta.version.as_deref().unwrap_or("-"),
                        meta.safe,
                        meta.description.as_deref().unwrap_or("")
                    );
                    for s in script_pack::list_scripts(&root, Some(id)) {
                        let ports = if s.ports.is_empty() {
                            "*".into()
                        } else {
                            s.ports
                                .iter()
                                .map(|p| p.to_string())
                                .collect::<Vec<_>>()
                                .join(",")
                        };
                        println!(
                            "  · {:<14} [{:<7}] ports={:<16} {}",
                            s.name, s.kind, ports, s.description
                        );
                    }
                }
            }
            ScriptsCmd::Info { name } => {
                let root = script_pack::resolve_packs_root();
                let scripts = script_pack::list_scripts(&root, None);
                let matches: Vec<_> = scripts
                    .iter()
                    .filter(|s| s.name == name || s.pack == name)
                    .collect();
                if matches.is_empty() {
                    anyhow::bail!("no pack/script named `{name}` (try: ares scripts list)");
                }
                for s in matches {
                    println!("pack:        {}", s.pack);
                    println!("name:        {}", s.name);
                    println!("kind:        {}", s.kind);
                    println!("description: {}", s.description);
                    println!("ports:       {:?}", s.ports);
                    println!("categories:  {:?}", s.categories);
                    println!();
                }
            }
        },
        Commands::Asn { targets } => {
            run_module(
                &registry,
                "asn",
                targets,
                vec![],
                mode,
                &renderer,
                true,
                cli.save,
                serde_json::Map::new(),
                ephemeral,
                &workspace_id,
            )
            .await?;
        }
        Commands::Service { targets, ports } => {
            let port_list = parse_ports(&ports)?;
            run_module(
                &registry,
                "service",
                targets,
                port_list,
                mode,
                &renderer,
                false,
                cli.save,
                serde_json::Map::new(),
                ephemeral,
                &workspace_id,
            )
            .await?;
        }
        Commands::Fp { targets, ports } => {
            let port_list = parse_ports(&ports)?;
            run_module(
                &registry,
                "fingerprint",
                targets,
                port_list,
                mode,
                &renderer,
                false,
                cli.save,
                serde_json::Map::new(),
                ephemeral,
                &workspace_id,
            )
            .await?;
        }
        Commands::Talk {
            target,
            proto,
            session,
            follow,
            repl,
        } => {
            if repl {
                talk_repl::run_talk_repl(talk_repl::ReplOpts {
                    target,
                    proto,
                    mode,
                    renderer: renderer.clone(),
                    save: cli.save,
                    ephemeral,
                    workspace: workspace_id.clone(),
                })
                .await?;
            } else {
                let mut extra = serde_json::Map::new();
                extra.insert("proto".into(), serde_json::Value::String(proto));
                let session = session || follow.as_ref().is_some_and(|v| !v.is_empty());
                extra.insert("session".into(), serde_json::Value::Bool(session));
                if let Some(paths) = follow {
                    extra.insert(
                        "follow_paths".into(),
                        serde_json::Value::Array(
                            paths.into_iter().map(serde_json::Value::String).collect(),
                        ),
                    );
                }
                run_module(
                    &registry,
                    "talk",
                    vec![target],
                    vec![],
                    mode,
                    &renderer,
                    false,
                    cli.save,
                    extra,
                    ephemeral,
                    &workspace_id,
                )
                .await?;
            }
        }
        Commands::Recon {
            targets,
            ports,
            no_skim,
        } => {
            let port_list = parse_ports(&ports)?;
            let mut extra = serde_json::Map::new();
            extra.insert("skim_ports".into(), serde_json::Value::Bool(!no_skim));
            run_module(
                &registry,
                "recon",
                targets,
                port_list,
                mode,
                &renderer,
                false,
                cli.save,
                extra,
                ephemeral,
                &workspace_id,
            )
            .await?;
        }
        Commands::Test {
            targets,
            ports,
            no_path_probes,
            path_delay_ms,
            path_profile,
            paths_file,
            baseline,
            compare,
            new_only,
            fail_on_new,
            fail_on_any,
            min_severity,
            notify,
            notify_on,
        } => {
            probe_cmd::test(
                &registry,
                targets,
                ports,
                no_path_probes,
                path_delay_ms,
                path_profile,
                paths_file,
                baseline,
                compare,
                new_only,
                fail_on_new,
                fail_on_any,
                min_severity,
                notify,
                notify_on,
                mode,
                renderer.clone(),
                format,
                cli.save,
                quiet,
                ephemeral,
                &workspace_id,
            )
            .await?;
        }
        Commands::Path { targets, max_hops } => {
            let mut extra = serde_json::Map::new();
            extra.insert("max_hops".into(), serde_json::Value::from(max_hops));
            run_module(
                &registry,
                "path",
                targets,
                vec![],
                mode,
                &renderer,
                true,
                cli.save,
                extra,
                ephemeral,
                &workspace_id,
            )
            .await?;
        }
        Commands::Proto { action } => {
            run_proto(
                action,
                mode,
                &renderer,
                &registry,
                cli.save,
                ephemeral,
                &workspace_id,
            )
            .await?;
        }
    }

    Ok(())
}

/// Rebuild an EventCollector from HostFinding rows on a living workspace graph.
pub(crate) fn collector_from_graph_findings(
    graph: &ares_core::AssetGraph,
) -> ares_core::EventCollector {
    let mut c = ares_core::EventCollector::new();
    for (addr, host) in &graph.hosts {
        for f in &host.findings {
            c.push(Event::MisconfigFinding {
                addr: *addr,
                port: f.port,
                finding: f.finding.clone(),
                severity: f.severity.clone(),
            });
        }
    }
    c
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "ares=warn,ares_net=warn",
        1 => "ares=info,ares_net=info,ares_modules=info",
        _ => "ares=debug,ares_net=debug,ares_modules=debug,ares_proto=debug",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_module(
    registry: &PluginRegistry,
    name: &str,
    targets: Vec<String>,
    ports: Vec<u16>,
    mode: ScanMode,
    renderer: &Renderer,
    active_allowed: bool,
    save: bool,
    extra: serde_json::Map<String, serde_json::Value>,
    ephemeral: bool,
    workspace_id: &str,
) -> anyhow::Result<(ares_core::EventCollector, ares_core::AssetGraph)> {
    run_module_opts(
        registry,
        name,
        targets,
        ports,
        mode,
        renderer,
        active_allowed,
        save,
        extra,
        false,
        ephemeral,
        workspace_id,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_module_opts(
    registry: &PluginRegistry,
    name: &str,
    targets: Vec<String>,
    ports: Vec<u16>,
    mode: ScanMode,
    renderer: &Renderer,
    active_allowed: bool,
    save: bool,
    extra: serde_json::Map<String, serde_json::Value>,
    suppress_summary: bool,
    ephemeral: bool,
    workspace_id: &str,
) -> anyhow::Result<(ares_core::EventCollector, ares_core::AssetGraph)> {
    let module = registry
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("module not found: {name}"))?;

    if targets.is_empty() && name != "service" {
        anyhow::bail!("at least one target is required");
    }

    let graph = Arc::new(Mutex::new(ares_core::AssetGraph::new()));
    let collector = Arc::new(Mutex::new(ares_core::EventCollector::new()));
    let cancel = tokio_util::sync::CancellationToken::new();
    let mut job = Job::new(name, mode);
    job.mark_running();
    let job_id = job.id;

    // Ctrl+C — cooperative cancel
    let cancel_c = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("\n[!] cancelling job {job_id}…");
        cancel_c.cancel();
    });

    let live = Arc::new(
        Renderer::new(renderer.format, renderer.color)
            .with_quiet(renderer.quiet)
            .with_port_visibility(renderer.show_closed, renderer.show_filtered)
            .with_min_finding_rank(renderer.min_finding_rank),
    );
    let emit_graph = graph.clone();
    let emit_collector = collector.clone();
    let emit_live = live.clone();
    let emit: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(move |event: Event| {
        emit_graph.lock().apply(&event);
        emit_collector.lock().push(event.clone());
        emit_live.print_event_live(&event);
    });

    emit(Event::JobStarted {
        job_id,
        started_at: job.started_at.unwrap_or_else(Utc::now),
    });

    let ctx = ModuleCtx {
        cancel: cancel.clone(),
        mode,
        targets,
        ports,
        graph: graph.clone(),
        emit: emit.clone(),
        active_allowed,
        extra,
    };

    if !renderer.quiet {
        eprintln!("→ module {} (job {job_id})", module.name());
    }

    let pb = if !renderer.quiet
        && matches!(renderer.format, OutputFormat::Table | OutputFormat::Plain)
    {
        let pb = indicatif::ProgressBar::new_spinner();
        pb.set_style(
            indicatif::ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
        );
        pb.set_message(format!("running {}…", module.name()));
        pb.enable_steady_tick(std::time::Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    let result = module.run(ctx).await;

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    let cancelled = cancel.is_cancelled();
    let status = match &result {
        Ok(()) if cancelled => {
            job.mark_cancelled();
            "cancelled".to_string()
        }
        Ok(()) => {
            job.mark_completed();
            "completed".to_string()
        }
        Err(e) if cancelled => {
            job.mark_cancelled();
            format!("cancelled ({e})")
        }
        Err(e) => {
            job.mark_failed(e.to_string());
            format!("failed: {e}")
        }
    };

    emit(Event::JobFinished {
        job_id,
        finished_at: job.finished_at.unwrap_or_else(Utc::now),
        status: status.clone(),
    });

    if !cancelled {
        result?;
    }

    let collector_out = collector.lock().clone();
    let graph_out = graph.lock().clone();
    if !suppress_summary {
        renderer.render_summary(&collector_out, &graph_out);
    }

    if save {
        let store = RunStore::open_default()?;
        let id = store.save(name, &collector_out, &graph_out)?;
        if !renderer.quiet {
            eprintln!("saved run {id}");
        } else {
            eprintln!("# saved {id}");
        }
    }

    if !ephemeral {
        workspace::merge_and_save(workspace_id, &collector_out, &graph_out, renderer.quiet)?;
    }

    if cancelled && !renderer.quiet {
        eprintln!("job {job_id} cancelled — partial results above");
    }

    Ok((collector_out, graph_out))
}

/// Catalog for `ares proto list` — (name, default_port, notes).
const PROTO_CATALOG: &[(&str, Option<u16>, &str)] = &[
    ("dns", None, "resolve / DNS enrich"),
    ("http", Some(80), "HTTP GET"),
    ("h2", Some(443), "HTTP/2 ALPN or h2c"),
    ("ssh", Some(22), "SSH banner"),
    ("tls", Some(443), "TLS observe + fingerprint"),
    ("smb", Some(445), "SMB negotiate"),
    ("ftp", Some(21), "FTP banner"),
    ("smtp", Some(25), "SMTP banner"),
    ("imap", Some(143), "IMAP greeting"),
    ("pop3", Some(110), "POP3 greeting"),
    ("redis", Some(6379), "PING / INFO"),
    ("mysql", Some(3306), "MySQL/MariaDB greeting"),
    ("postgres", Some(5432), "SSLRequest + startup"),
    ("mongodb", Some(27017), "isMaster / hello"),
    ("elasticsearch", Some(9200), "GET / cluster+version"),
    ("memcached", Some(11211), "version / stats"),
    ("kafka", Some(9092), "ApiVersions"),
    ("amqp", Some(5672), "AMQP 0-9-1 Connection.Start"),
    ("mqtt", Some(1883), "MQTT 3.1.1 CONNECT"),
    ("nats", Some(4222), "INFO greeting"),
    ("ldap", Some(389), "RootDSE search"),
    ("kerberos", Some(88), "AS-REQ realm observe"),
    ("vnc", Some(5900), "RFB banner + security types"),
    ("winrm", Some(5985), "POST /wsman (5986=HTTPS)"),
    ("snmp", Some(161), "UDP v2c GET sysDescr (community=public)"),
    ("docker", Some(2375), "Docker Engine /_ping + /version"),
    ("etcd", Some(2379), "etcd /version + /health"),
    ("consul", Some(8500), "Consul /v1/status/leader"),
    ("mssql", Some(1433), "TDS PreLogin version/encrypt"),
    ("kubernetes", Some(6443), "HTTPS /version|/readyz"),
    ("oracle", Some(1521), "TNS CONNECT_DATA=(COMMAND=version)"),
    ("couchdb", Some(5984), "GET / welcome JSON"),
    ("zookeeper", Some(2181), "ruok / srvr four-letter"),
    ("cassandra", Some(9042), "native OPTIONS → SUPPORTED"),
    ("rdp", Some(3389), "TPKT + X.224 + negotiation"),
    ("neo4j", Some(7474), "GET / discovery JSON"),
    ("clickhouse", Some(8123), "GET /ping + SELECT version()"),
    ("minio", Some(9000), "health/live + S3 markers"),
    ("bolt", Some(7687), "Neo4j Bolt handshake"),
    ("rabbitmq", Some(15672), "Management UI/API"),
    ("grafana", Some(3000), "GET /api/health"),
    ("kibana", Some(5601), "GET /api/status + kbn-*"),
    ("prometheus", Some(9090), "/-/healthy + buildinfo"),
    ("jenkins", Some(8080), "X-Jenkins /login"),
    ("keycloak", Some(8080), "GET /realms/master"),
    ("portainer", Some(9000), "GET /api/system/status"),
    ("argocd", Some(8080), "GET /api/version"),
    (
        "sonarqube",
        Some(9000),
        "GET /api/system/status|/api/server/version",
    ),
    (
        "influxdb",
        Some(8086),
        "/health + /ping (X-Influxdb-Version)",
    ),
    ("rethinkdb", Some(28015), "V0_4 JSON handshake"),
    (
        "scylla",
        Some(10000),
        "REST /storage_service/scylla_release_version",
    ),
    ("elastic-apm", Some(8200), "APM Server root ok.version"),
    (
        "grpc",
        Some(50051),
        "HTTP/2 preface + application/grpc probe",
    ),
    ("vault", Some(8200), "GET /v1/sys/health"),
    ("nomad", Some(4646), "GET /v1/agent/self|/v1/status/leader"),
    ("solr", Some(8983), "GET /solr/admin/info/system"),
    ("hazelcast", Some(5701), "GET /hazelcast/rest/cluster"),
    ("opensearch", Some(9200), "GET / OpenSearch distribution"),
];

async fn run_proto(
    action: ProtoCmd,
    mode: ScanMode,
    renderer: &Renderer,
    registry: &PluginRegistry,
    save: bool,
    ephemeral: bool,
    workspace_id: &str,
) -> anyhow::Result<()> {
    match action {
        ProtoCmd::List => {
            println!("{:<16} {:>6}  NOTES", "PROTO", "PORT");
            for (name, port, notes) in PROTO_CATALOG {
                let p = port.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
                println!("{name:<16} {p:>6}  {notes}");
            }
            println!();
            println!("Port presets for -p / --ports:");
            for (name, desc) in ares_core::port_preset_names() {
                println!("  {name:<10} {desc}");
            }
            println!();
            println!("Examples:");
            println!("  ares proto redis 127.0.0.1");
            println!("  ares proto grafana 127.0.0.1");
            println!("  ares proto snmp 127.0.0.1 --community public");
            println!("  ares talk dc.lab.local --proto kerberos");
            println!("  ares scan 127.0.0.1 -p apps --service");
        }
        ProtoCmd::Dns { name } => {
            let mut extra = serde_json::Map::new();
            extra.insert("proto".into(), serde_json::Value::String("dns".into()));
            run_module(
                registry,
                "talk",
                vec![name],
                vec![],
                mode,
                renderer,
                true,
                save,
                extra,
                ephemeral,
                workspace_id,
            )
            .await?;
        }
        ProtoCmd::Http { target, path } => {
            let mut extra = serde_json::Map::new();
            extra.insert("proto".into(), serde_json::Value::String("http".into()));
            let url = if target.starts_with("http://") || target.starts_with("https://") {
                target
            } else if path == "/" {
                format!("http://{target}/")
            } else {
                format!("http://{target}{path}")
            };
            run_module(
                registry,
                "talk",
                vec![url],
                vec![],
                mode,
                renderer,
                true,
                save,
                extra,
                ephemeral,
                workspace_id,
            )
            .await?;
        }
        ProtoCmd::Snmp { target, community } => {
            let mut extra = serde_json::Map::new();
            extra.insert("proto".into(), serde_json::Value::String("snmp".into()));
            extra.insert("community".into(), serde_json::Value::String(community));
            run_module(
                registry,
                "talk",
                vec![target],
                vec![],
                mode,
                renderer,
                true,
                save,
                extra,
                ephemeral,
                workspace_id,
            )
            .await?;
        }
        ProtoCmd::Observe(args) => {
            if args.len() < 2 {
                anyhow::bail!("usage: ares proto <name> <target>  (try: ares proto list)");
            }
            let proto = args[0].to_ascii_lowercase();
            let target = args[1].clone();
            // Prefer catalog names; also accept talk aliases (k8s, zk, …).
            let known = PROTO_CATALOG.iter().any(|(n, _, _)| *n == proto)
                || matches!(
                    proto.as_str(),
                    "k8s"
                        | "zk"
                        | "cql"
                        | "ch"
                        | "s3"
                        | "rmq"
                        | "rabbitmq-mgmt"
                        | "mstsc"
                        | "tns"
                        | "couch"
                        | "prom"
                );
            if !known {
                eprintln!(
                    "warning: unknown proto '{proto}' — passing to talk (see ares proto list)"
                );
            }
            run_talk_proto(
                registry,
                &proto,
                target,
                mode,
                renderer,
                save,
                ephemeral,
                workspace_id,
            )
            .await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_talk_proto(
    registry: &PluginRegistry,
    proto: &str,
    target: String,
    mode: ScanMode,
    renderer: &Renderer,
    save: bool,
    ephemeral: bool,
    workspace_id: &str,
) -> anyhow::Result<()> {
    let mut extra = serde_json::Map::new();
    extra.insert("proto".into(), serde_json::Value::String(proto.into()));
    run_module(
        registry,
        "talk",
        vec![target],
        vec![],
        mode,
        renderer,
        true,
        save,
        extra,
        ephemeral,
        workspace_id,
    )
    .await?;
    Ok(())
}

// silence unused import warning for ValueEnum if any
#[allow(dead_code)]
fn _unused(_: ScanModeHint) {}

#[derive(Clone, ValueEnum)]
enum ScanModeHint {
    Quiet,
    Normal,
    Fast,
    Insane,
    Stealth,
}
