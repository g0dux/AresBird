//! AresBird CLI — network interaction Swiss-army knife.

mod brand;
mod pipeline;
mod script_pack;
mod talk_repl;
mod watch;
mod workspace;

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use ares_core::event::Event;
use ares_core::job::Job;
use ares_core::parse_ports;
use ares_core::timing::ScanMode;
use ares_modules::builtin_registry;
use ares_output::{
    diff_collectors, diff_findings, filter_diff_by_severity, filter_findings_collapsed,
    findings_diff_to_csv, findings_diff_to_csv_filtered, findings_to_csv_min, parse_min_severity,
    OutputFormat, Renderer, RunStore,
};
use ares_plugin_api::{register_discovered, Capability, ModuleCtx, PluginRegistry};
use ares_proto::post_json;
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
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

#[derive(Subcommand, Debug)]
enum Commands {
    /// Discover live hosts
    Discover {
        /// Targets (IP, hostname, CIDR)
        targets: Vec<String>,
        /// Prefer ARP/L2 sweep (Linux + `ares-net` feature `raw`; needs CAP_NET_RAW)
        #[arg(long)]
        arp: bool,
        /// TCP probe ports for hosts that don't answer ICMP (default: 80,443,22,135,445,3389,8080)
        #[arg(short, long)]
        ports: Option<String>,
    },
    /// Port scan (TCP connect; optional UDP)
    Scan {
        /// Targets (IP, hostname, CIDR)
        targets: Vec<String>,
        /// Ports: `22`, `80,443`, `1-1024`, `top100`, `top1000`, `apps`, `infra`, `web`, `all`
        #[arg(short, long, default_value = "top100")]
        ports: String,
        /// Also run selective UDP probes (timeout without reply = open|filtered; no ICMP on Windows)
        #[arg(long)]
        udp: bool,
        /// UDP ports for `--udp` (default: built-in UDP_TOP). Same syntax as `-p`.
        #[arg(long)]
        udp_ports: Option<String>,
        /// Show closed ports in live/table output
        #[arg(long)]
        show_closed: bool,
        /// Show filtered / open|filtered ports in live/table output
        #[arg(long)]
        show_filtered: bool,
        /// Follow up with service detection on opens
        #[arg(long)]
        service: bool,
        /// Prefer SYN engine: true half-open on Linux+raw; elsewhere syn-compat (aggressive connect, not half-open)
        #[arg(long)]
        syn: bool,
        /// Run host discovery first; scan only live hosts
        #[arg(long)]
        discover: bool,
        /// Treat all targets as up (skip discovery). Default without `--discover`; useful to force scan after empty discover
        #[arg(long, alias = "skip-discover")]
        pn: bool,
        /// Resume from a previous saved run id (skip already-scanned pairs)
        #[arg(long)]
        resume: Option<String>,
        /// Opt-in NSE-style script pack after open ports (e.g. `default`)
        #[arg(long, value_name = "PACK")]
        script_pack: Option<String>,
    },
    /// List / inspect optional NSE-style script packs
    Scripts {
        #[command(subcommand)]
        action: ScriptsCmd,
    },
    /// ASN / CDN enrichment
    Asn { targets: Vec<String> },
    /// Service / banner detection
    Service {
        targets: Vec<String>,
        #[arg(short, long, default_value = "top100")]
        ports: String,
    },
    /// TLS + service fingerprint / soft OS hints
    Fp {
        targets: Vec<String>,
        #[arg(short, long, default_value = "22,80,443,445,8443")]
        ports: String,
    },
    /// Talk to a service (HTTP/H2/DNS/SSH/TLS/SMB + app observes)
    Talk {
        target: String,
        #[arg(long, default_value = "auto")]
        proto: String,
        /// Keep HTTP cookie jar across redirects + follow-up GETs (observe-only)
        #[arg(long)]
        session: bool,
        /// Extra paths to GET under one session (comma-separated). Implies `--session`.
        #[arg(long, value_delimiter = ',')]
        follow: Option<Vec<String>>,
        /// Interactive observe REPL (`--proto http|https|redis|ssh`, auto from URL/port)
        #[arg(long)]
        repl: bool,
    },
    /// Intent probe: discover→scan→service→misconfig for a profile
    Probe {
        /// Profile: web | apps | infra | quick
        profile: String,
        /// Targets (IP, hostname, CIDR)
        targets: Vec<String>,
        /// Exit 2 if new findings vs last saved probe/misconfig run (implies --save compare)
        #[arg(long)]
        fail_on_new: bool,
        #[arg(long, default_value = "medium")]
        min_severity: String,
        /// After profile steps, run NSE-style pack on open ports
        #[arg(long, value_name = "PACK")]
        script_pack: Option<String>,
    },
    /// Live TUI while a probe or pipeline runs
    Watch {
        #[command(subcommand)]
        action: WatchCmd,
    },
    /// DNS / subdomain recon (Amass-style lite)
    Recon {
        /// Domain or IP
        targets: Vec<String>,
        #[arg(short, long, default_value = "top100")]
        ports: String,
        /// Skip port skim after DNS
        #[arg(long)]
        no_skim: bool,
    },
    /// Active misconfig checks
    Test {
        targets: Vec<String>,
        #[arg(
            short,
            long,
            default_value = "21,80,88,161,389,443,1433,1521,1883,2181,2375,2379,3000,3389,4222,5601,5672,5900,5984,5985,6379,6443,7474,7687,8080,8123,8500,9000,9042,9090,9092,9200,11211,15672,27017"
        )]
        ports: String,
        /// Skip sensitive path probes
        #[arg(long)]
        no_path_probes: bool,
        /// Delay between sensitive path probes (ms)
        #[arg(long, default_value_t = 120)]
        path_delay_ms: u64,
        /// Path wordlist profile: default|api|web|all
        #[arg(long, default_value = "default")]
        path_profile: String,
        /// Extra paths file (# comments, one path per line)
        #[arg(long)]
        paths_file: Option<PathBuf>,
        /// Baseline run UUID for findings compare
        #[arg(long)]
        baseline: Option<String>,
        /// Auto-compare against last saved `active-misconfig` run
        #[arg(long)]
        compare: bool,
        /// With baseline/compare: only show newly added findings
        #[arg(long)]
        new_only: bool,
        /// Exit 2 if there are new findings vs baseline (implies --compare if no --baseline)
        #[arg(long)]
        fail_on_new: bool,
        /// Exit 2 if the current run has any findings (no baseline needed)
        #[arg(long)]
        fail_on_any: bool,
        /// Minimum severity to show/fail on: info|low|medium|high (default: info)
        #[arg(long, default_value = "info")]
        min_severity: String,
        /// POST JSON webhook when notify condition matches
        #[arg(long)]
        notify: Option<String>,
        /// When to fire --notify: new (default), any, always
        #[arg(long, value_enum, default_value_t = NotifyOn::New)]
        notify_on: NotifyOn,
    },
    /// Traceroute / path to target
    Path {
        targets: Vec<String>,
        #[arg(long, default_value_t = 30)]
        max_hops: u8,
    },
    /// Low-level protocol helpers
    Proto {
        #[command(subcommand)]
        action: ProtoCmd,
    },
    /// List built-in plugins/modules
    Plugin {
        #[command(subcommand)]
        action: PluginCmd,
    },
    /// Show / diff stored reports
    Report {
        #[command(subcommand)]
        action: ReportCmd,
    },
    /// Run a YAML pipeline playbook
    Pipeline {
        #[command(subcommand)]
        action: PipelineCmd,
    },
    /// Print version / engine info
    Version,
    /// Diagnose environment (store, features, modes)
    Doctor,
}

#[derive(Subcommand, Debug)]
enum ScriptsCmd {
    /// List packs and their scripts/builtins
    List {
        /// Only show one pack id
        #[arg(long)]
        pack: Option<String>,
    },
    /// Show details for a pack or script name
    Info {
        /// `pack-id` or `script-name` (searches all packs)
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum WatchCmd {
    /// Watch an intent probe profile
    Probe {
        /// Profile: web | apps | infra | quick
        profile: String,
        targets: Vec<String>,
        #[arg(long, default_value = "info")]
        min_severity: String,
    },
    /// Watch a YAML pipeline playbook
    Pipeline {
        file: PathBuf,
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
        #[arg(long, default_value = "info")]
        min_severity: String,
    },
}

#[derive(Subcommand, Debug)]
enum PluginCmd {
    /// List registered modules (built-in + discovered plugins)
    List {
        /// Filter by capability: passive|discover|scan|interact|active
        #[arg(long)]
        cap: Option<String>,
    },
    /// Show details for a registered module or on-disk manifest
    Info { name: String },
    /// Run a registered module/plugin by name
    Run {
        name: String,
        targets: Vec<String>,
        /// Ports passed to the module (comma-separated or repeated)
        #[arg(short = 'p', long = "ports", value_delimiter = ',')]
        ports: Vec<u16>,
        /// Extra JSON object for plugins (e.g. '{"path":"/admin"}')
        #[arg(long)]
        extra: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum ReportCmd {
    Last {
        #[arg(long, default_value = "table")]
        format: String,
        /// Minimum severity in FINDINGS: info|low|medium|high
        #[arg(long, default_value = "info")]
        min_severity: String,
    },
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Filter by name substring (e.g. `scan`, `active-misconfig`)
        #[arg(long)]
        name: Option<String>,
    },
    /// Show store path + counts / stats for one run
    Show {
        /// Run UUID (default: last run)
        run_id: Option<String>,
    },
    /// Show the living workspace graph summary
    Workspace {
        /// Workspace name (default: global --workspace / ARES_WORKSPACE / default)
        name: Option<String>,
    },
    /// Delete a stored run by UUID
    Delete {
        run_id: String,
    },
    /// Delete older runs, keeping the newest N
    Prune {
        #[arg(long, default_value_t = 20)]
        keep: usize,
        /// Only prune runs whose name matches (exact)
        #[arg(long)]
        name: Option<String>,
    },
    Diff {
        run_a: String,
        run_b: String,
    },
    /// Diff misconfig findings between two runs (baseline → current)
    DiffFindings {
        run_a: String,
        run_b: String,
        #[arg(long, default_value = "table")]
        format: String,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Minimum severity in diff: info|low|medium|high
        #[arg(long, default_value = "info")]
        min_severity: String,
    },
    /// Export findings from a stored run (default: CSV to stdout or --out)
    Export {
        /// Run UUID (default: last run)
        run_id: Option<String>,
        #[arg(long, default_value = "csv")]
        format: String,
        /// Write to file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
        /// Minimum severity to export: info|low|medium|high
        #[arg(long, default_value = "info")]
        min_severity: String,
    },
    /// Export asset relations (DNS→IP, open ports, paths) as Mermaid or JSON
    Graph {
        /// Run UUID (default: last run). Ignored with `--workspace`.
        run_id: Option<String>,
        /// Use living workspace graph instead of a saved run
        #[arg(long)]
        workspace: bool,
        /// Workspace name when `--workspace` (default: global workspace id)
        #[arg(long)]
        workspace_name: Option<String>,
        /// mermaid | json
        #[arg(long, default_value = "mermaid")]
        format: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Pin / show / clear the day-to-day findings baseline
    Baseline {
        #[command(subcommand)]
        action: BaselineCmd,
    },
    /// Diff current (or --current UUID) findings vs pinned baseline
    Delta {
        /// Current run UUID (default: newest non-baseline run)
        #[arg(long)]
        current: Option<String>,
        #[arg(long, default_value = "table")]
        format: String,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = "info")]
        min_severity: String,
        /// Exit 2 when there are new findings ≥ min-severity
        #[arg(long)]
        fail_on_new: bool,
    },
}

#[derive(Subcommand, Debug)]
enum BaselineCmd {
    /// Pin a stored run as baseline (default: last run)
    Set { run_id: Option<String> },
    /// Show pinned baseline meta
    Show,
    /// Remove pinned baseline copies
    Clear,
}

#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
enum NotifyOn {
    /// New findings vs baseline; without baseline, any finding ≥ min-severity
    #[default]
    New,
    /// Any finding on the current run ≥ min-severity
    Any,
    /// Always POST after the run
    Always,
}

#[derive(Subcommand, Debug)]
enum PipelineCmd {
    Run {
        file: PathBuf,
        /// Resume from a prior saved run (seeds graph + skip_pairs for scan steps)
        #[arg(long)]
        resume: Option<String>,
        /// Start at step index (0-based); earlier steps are skipped
        #[arg(long)]
        from_step: Option<usize>,
        /// Override pipeline vars (`--var target=10.0.0.5`)
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum ProtoCmd {
    /// List supported protocol observes
    List,
    /// DNS enrich / resolve
    Dns { name: String },
    /// HTTP GET probe
    Http {
        target: String,
        #[arg(long, default_value = "/")]
        path: String,
    },
    /// SNMP v2c sysDescr observe (UDP)
    Snmp {
        target: String,
        /// Community string (default: public)
        #[arg(long, default_value = "public")]
        community: String,
    },
    /// Catalog observe: `ares proto <name> <target>` (see `ares proto list`)
    #[command(external_subcommand)]
    Observe(Vec<String>),
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
    let quiet = cli.quiet || matches!(format, OutputFormat::Csv | OutputFormat::Markdown);
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
        Commands::Report { action } => match action {
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
                    println!("  · {} ({name}): {} finding(s)", h.addr, h.findings.len());
                }
            }
            ReportCmd::Workspace { name } => {
                let wid = name
                    .as_deref()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| workspace_id.clone());
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
                        "  · {} up={} open=[{}] findings={}",
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
                            "findings diff {id_a} → {id_b}: +{} -{} ~{} → {}",
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
                        "Findings diff {id_a} → {id_b}: +{} added, -{} removed, {} unchanged",
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
                        eprintln!("exported findings from {id} → {}", path.display());
                    }
                    (Some(path), OutputFormat::Json) => {
                        let findings =
                            filter_findings_collapsed(collector.findings_collapsed(), min_rank);
                        let json = serde_json::to_string_pretty(&findings)?;
                        std::fs::write(path, json)?;
                        eprintln!("exported findings JSON from {id} → {}", path.display());
                    }
                    (Some(path), OutputFormat::Markdown) => {
                        let md = ares_output::render_markdown(&collector, &graph, min_rank);
                        std::fs::write(path, md)?;
                        eprintln!("exported markdown from {id} → {}", path.display());
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
                        anyhow::bail!("--out supports csv/json/md (use --format csv|json|md)");
                    }
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
                        .unwrap_or_else(|| workspace_id.clone());
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
                    other => anyhow::bail!("unknown graph format `{other}` — use mermaid|json"),
                };
                if let Some(path) = out {
                    std::fs::write(&path, &body)?;
                    eprintln!(
                        "graph from {label} ({format}, {} nodes) → {}",
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
                        println!("pinned baseline ← run {id}");
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
                    anyhow::bail!("no pinned baseline — run: ares report baseline set");
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
                        eprintln!("delta csv → {}", path.display());
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
                                println!("      fix → {fix}");
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
                                "- **{}** `{}:{p}` — {}\n",
                                r.severity, r.host, r.finding
                            ));
                            if let Some(fix) = ares_output::remediation_for(&r.finding) {
                                body.push_str(&format!("  - fix: {fix}\n"));
                            }
                        }
                        std::fs::write(&path, body)?;
                        eprintln!("wrote delta notes → {}", path.display());
                    }
                }
                if fail_on_new && new_n > 0 {
                    std::process::exit(2);
                }
            }
        },
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
            if targets.is_empty() {
                anyhow::bail!("ares probe needs at least one target");
            }
            let save = cli.save || fail_on_new;
            let min_rank = parse_min_severity(&min_severity)?;
            let renderer = renderer.clone().with_min_finding_rank(min_rank);
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
                pipe, &name, mode, &renderer, &registry, true, false, None, None,
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
                let _ = script_pack::run_script_pack(&pack_id, &open, mode, quiet, emit, cancel)
                    .await?;
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
                workspace::merge_and_save(&workspace_id, &collector, &graph, quiet)?;
            }
            if fail_on_new {
                if let Some(bid) = baseline {
                    let new_count =
                        print_findings_delta(bid, &collector, true, format, quiet, min_rank)?;
                    if new_count > 0 {
                        std::process::exit(2);
                    }
                } else if !quiet {
                    eprintln!("fail-on-new: no baseline yet (saved as first run)");
                }
            }
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
                &registry,
                "discover",
                targets,
                probe,
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
            let port_list = parse_ports(&ports)?;
            let mut extra = serde_json::Map::new();
            extra.insert("udp".into(), serde_json::Value::Bool(udp));
            if let Some(up) = udp_ports {
                let list = parse_ports(&up)?;
                extra.insert(
                    "udp_ports".into(),
                    serde_json::Value::Array(
                        list.into_iter().map(serde_json::Value::from).collect(),
                    ),
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
                &registry,
                "scan",
                targets.clone(),
                port_list.clone(),
                mode,
                &renderer,
                true,
                false,
                extra,
                ephemeral,
                &workspace_id,
            )
            .await?;

            // Merge prior + new for save/report continuity
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
                    &registry,
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
                    &workspace_id,
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
                let _ = script_pack::run_script_pack(&pack_id, &open, mode, quiet, emit, cancel)
                    .await?;
                collector = collector_arc.lock().clone();
                graph = graph_arc.lock().clone();
                if !ephemeral {
                    workspace::merge_and_save(&workspace_id, &collector, &graph, quiet)?;
                }
            }

            if cli.save {
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
            let port_list = parse_ports(&ports)?;
            let min_rank = parse_min_severity(&min_severity)?;
            let renderer = renderer.clone().with_min_finding_rank(min_rank);
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
                &registry,
                "active-misconfig",
                targets,
                port_list,
                mode,
                &renderer,
                true,
                cli.save,
                extra,
                suppress,
                ephemeral,
                &workspace_id,
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
                            // Prefer delta keys already printed; rebuild from current − baseline.
                            let store = RunStore::open_default()?;
                            let (base, _) = store.load(*bid)?;
                            let diff =
                                filter_diff_by_severity(diff_findings(&base, &collector), min_rank);
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
                eprintln!(
                    "error: {new_count} new finding(s) ≥ {min_severity} vs baseline (--fail-on-new)"
                );
                std::process::exit(2);
            }
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
async fn run_module(
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
async fn run_module_opts(
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
