//! CLI argument model (clap derives) for the `ares` binary.
//!
//! Extracted from `main.rs` to keep the command surface separate from the
//! dispatch logic. `Cli` (the top-level parser) stays in `main.rs`.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

#[derive(Subcommand, Debug)]
pub enum Commands {
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
            default_value = "21,80,88,161,389,443,1433,1521,1883,2181,2375,2379,3000,3389,4222,5601,5672,5900,5984,5985,6379,6443,7474,7687,8080,8086,8123,8200,8500,9000,9042,9090,9092,9200,10000,11211,15672,27017,28015,50051"
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
    /// Local JSON control-plane HTTP API (workspace / runs / jobs)
    Serve {
        /// Bind address (default: 127.0.0.1:7420)
        #[arg(long, default_value = "127.0.0.1:7420")]
        bind: String,
        /// Optional bearer token (or env ARES_SERVE_TOKEN). Required for non-/healthz when set.
        #[arg(long, env = "ARES_SERVE_TOKEN")]
        token: Option<String>,
        /// Allow non-loopback bind without a token (insecure)
        #[arg(long)]
        allow_remote_no_auth: bool,
        /// PEM certificate (or chain) for HTTPS — requires `--tls-key`
        #[arg(long, env = "ARES_SERVE_TLS_CERT", value_name = "FILE")]
        tls_cert: Option<PathBuf>,
        /// PEM private key for HTTPS — requires `--tls-cert`
        #[arg(long, env = "ARES_SERVE_TLS_KEY", value_name = "FILE")]
        tls_key: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ScriptsCmd {
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
pub enum WatchCmd {
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
pub enum PluginCmd {
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
pub enum ReportCmd {
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
    /// Aggregate finding metrics (severity / category / CWE / rule)
    Metrics {
        /// Run UUID (default: last run). Ignored with `--workspace`.
        run_id: Option<String>,
        /// Read living workspace graph findings instead of a stored run
        #[arg(long)]
        workspace: bool,
        /// Workspace name when `--workspace` (default: global workspace id)
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "table")]
        format: String,
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
pub enum BaselineCmd {
    /// Pin a stored run as baseline (default: last run)
    Set { run_id: Option<String> },
    /// Show pinned baseline meta
    Show,
    /// Remove pinned baseline copies
    Clear,
}

#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NotifyOn {
    /// New findings vs baseline; without baseline, any finding ≥ min-severity
    #[default]
    New,
    /// Any finding on the current run ≥ min-severity
    Any,
    /// Always POST after the run
    Always,
}

#[derive(Subcommand, Debug)]
pub enum PipelineCmd {
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
pub enum ProtoCmd {
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
