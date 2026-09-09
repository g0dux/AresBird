use ares_core::event::{Event, EventCollector};
use ares_core::graph::AssetGraph;
use ares_core::model::PortState;
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement, Table};
use console::style;
use serde::Serialize;

use crate::diff::filter_findings_collapsed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
    Jsonl,
    Plain,
    /// Findings-focused CSV (severity,host,port,peers,finding)
    Csv,
    /// Markdown report (ports, DNS, findings, intel)
    Markdown,
    /// SARIF 2.1.0 findings log (GitHub code scanning / CI security)
    Sarif,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" | "pretty" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "jsonl" | "ndjson" => Ok(OutputFormat::Jsonl),
            "plain" => Ok(OutputFormat::Plain),
            "csv" => Ok(OutputFormat::Csv),
            "md" | "markdown" => Ok(OutputFormat::Markdown),
            "sarif" => Ok(OutputFormat::Sarif),
            other => Err(format!("unknown format: {other}")),
        }
    }
}

/// A collapsed finding enriched with its stable taxonomy class (rule id / CWE).
///
/// Used by JSON summaries and `report export --format json` so downstream tools
/// get a machine-friendly classification alongside the human finding text.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EnrichedFinding {
    pub host: std::net::IpAddr,
    pub port: Option<u16>,
    pub severity: String,
    pub finding: String,
    pub rule_id: &'static str,
    pub category: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<&'static str>,
}

/// Collapsed findings (severity >= `min_rank`) with taxonomy classification.
/// Peer counts are folded into the `finding` text (`"… (N peers)"`).
pub fn enriched_findings(collector: &EventCollector, min_rank: u8) -> Vec<EnrichedFinding> {
    filter_findings_collapsed(collector.findings_collapsed(), min_rank)
        .into_iter()
        .map(|(host, port, severity, finding, peers)| {
            let class = crate::taxonomy::classify(&finding);
            EnrichedFinding {
                host,
                port,
                severity,
                finding: if peers > 1 {
                    format!("{finding} ({peers} peers)")
                } else {
                    finding
                },
                rule_id: class.id,
                category: class.category,
                cwe: class.cwe,
            }
        })
        .collect()
}

/// RFC4180-ish CSV for collapsed findings.
pub fn findings_to_csv(collector: &EventCollector) -> String {
    findings_to_csv_min(collector, 0)
}

/// CSV for collapsed findings, keeping only severities ≥ `min_rank`.
///
/// Leading columns (`severity,host,port,peers,finding`) are stable; the trailing
/// `rule_id,cwe,category` columns come from [`crate::taxonomy::classify`] so the
/// CSV carries the same classification as the JSON / SARIF exports.
pub fn findings_to_csv_min(collector: &EventCollector, min_rank: u8) -> String {
    let mut out = String::from("severity,host,port,peers,finding,rule_id,cwe,category\n");
    for (addr, port, severity, finding, peers) in
        filter_findings_collapsed(collector.findings_collapsed(), min_rank)
    {
        let port_s = port.map(|p| p.to_string()).unwrap_or_default();
        let class = crate::taxonomy::classify(&finding);
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            csv_escape(&severity),
            csv_escape(&addr.to_string()),
            csv_escape(&port_s),
            peers,
            csv_escape(&finding),
            csv_escape(class.id),
            csv_escape(class.cwe.unwrap_or("")),
            csv_escape(class.category),
        ));
    }
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[derive(Clone)]
pub struct Renderer {
    pub format: OutputFormat,
    pub color: bool,
    /// Suppress live stream (also implied by CSV format).
    pub quiet: bool,
    /// Minimum severity rank for FINDINGS table/CSV/JSON (0 = show all).
    pub min_finding_rank: u8,
    /// Live/table: also show closed TCP/UDP ports.
    pub show_closed: bool,
    /// Live/table: also show filtered / open|filtered ports.
    pub show_filtered: bool,
}

impl Renderer {
    pub fn new(format: OutputFormat, color: bool) -> Self {
        Self {
            format,
            color,
            quiet: matches!(
                format,
                OutputFormat::Csv | OutputFormat::Markdown | OutputFormat::Sarif
            ),
            min_finding_rank: 0,
            show_closed: false,
            show_filtered: false,
        }
    }

    pub fn with_quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet
            || matches!(
                self.format,
                OutputFormat::Csv | OutputFormat::Markdown | OutputFormat::Sarif
            );
        self
    }

    pub fn with_min_finding_rank(mut self, min_rank: u8) -> Self {
        self.min_finding_rank = min_rank;
        self
    }

    pub fn with_port_visibility(mut self, show_closed: bool, show_filtered: bool) -> Self {
        self.show_closed = show_closed;
        self.show_filtered = show_filtered;
        self
    }

    pub fn print_event_live(&self, event: &Event) {
        if self.quiet {
            return;
        }
        if matches!(self.format, OutputFormat::Jsonl) {
            if let Ok(line) = serde_json::to_string(event) {
                println!("{line}");
            }
            return;
        }
        // Port visibility can include closed/filtered beyond is_interesting().
        let port_visibility = matches!(
            event,
            Event::PortResult {
                state: PortState::Closed | PortState::Filtered | PortState::OpenFiltered,
                ..
            }
        );
        if !event.is_interesting()
            && !matches!(event, Event::Stats { .. } | Event::Log { .. })
            && !port_visibility
        {
            return;
        }
        match event {
            Event::JobStarted { job_id, started_at } => {
                eprintln!(
                    "{} job {} started at {}",
                    paint(self.color, style("[job]").cyan()),
                    job_id,
                    started_at.to_rfc3339()
                );
            }
            Event::JobFinished {
                job_id,
                finished_at,
                status,
            } => {
                eprintln!(
                    "{} job {} {} ({})",
                    paint(self.color, style("[job]").cyan()),
                    job_id,
                    status,
                    finished_at.to_rfc3339()
                );
            }
            Event::HostUp {
                addr,
                latency_ms,
                method,
            } => {
                let lat = latency_ms.map(|m| format!(" {m}ms")).unwrap_or_default();
                println!(
                    "{} {} up via {}{}",
                    paint(self.color, style("[+]").green().bold()),
                    addr,
                    method,
                    lat
                );
            }
            Event::PortResult {
                addr,
                port,
                state,
                protocol,
                rtt_ms,
            } => {
                let show = match state {
                    PortState::Open => true,
                    PortState::Closed => self.show_closed,
                    PortState::Filtered | PortState::OpenFiltered => self.show_filtered,
                    _ => false,
                };
                if !show {
                    return;
                }
                let rtt = rtt_ms.map(|m| format!(" {m}ms")).unwrap_or_default();
                let (tag, color_tag) = match state {
                    PortState::Open => ("[open]", style("[open]").cyan().bold()),
                    PortState::Closed => ("[closed]", style("[closed]").red()),
                    PortState::Filtered => ("[filtered]", style("[filtered]").yellow()),
                    PortState::OpenFiltered => {
                        ("[open|filtered]", style("[open|filtered]").yellow())
                    }
                    _ => ("[port]", style("[port]").dim()),
                };
                let _ = tag;
                println!(
                    "{} {}:{} {}/{} {}{}",
                    paint(self.color, color_tag),
                    addr,
                    port,
                    protocol,
                    port,
                    state,
                    rtt
                );
            }
            Event::Banner { addr, port, banner } => {
                println!(
                    "{} {}:{}  {}",
                    paint(self.color, style("[banner]").yellow()),
                    addr,
                    port,
                    banner
                );
            }
            Event::ServiceDetected {
                addr,
                port,
                service,
            } => {
                let product = service.product.as_deref().unwrap_or("");
                println!(
                    "{} {}:{}  {} {} (conf {:.0}%)",
                    paint(self.color, style("[svc]").magenta()),
                    addr,
                    port,
                    service.name,
                    product,
                    service.confidence * 100.0
                );
            }
            Event::DnsRecord {
                name,
                record_type,
                value,
            } => {
                println!(
                    "{} {} {} -> {}",
                    paint(self.color, style("[dns]").blue()),
                    name,
                    record_type,
                    value
                );
            }
            Event::PathHop {
                target,
                hop,
                addr,
                rtt_ms,
                label,
            } => {
                let hop_addr = addr.map(|a| a.to_string()).unwrap_or_else(|| "*".into());
                let rtt = rtt_ms
                    .map(|m| format!("{m}ms"))
                    .unwrap_or_else(|| "*".into());
                println!(
                    "{} {} hop {hop:>2}  {hop_addr:<40} {rtt}  ({label})",
                    paint(self.color, style("[path]").cyan()),
                    target
                );
            }
            Event::TlsCert {
                addr,
                port,
                subject,
                issuer,
                not_after,
            } => {
                println!(
                    "{} {}:{} subj={} issuer={} not_after={}",
                    paint(self.color, style("[tls]").green()),
                    addr,
                    port,
                    subject,
                    issuer,
                    not_after
                );
            }
            Event::AsnInfo { addr, asn, org } => {
                println!(
                    "{} {}  {} ({})",
                    paint(self.color, style("[asn]").yellow()),
                    addr,
                    asn,
                    org
                );
            }
            Event::OsGuess {
                addr,
                os,
                confidence,
                observed_ttl,
            } => {
                let ttl = observed_ttl
                    .map(|t| format!(" ttl={t}"))
                    .unwrap_or_default();
                println!(
                    "{} {}  {} (conf {:.0}%{})",
                    paint(self.color, style("[os]").magenta()),
                    addr,
                    os,
                    confidence * 100.0,
                    ttl
                );
            }
            Event::ProbeResult {
                addr,
                port,
                probe,
                detail,
                confidence,
            } => {
                println!(
                    "{} {}:{}  {} — {} (conf {:.0}%)",
                    paint(self.color, style("[probe]").blue()),
                    addr,
                    port,
                    probe,
                    detail,
                    confidence * 100.0
                );
            }
            Event::MisconfigFinding {
                addr,
                port,
                finding,
                severity,
            } => {
                let p = port.map(|p| format!(":{p}")).unwrap_or_default();
                println!(
                    "{} {}{} [{}] {}",
                    paint(self.color, style("[!]").red().bold()),
                    addr,
                    p,
                    severity,
                    finding
                );
            }
            Event::Stats {
                pps,
                open,
                closed,
                filtered,
                elapsed_ms,
            } => {
                eprintln!(
                    "{} {:.0} pps | open={} closed={} filtered={} | {}ms",
                    paint(self.color, style("[stats]").dim()),
                    pps,
                    open,
                    closed,
                    filtered,
                    elapsed_ms
                );
            }
            Event::Log { level, message } => {
                eprintln!("[{level}] {message}");
            }
            _ => {}
        }
    }

    pub fn render_summary(&self, collector: &EventCollector, graph: &AssetGraph) {
        match self.format {
            OutputFormat::Json => {
                #[derive(Serialize)]
                struct Summary<'a> {
                    hosts_up: Vec<std::net::IpAddr>,
                    open_ports: Vec<(std::net::IpAddr, u16, String)>,
                    findings: Vec<EnrichedFinding>,
                    graph: &'a AssetGraph,
                    events: &'a [Event],
                }
                let findings = enriched_findings(collector, self.min_finding_rank);
                let s = Summary {
                    hosts_up: collector.hosts_up(),
                    open_ports: collector.open_ports(),
                    findings,
                    graph,
                    events: &collector.events,
                };
                println!("{}", serde_json::to_string_pretty(&s).unwrap_or_default());
            }
            OutputFormat::Jsonl => {
                // already streamed
            }
            OutputFormat::Csv => {
                print!("{}", findings_to_csv_min(collector, self.min_finding_rank));
            }
            OutputFormat::Markdown => {
                print!(
                    "{}",
                    render_markdown(collector, graph, self.min_finding_rank)
                );
            }
            OutputFormat::Sarif => {
                println!(
                    "{}",
                    crate::sarif::findings_to_sarif_min(collector, self.min_finding_rank)
                );
            }
            OutputFormat::Table | OutputFormat::Plain => {
                self.render_table(collector, graph);
            }
        }
    }

    fn render_table(&self, collector: &EventCollector, graph: &AssetGraph) {
        println!();
        println!(
            "{}",
            paint(self.color, style("═══ AresBird Report ═══").bold())
        );

        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("Host").add_attribute(Attribute::Bold),
                Cell::new("Port").add_attribute(Attribute::Bold),
                Cell::new("Proto").add_attribute(Attribute::Bold),
                Cell::new("State").add_attribute(Attribute::Bold),
                Cell::new("Service").add_attribute(Attribute::Bold),
                Cell::new("Banner").add_attribute(Attribute::Bold),
            ]);

        let mut rows = 0u32;
        for (addr, host) in &graph.hosts {
            for (port, p) in &host.ports {
                let show = match p.state {
                    PortState::Open => true,
                    PortState::Closed => self.show_closed || self.format == OutputFormat::Plain,
                    PortState::Filtered | PortState::OpenFiltered => {
                        self.show_filtered || self.format == OutputFormat::Plain
                    }
                    _ => self.format == OutputFormat::Plain,
                };
                if !show {
                    continue;
                }
                let svc = p
                    .service
                    .as_ref()
                    .map(|s| s.name.clone())
                    .unwrap_or_default();
                let banner = p
                    .banner
                    .as_deref()
                    .unwrap_or("")
                    .chars()
                    .take(40)
                    .collect::<String>();
                let state_cell = match p.state {
                    PortState::Open => Cell::new("open").fg(Color::Green),
                    PortState::Closed => Cell::new("closed").fg(Color::Red),
                    PortState::Filtered => Cell::new("filtered").fg(Color::Yellow),
                    _ => Cell::new(p.state.to_string()),
                };
                table.add_row(vec![
                    Cell::new(addr.to_string()),
                    Cell::new(port.to_string()),
                    Cell::new(&p.protocol),
                    state_cell,
                    Cell::new(svc),
                    Cell::new(banner),
                ]);
                rows += 1;
            }
        }

        if rows == 0 {
            println!("(no open ports to display)");
        } else {
            println!("{table}");
        }

        // DNS section
        if !graph.dns.is_empty() {
            println!();
            println!("{}", paint(self.color, style("DNS").bold()));
            for (name, values) in &graph.dns {
                for v in values {
                    println!("  {name} -> {v}");
                }
            }
        }

        // FINDINGS (collapsed across A/AAAA peers with same message)
        let findings =
            filter_findings_collapsed(collector.findings_collapsed(), self.min_finding_rank);
        if !findings.is_empty() {
            println!();
            println!("{}", paint(self.color, style("FINDINGS").bold()));
            let mut ftable = Table::new();
            ftable
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    Cell::new("Severity").add_attribute(Attribute::Bold),
                    Cell::new("Host").add_attribute(Attribute::Bold),
                    Cell::new("Port").add_attribute(Attribute::Bold),
                    Cell::new("Peers").add_attribute(Attribute::Bold),
                    Cell::new("Finding").add_attribute(Attribute::Bold),
                    Cell::new("Why").add_attribute(Attribute::Bold),
                ]);
            for (addr, port, severity, finding, peers) in &findings {
                let sev = match severity.as_str() {
                    "high" => Cell::new(severity).fg(Color::Red),
                    "medium" => Cell::new(severity).fg(Color::Yellow),
                    "low" => Cell::new(severity).fg(Color::Blue),
                    _ => Cell::new(severity.as_str()),
                };
                let why = crate::narrative::format_why(&crate::narrative::evidence_chain(
                    collector, *addr, *port, finding, 3,
                ));
                ftable.add_row(vec![
                    sev,
                    Cell::new(addr.to_string()),
                    Cell::new(port.map(|p| p.to_string()).unwrap_or_else(|| "-".into())),
                    Cell::new(peers.to_string()),
                    Cell::new(finding.chars().take(80).collect::<String>()),
                    Cell::new(why.chars().take(72).collect::<String>()),
                ]);
            }
            println!("{ftable}");
        }

        // INTEL: ASN / PTR / CDN / OS / HTTP-TLS correlation
        let intel: Vec<_> = graph
            .hosts
            .values()
            .filter(|h| {
                h.asn.is_some()
                    || h.cdn.is_some()
                    || h.ptr.is_some()
                    || h.os_guess.is_some()
                    || h.http_title.is_some()
                    || h.tls_subject.is_some()
                    || h.alpn.is_some()
                    || !h.findings.is_empty()
            })
            .collect();
        if !intel.is_empty() {
            println!();
            println!("{}", paint(self.color, style("INTEL").bold()));
            let mut itable = Table::new();
            itable
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    Cell::new("Host").add_attribute(Attribute::Bold),
                    Cell::new("ASN").add_attribute(Attribute::Bold),
                    Cell::new("CDN").add_attribute(Attribute::Bold),
                    Cell::new("OS").add_attribute(Attribute::Bold),
                    Cell::new("ALPN").add_attribute(Attribute::Bold),
                    Cell::new("Findings").add_attribute(Attribute::Bold),
                    Cell::new("Title/TLS").add_attribute(Attribute::Bold),
                ]);
            for h in intel {
                let os = match (&h.os_guess, h.os_confidence) {
                    (Some(os), Some(c)) => format!("{os} ({:.0}%)", c * 100.0),
                    (Some(os), None) => os.clone(),
                    _ => "-".into(),
                };
                let title_tls = h
                    .http_title
                    .clone()
                    .or_else(|| h.tls_subject.clone())
                    .unwrap_or_else(|| "-".into());
                let fname = h
                    .hostname
                    .as_ref()
                    .map(|n| format!("{} ({})", h.addr, n))
                    .unwrap_or_else(|| h.addr.to_string());
                itable.add_row(vec![
                    Cell::new(fname),
                    Cell::new(h.asn.as_deref().unwrap_or("-")),
                    Cell::new(h.cdn.as_deref().unwrap_or("-")),
                    Cell::new(os),
                    Cell::new(h.alpn.as_deref().unwrap_or("-")),
                    Cell::new(h.findings.len().to_string()),
                    Cell::new(title_tls.chars().take(40).collect::<String>()),
                ]);
            }
            println!("{itable}");
        }

        // PATHS
        if !graph.paths.is_empty() {
            println!();
            println!("{}", paint(self.color, style("PATHS").bold()));
            for (target, hops) in &graph.paths {
                println!("  → {target}");
                for h in hops {
                    let a = h.addr.map(|x| x.to_string()).unwrap_or_else(|| "*".into());
                    let rtt = h
                        .rtt_ms
                        .map(|m| format!("{m}ms"))
                        .unwrap_or_else(|| "*".into());
                    println!("    {:>2}  {a:<40} {rtt}  ({})", h.hop, h.label);
                }
            }
        }

        println!();
        // Prefer live Stats event totals when available
        let (open, closed, filtered) = collector
            .events
            .iter()
            .rev()
            .find_map(|e| match e {
                Event::Stats {
                    open,
                    closed,
                    filtered,
                    ..
                } => Some((*open, *closed, *filtered)),
                _ => None,
            })
            .unwrap_or_else(|| collector.stats_summary());
        println!(
            "Summary: {} open | {} closed | {} filtered | {} hosts | {} findings",
            open,
            closed,
            filtered,
            graph.hosts.len(),
            graph.finding_count().max(findings.len())
        );

        let handoffs =
            crate::narrative::suggest_talk_handoffs(collector, graph, self.min_finding_rank);
        if !handoffs.is_empty() {
            println!();
            println!("{}", paint(self.color, style("NEXT").bold()));
            for h in handoffs {
                println!("  → {}  # {}", h.cmd, h.reason);
            }
        }

        let mut fixes = Vec::new();
        for (_addr, _port, severity, finding, _) in &findings {
            if !matches!(severity.as_str(), "high" | "medium") {
                continue;
            }
            if let Some(fix) = crate::remediation::remediation_for(finding) {
                fixes.push((severity.clone(), finding.clone(), fix));
            }
        }
        if !fixes.is_empty() {
            println!();
            println!("{}", paint(self.color, style("FIX").bold()));
            for (sev, finding, fix) in fixes.into_iter().take(12) {
                println!(
                    "  · [{sev}] {}",
                    finding.chars().take(64).collect::<String>()
                );
                println!("      → {fix}");
            }
        }
    }
}

/// Markdown report for tickets / CI artifacts.
pub fn render_markdown(
    collector: &EventCollector,
    graph: &AssetGraph,
    min_finding_rank: u8,
) -> String {
    let generated = chrono::Utc::now().to_rfc3339();
    let findings = filter_findings_collapsed(collector.findings_collapsed(), min_finding_rank);
    let mut sev_counts = [0usize; 5]; // high, medium, low, info, other
    for (_, _, severity, _, _) in &findings {
        match severity.as_str() {
            "high" => sev_counts[0] += 1,
            "medium" => sev_counts[1] += 1,
            "low" => sev_counts[2] += 1,
            "info" => sev_counts[3] += 1,
            _ => sev_counts[4] += 1,
        }
    }

    let mut out = String::from("# AresBird Report\n\n");
    out.push_str(&format!("_Generated: `{generated}`_\n\n"));
    out.push_str("## Executive summary\n\n");
    out.push_str(&format!(
        "| High | Medium | Low | Info | Hosts | Open ports |\n| ---: | ---: | ---: | ---: | ---: | ---: |\n| {} | {} | {} | {} | {} | {} |\n\n",
        sev_counts[0],
        sev_counts[1],
        sev_counts[2],
        sev_counts[3],
        graph.hosts.len(),
        graph.open_services().len()
    ));
    out.push_str(
        "- [Open ports](#open-ports)\n- [Findings](#findings)\n- [Remediation](#remediation)\n- [Next steps](#next-talk-handoff)\n- [Intel](#intel)\n\n",
    );

    out.push_str("## Open ports\n\n");
    out.push_str("| Host | Port | Proto | Service | Banner |\n");
    out.push_str("| --- | ---: | --- | --- | --- |\n");
    let mut port_rows = 0usize;
    let mut hosts: Vec<_> = graph.hosts.iter().collect();
    hosts.sort_by(|a, b| a.0.cmp(b.0));
    for (addr, host) in hosts {
        for (port, p) in &host.ports {
            if p.state != PortState::Open {
                continue;
            }
            let svc = p.service.as_ref().map(|s| s.name.as_str()).unwrap_or("");
            let banner = p
                .banner
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(40)
                .collect::<String>()
                .replace('|', "\\|");
            out.push_str(&format!(
                "| `{addr}` | {port} | {} | {svc} | {banner} |\n",
                p.protocol
            ));
            port_rows += 1;
        }
    }
    if port_rows == 0 {
        out.push_str("_No open ports._\n");
    }

    if !graph.dns.is_empty() {
        out.push_str("\n## DNS\n\n");
        for (name, values) in &graph.dns {
            for v in values {
                out.push_str(&format!("- `{name}` → `{v}`\n"));
            }
        }
    }

    if !findings.is_empty() {
        out.push_str("\n## Findings\n\n");
        out.push_str("| Severity | Host | Port | Peers | Finding | Why |\n");
        out.push_str("| --- | --- | ---: | ---: | --- | --- |\n");
        for (addr, port, severity, finding, peers) in &findings {
            let port_s = port.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
            let finding_esc = finding.replace('|', "\\|");
            let why = crate::narrative::format_why(&crate::narrative::evidence_chain(
                collector, *addr, *port, finding, 3,
            ))
            .replace('|', "\\|");
            out.push_str(&format!(
                "| **{severity}** | `{addr}` | {port_s} | {peers} | {finding_esc} | {why} |\n"
            ));
        }

        out.push_str("\n### Evidence\n\n");
        for (addr, port, severity, finding, _) in &findings {
            let chain = crate::narrative::evidence_chain(collector, *addr, *port, finding, 4);
            if chain.is_empty() {
                continue;
            }
            let port_s = port.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
            out.push_str(&format!("- **{severity}** `{addr}:{port_s}` — {finding}\n"));
            for step in chain {
                out.push_str(&format!("  - `{}`: {}\n", step.kind, step.detail));
            }
        }

        out.push_str("\n## Remediation\n\n");
        let mut any_fix = false;
        for (_addr, _port, severity, finding, _) in &findings {
            if let Some(fix) = crate::remediation::remediation_for(finding) {
                any_fix = true;
                out.push_str(&format!(
                    "### [{severity}] {}\n\n{fix}\n\n",
                    finding.replace('|', "\\|")
                ));
            }
        }
        if !any_fix {
            out.push_str("_No automated remediation hints for these findings._\n");
        }
    }

    let handoffs = crate::narrative::suggest_talk_handoffs(collector, graph, min_finding_rank);
    if !handoffs.is_empty() {
        out.push_str("\n## Next (talk handoff)\n\n");
        for h in handoffs {
            out.push_str(&format!("- `{}` — {}\n", h.cmd, h.reason));
        }
    }

    let intel: Vec<_> = graph
        .hosts
        .values()
        .filter(|h| {
            h.asn.is_some()
                || h.cdn.is_some()
                || h.os_guess.is_some()
                || h.http_title.is_some()
                || h.tls_subject.is_some()
                || !h.findings.is_empty()
        })
        .collect();
    if !intel.is_empty() {
        out.push_str("\n## Intel\n\n");
        out.push_str("| Host | Hostname | ASN | CDN | OS | Findings |\n");
        out.push_str("| --- | --- | --- | --- | --- | ---: |\n");
        for h in intel {
            let os = h.os_guess.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} |\n",
                h.addr,
                h.hostname.as_deref().unwrap_or("-"),
                h.asn.as_deref().unwrap_or("-"),
                h.cdn.as_deref().unwrap_or("-"),
                os,
                h.findings.len()
            ));
        }
    }

    if !graph.paths.is_empty() {
        out.push_str("\n## Paths\n\n");
        for (target, hops) in &graph.paths {
            out.push_str(&format!("### `{target}`\n\n"));
            for h in hops {
                let a = h.addr.map(|x| x.to_string()).unwrap_or_else(|| "*".into());
                let rtt = h
                    .rtt_ms
                    .map(|m| format!("{m}ms"))
                    .unwrap_or_else(|| "*".into());
                out.push_str(&format!("- hop {} `{a}` {rtt} ({})\n", h.hop, h.label));
            }
            out.push('\n');
        }
    }

    let (open, closed, filtered) = collector.stats_summary();
    out.push_str(&format!(
        "\n---\n\n**Summary:** {open} open · {closed} closed · {filtered} filtered · {} hosts · {} findings\n",
        graph.hosts.len(),
        graph.finding_count().max(findings.len())
    ));
    out
}

fn paint(color: bool, styled: console::StyledObject<&str>) -> String {
    if color {
        styled.to_string()
    } else {
        // Recreate without ANSI by using the underlying content via Display after disabling.
        format!("{styled}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::event::Event;
    use std::net::{IpAddr, Ipv4Addr};

    fn collector_with(port: u16, sev: &str, msg: &str) -> EventCollector {
        let mut c = EventCollector::new();
        c.push(Event::MisconfigFinding {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: Some(port),
            finding: msg.to_string(),
            severity: sev.to_string(),
        });
        c
    }

    #[test]
    fn csv_carries_taxonomy_columns() {
        let c = collector_with(6379, "high", "Redis responds without AUTH (PONG)");
        let csv = findings_to_csv(&c);
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().unwrap(),
            "severity,host,port,peers,finding,rule_id,cwe,category"
        );
        let row = lines.next().expect("one finding row");
        // Leading columns stay in place; taxonomy is appended.
        assert!(row.starts_with("high,127.0.0.1,6379,1,"), "row={row}");
        assert!(row.contains("service-missing-auth"), "row={row}");
        assert!(row.contains("CWE-306"), "row={row}");
        assert!(row.trim_end().ends_with("exposure"), "row={row}");
    }

    #[test]
    fn enriched_findings_classify() {
        let c = collector_with(
            443,
            "medium",
            "Missing security header: strict-transport-security",
        );
        let ef = enriched_findings(&c, 0);
        assert_eq!(ef.len(), 1);
        assert_eq!(ef[0].rule_id, "http-missing-hsts");
        assert_eq!(ef[0].cwe, Some("CWE-319"));
        assert_eq!(ef[0].category, "web");
    }
}
