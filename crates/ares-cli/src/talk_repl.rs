//! Interactive observe REPL: HTTP(S), Redis (duplex TCP), SSH (banner/session lite).

use std::io::{self, BufRead, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ares_core::event::Event;
use ares_core::job::Job;
use ares_core::timing::ScanMode;
use ares_core::{AssetGraph, EventCollector};
use ares_output::{OutputFormat, Renderer, RunStore};
use ares_proto::{CookieJar, HttpEngine, SshBanner};
use chrono::Utc;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use url::Url;
use uuid::Uuid;

pub struct ReplOpts {
    pub target: String,
    /// `auto` | `http` | `https` | `redis` | `ssh`
    pub proto: String,
    pub mode: ScanMode,
    pub renderer: Renderer,
    pub save: bool,
    pub ephemeral: bool,
    pub workspace: String,
}

pub async fn run_talk_repl(opts: ReplOpts) -> anyhow::Result<(EventCollector, AssetGraph)> {
    let proto = resolve_proto(&opts.proto, &opts.target);
    match proto.as_str() {
        "http" | "https" => run_http_repl(opts, proto == "https").await,
        "redis" => run_redis_repl(opts).await,
        "ssh" => run_ssh_repl(opts).await,
        other => anyhow::bail!(
            "talk --repl supports http|https|redis|ssh (got `{other}`; use --proto)"
        ),
    }
}

fn resolve_proto(cli: &str, target: &str) -> String {
    let c = cli.trim().to_ascii_lowercase();
    if c != "auto" && !c.is_empty() {
        return c;
    }
    if let Ok(url) = Url::parse(target) {
        return match url.scheme() {
            "https" => "https".into(),
            "http" => "http".into(),
            "redis" => "redis".into(),
            "ssh" => "ssh".into(),
            _ => "http".into(),
        };
    }
    let lower = target.to_ascii_lowercase();
    if lower.contains(":6379") || lower.starts_with("redis://") {
        return "redis".into();
    }
    if lower.contains(":22") || lower.starts_with("ssh://") {
        return "ssh".into();
    }
    "http".into()
}

// ─── shared session helpers ─────────────────────────────────────────────────

struct SessionState {
    graph: Arc<Mutex<AssetGraph>>,
    collector: Arc<Mutex<EventCollector>>,
    emit: Arc<dyn Fn(Event) + Send + Sync>,
    job_id: uuid::Uuid,
    session_id: Uuid,
    renderer: Renderer,
    save: bool,
    ephemeral: bool,
    workspace: String,
    mode: ScanMode,
}

fn begin_session(
    opts: &ReplOpts,
    module_name: &str,
) -> (
    SessionState,
    Job,
    Arc<dyn Fn(Event) + Send + Sync>,
) {
    let graph = Arc::new(Mutex::new(AssetGraph::new()));
    let collector = Arc::new(Mutex::new(EventCollector::new()));
    let mut job = Job::new(module_name, opts.mode);
    job.mark_running();
    let job_id = job.id;
    let live = Arc::new(
        Renderer::new(opts.renderer.format, opts.renderer.color)
            .with_quiet(opts.renderer.quiet)
            .with_port_visibility(opts.renderer.show_closed, opts.renderer.show_filtered)
            .with_min_finding_rank(opts.renderer.min_finding_rank),
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
    let state = SessionState {
        graph,
        collector,
        emit: emit.clone(),
        job_id,
        session_id: Uuid::new_v4(),
        renderer: opts.renderer.clone(),
        save: opts.save,
        ephemeral: opts.ephemeral,
        workspace: opts.workspace.clone(),
        mode: opts.mode,
    };
    let _ = state.mode;
    (state, job, emit)
}

fn finish_session(
    state: SessionState,
    mut job: Job,
    transcript: Vec<String>,
    note: String,
    addr: IpAddr,
    port: u16,
) -> anyhow::Result<(EventCollector, AssetGraph)> {
    {
        let mut g = state.graph.lock();
        if let Some(s) = g.sessions.get_mut(&state.session_id) {
            s.closed = true;
            s.note = Some(note.clone());
            s.transcript = transcript;
        }
    }
    (state.emit)(Event::ProbeResult {
        addr,
        port,
        probe: "repl-summary".into(),
        detail: note,
        confidence: 0.9,
    });
    (state.emit)(Event::SessionClosed {
        session_id: state.session_id,
    });
    job.mark_completed();
    (state.emit)(Event::JobFinished {
        job_id: state.job_id,
        finished_at: job.finished_at.unwrap_or_else(Utc::now),
        status: "completed".into(),
    });

    let collector_out = state.collector.lock().clone();
    let graph_out = state.graph.lock().clone();
    if !matches!(state.renderer.format, OutputFormat::Jsonl) {
        state
            .renderer
            .render_summary(&collector_out, &graph_out);
    }
    if state.save {
        let store = RunStore::open_default()?;
        let id = store.save("talk-repl", &collector_out, &graph_out)?;
        if !state.renderer.quiet {
            eprintln!("saved run {id}");
        } else {
            eprintln!("# saved {id}");
        }
    }
    if !state.ephemeral {
        crate::workspace::merge_and_save(
            &state.workspace,
            &collector_out,
            &graph_out,
            state.renderer.quiet,
        )?;
    }
    Ok((collector_out, graph_out))
}

async fn resolve_host_port(raw: &str, default_port: u16) -> anyhow::Result<(IpAddr, u16)> {
    let s = raw
        .trim()
        .trim_start_matches("redis://")
        .trim_start_matches("ssh://")
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let (host, port) = if let Some((h, p)) = s.rsplit_once(':') {
        if h.starts_with('[') {
            // skip ipv6 complexity — try parse whole as host
            (s, default_port)
        } else if let Ok(pn) = p.parse::<u16>() {
            (h, pn)
        } else {
            (s, default_port)
        }
    } else {
        (s, default_port)
    };
    let host = host.trim_end_matches('/');
    let addr = resolve_one(host).await?;
    Ok((addr, port))
}

async fn resolve_one(host: &str) -> anyhow::Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let mut addrs = tokio::net::lookup_host((host, 0)).await?;
    addrs
        .next()
        .map(|sa| sa.ip())
        .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {host}"))
}

fn read_line_prompt(quiet: bool, prompt: &str) -> anyhow::Result<Option<String>> {
    if !quiet {
        print!("{prompt}");
        let _ = io::stdout().flush();
    }
    let mut input = String::new();
    let n = io::stdin().lock().read_line(&mut input)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(input.trim().to_string()))
}

// ─── HTTP ───────────────────────────────────────────────────────────────────

struct ResolvedHttp {
    addr: IpAddr,
    port: u16,
    host_header: String,
    start_path: String,
    use_tls: bool,
    sni: Option<String>,
}

async fn run_http_repl(
    opts: ReplOpts,
    force_tls: bool,
) -> anyhow::Result<(EventCollector, AssetGraph)> {
    let mut resolved = resolve_http_target(&opts.target).await?;
    if force_tls {
        resolved.use_tls = true;
    }
    let (state, job, emit) = begin_session(&opts, "talk-repl-http");
    let protocol = if resolved.use_tls { "https" } else { "http" };
    emit(Event::SessionOpened {
        session_id: state.session_id,
        addr: resolved.addr,
        port: resolved.port,
        protocol: protocol.into(),
    });

    if !opts.renderer.quiet {
        eprintln!(
            "talk REPL → {protocol}://{}:{}  (session {})",
            resolved.host_header, resolved.port, state.session_id
        );
        eprintln!("commands: GET /path | /path | cookies | help | quit");
    }

    let engine = HttpEngine::default();
    let mut jar = CookieJar::default();
    let mut transcript = Vec::new();

    {
        let path = resolved.start_path.clone();
        if let Err(e) = http_get(&engine, &resolved, &path, &mut jar, &emit, &mut transcript).await
        {
            emit(Event::Log {
                level: "warn".into(),
                message: format!("landing GET {path} failed: {e}"),
            });
        }
    }

    loop {
        let Some(line) = read_line_prompt(opts.renderer.quiet, "ares> ")? else {
            break;
        };
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if matches!(lower.as_str(), "quit" | "exit" | "q") {
            break;
        }
        if matches!(lower.as_str(), "help" | "?") {
            eprintln!("  GET /path   observe GET (cookies persist)");
            eprintln!("  /path       same as GET /path");
            eprintln!("  cookies     list jar");
            eprintln!("  quit");
            continue;
        }
        if lower == "cookies" {
            if jar.is_empty() {
                eprintln!("(no cookies)");
            } else {
                for (k, v) in jar.pairs() {
                    eprintln!("  {k}={v}");
                }
            }
            continue;
        }
        let path = parse_get_path(&line);
        match http_get(&engine, &resolved, &path, &mut jar, &emit, &mut transcript).await {
            Ok(status) => {
                if !opts.renderer.quiet {
                    eprintln!("→ {path}  {status}");
                }
            }
            Err(e) => {
                eprintln!("! {path}: {e}");
                transcript.push(format!("GET {path} → error: {e}"));
            }
        }
    }

    let note = format!(
        "{} hop(s), {} cookie(s)",
        transcript.len(),
        jar.len()
    );
    let addr = resolved.addr;
    let port = resolved.port;
    finish_session(state, job, transcript, note, addr, port)
}

async fn http_get(
    engine: &HttpEngine,
    resolved: &ResolvedHttp,
    path: &str,
    jar: &mut CookieJar,
    emit: &Arc<dyn Fn(Event) + Send + Sync>,
    transcript: &mut Vec<String>,
) -> anyhow::Result<String> {
    let emit_fn = |e: Event| emit(e);
    let resp = engine
        .session_get(
            resolved.addr,
            resolved.port,
            &resolved.host_header,
            path,
            resolved.use_tls,
            resolved.sni.as_deref(),
            jar,
            emit_fn,
        )
        .await?;
    let status = resp.status_line.clone();
    emit(Event::ProbeResult {
        addr: resolved.addr,
        port: resolved.port,
        probe: "http-repl-get".into(),
        detail: format!("{path} → {status}"),
        confidence: 0.95,
    });
    transcript.push(format!("GET {path} → {status}"));
    Ok(status)
}

fn parse_get_path(line: &str) -> String {
    let t = line.trim();
    let rest = if let Some(r) = t.strip_prefix("GET ") {
        r.trim()
    } else if let Some(r) = t.strip_prefix("get ") {
        r.trim()
    } else {
        t
    };
    if rest.is_empty() {
        "/".into()
    } else if rest.starts_with('/') {
        rest.to_string()
    } else {
        format!("/{rest}")
    }
}

async fn resolve_http_target(raw: &str) -> anyhow::Result<ResolvedHttp> {
    let candidate = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}/")
    };
    let url = Url::parse(&candidate).map_err(|e| anyhow::anyhow!("bad URL: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL missing host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(80);
    let path = {
        let p = url.path();
        if p.is_empty() {
            "/".to_string()
        } else {
            p.to_string()
        }
    };
    let use_tls = url.scheme() == "https" || port == 443 || port == 8443;
    let addr = resolve_one(&host).await?;
    let sni = if host.parse::<IpAddr>().is_ok() {
        None
    } else {
        Some(host.clone())
    };
    Ok(ResolvedHttp {
        addr,
        port,
        host_header: host,
        start_path: path,
        use_tls,
        sni,
    })
}

// ─── Redis duplex ───────────────────────────────────────────────────────────

async fn run_redis_repl(opts: ReplOpts) -> anyhow::Result<(EventCollector, AssetGraph)> {
    let (addr, port) = resolve_host_port(&opts.target, 6379).await?;
    let (state, job, emit) = begin_session(&opts, "talk-repl-redis");
    emit(Event::SessionOpened {
        session_id: state.session_id,
        addr,
        port,
        protocol: "redis".into(),
    });

    let sa = SocketAddr::new(addr, port);
    let mut stream: Option<TcpStream> = match timeout(Duration::from_secs(5), TcpStream::connect(sa)).await
    {
        Ok(Ok(s)) => Some(s),
        Ok(Err(e)) => {
            emit(Event::Log {
                level: "warn".into(),
                message: format!("redis connect {sa}: {e} (REPL still open; will retry on command)"),
            });
            if !opts.renderer.quiet {
                eprintln!("! connect failed: {e} — type help | quit; commands retry connect");
            }
            None
        }
        Err(_) => {
            emit(Event::Log {
                level: "warn".into(),
                message: format!("redis connect {sa}: timeout (REPL still open)"),
            });
            if !opts.renderer.quiet {
                eprintln!("! connect timeout — type help | quit; commands retry connect");
            }
            None
        }
    };

    if !opts.renderer.quiet {
        eprintln!("talk REPL → redis://{addr}:{port}  (session {})", state.session_id);
        eprintln!("read-only: PING INFO GET EXISTS DBSIZE TIME | help | quit");
    }

    let mut transcript = Vec::new();
    if let Some(ref mut s) = stream {
        match redis_cmd(s, &["PING"], addr, port, &emit, &mut transcript).await {
            Ok(r) => {
                if !opts.renderer.quiet {
                    eprintln!("→ {r}");
                }
            }
            Err(e) => emit(Event::Log {
                level: "warn".into(),
                message: format!("redis landing PING failed: {e}"),
            }),
        }
    }

    loop {
        let Some(line) = read_line_prompt(opts.renderer.quiet, "redis> ")? else {
            break;
        };
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if matches!(lower.as_str(), "quit" | "exit" | "q") {
            break;
        }
        if matches!(lower.as_str(), "help" | "?") {
            eprintln!("  PING | INFO [section] | GET key | EXISTS key | DBSIZE | TIME");
            eprintln!("  (write/admin commands blocked)");
            eprintln!("  quit");
            continue;
        }
        let args = split_args(&line);
        if args.is_empty() {
            continue;
        }
        if !redis_cmd_allowed(&args[0]) {
            eprintln!("! blocked unsafe command `{}` (observe-only REPL)", args[0]);
            transcript.push(format!("BLOCKED {}", args[0]));
            continue;
        }
        if stream.is_none() {
            match timeout(Duration::from_secs(3), TcpStream::connect(sa)).await {
                Ok(Ok(s)) => stream = Some(s),
                Ok(Err(e)) => {
                    eprintln!("! not connected: {e}");
                    transcript.push(format!("ERR connect {e}"));
                    continue;
                }
                Err(_) => {
                    eprintln!("! not connected: timeout");
                    transcript.push("ERR connect timeout".into());
                    continue;
                }
            }
        }
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let Some(ref mut s) = stream else { continue };
        match redis_cmd(s, &refs, addr, port, &emit, &mut transcript).await {
            Ok(r) => {
                if !opts.renderer.quiet {
                    eprintln!("→ {}", r.chars().take(500).collect::<String>());
                }
            }
            Err(e) => {
                eprintln!("! {e}");
                transcript.push(format!("ERR {e}"));
                stream = None;
                if let Ok(Ok(s)) = timeout(Duration::from_secs(3), TcpStream::connect(sa)).await {
                    stream = Some(s);
                }
            }
        }
    }

    let note = format!("redis {} cmd(s)", transcript.len());
    finish_session(state, job, transcript, note, addr, port)
}

fn redis_cmd_allowed(cmd: &str) -> bool {
    matches!(
        cmd.to_ascii_uppercase().as_str(),
        "PING"
            | "INFO"
            | "GET"
            | "EXISTS"
            | "TTL"
            | "PTTL"
            | "TYPE"
            | "DBSIZE"
            | "TIME"
            | "ECHO"
            | "STRLEN"
            | "GETRANGE"
            | "HGET"
            | "HLEN"
            | "HKEYS"
            | "LLEN"
            | "SCARD"
            | "ZCARD"
            | "CLIENT"
    )
}

fn split_args(line: &str) -> Vec<String> {
    line.split_whitespace().map(|s| s.to_string()).collect()
}

fn encode_resp(args: &[&str]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

async fn redis_cmd(
    stream: &mut TcpStream,
    args: &[&str],
    addr: IpAddr,
    port: u16,
    emit: &Arc<dyn Fn(Event) + Send + Sync>,
    transcript: &mut Vec<String>,
) -> anyhow::Result<String> {
    let payload = encode_resp(args);
    timeout(Duration::from_secs(3), stream.write_all(&payload)).await??;
    let mut buf = vec![0u8; 8192];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    if n == 0 {
        anyhow::bail!("empty reply (connection closed)");
    }
    let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    let label = args.join(" ");
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "redis-repl".into(),
        detail: format!("{label} → {}", text.chars().take(120).collect::<String>()),
        confidence: 0.9,
    });
    transcript.push(format!("{label} → {}", text.chars().take(80).collect::<String>()));
    Ok(text)
}

// ─── SSH observe REPL ───────────────────────────────────────────────────────

async fn run_ssh_repl(opts: ReplOpts) -> anyhow::Result<(EventCollector, AssetGraph)> {
    let (addr, port) = resolve_host_port(&opts.target, 22).await?;
    let (state, job, emit) = begin_session(&opts, "talk-repl-ssh");
    emit(Event::SessionOpened {
        session_id: state.session_id,
        addr,
        port,
        protocol: "ssh".into(),
    });

    if !opts.renderer.quiet {
        eprintln!("talk REPL → ssh://{addr}:{port}  (session {})", state.session_id);
        eprintln!("observe-only (no shell): banner | probe | help | quit");
    }

    let mut transcript = Vec::new();
    match SshBanner::grab(addr, port, |e| emit(e)).await {
        Ok(b) => {
            transcript.push(format!("banner → {b}"));
            if !opts.renderer.quiet {
                eprintln!("→ {b}");
            }
        }
        Err(e) => emit(Event::Log {
            level: "warn".into(),
            message: format!("ssh banner failed: {e}"),
        }),
    }

    loop {
        let Some(line) = read_line_prompt(opts.renderer.quiet, "ssh> ")? else {
            break;
        };
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if matches!(lower.as_str(), "quit" | "exit" | "q") {
            break;
        }
        if matches!(lower.as_str(), "help" | "?") {
            eprintln!("  banner   re-grab SSH identification string");
            eprintln!("  probe    send AresBird client id + read reply bytes");
            eprintln!("  quit     (full interactive SSH shell is not implemented — observe only)");
            continue;
        }
        if lower == "banner" {
            match SshBanner::grab(addr, port, |e| emit(e)).await {
                Ok(b) => {
                    transcript.push(format!("banner → {b}"));
                    eprintln!("→ {b}");
                }
                Err(e) => eprintln!("! {e}"),
            }
            continue;
        }
        if lower == "probe" {
            match ssh_probe_kex(addr, port, &emit, &mut transcript).await {
                Ok(d) => eprintln!("→ {d}"),
                Err(e) => eprintln!("! {e}"),
            }
            continue;
        }
        eprintln!("unknown command (try help)");
    }

    let note = format!("ssh {} step(s)", transcript.len());
    finish_session(state, job, transcript, note, addr, port)
}

async fn ssh_probe_kex(
    addr: IpAddr,
    port: u16,
    emit: &Arc<dyn Fn(Event) + Send + Sync>,
    transcript: &mut Vec<String>,
) -> anyhow::Result<String> {
    let sa = SocketAddr::new(addr, port);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(sa)).await??;
    // read server banner
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    // send client identification
    let id = b"SSH-2.0-AresBird_0.1\r\n";
    timeout(Duration::from_secs(2), stream.write_all(id)).await??;
    let mut more = [0u8; 512];
    let m = timeout(Duration::from_secs(2), stream.read(&mut more))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    let detail = format!(
        "server={banner}; kex_bytes={m} (binary handshake observed, no auth)"
    );
    emit(Event::ProbeResult {
        addr,
        port,
        probe: "ssh-repl-probe".into(),
        detail: detail.clone(),
        confidence: 0.75,
    });
    transcript.push(detail.clone());
    Ok(detail)
}
