//! Path discovery (traceroute) — portable via OS tracert/traceroute.

use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;

use ares_core::event::Event;
use tokio::process::Command;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Run system traceroute/tracert and emit PathHop events.
pub async fn traceroute(
    target: IpAddr,
    max_hops: u8,
    cancel: CancellationToken,
    emit: impl Fn(Event) + Send + Sync,
) -> anyhow::Result<()> {
    let max_hops = max_hops.clamp(1, 64);
    let (program, args) = if cfg!(windows) {
        (
            "tracert",
            vec![
                "-d".into(),
                "-h".into(),
                max_hops.to_string(),
                "-w".into(),
                "1000".into(),
                target.to_string(),
            ],
        )
    } else {
        (
            "traceroute",
            vec![
                "-n".into(),
                "-m".into(),
                max_hops.to_string(),
                "-w".into(),
                "1".into(),
                target.to_string(),
            ],
        )
    };

    emit(Event::Log {
        level: "info".into(),
        message: format!("path: running {program} to {target}"),
    });

    if cancel.is_cancelled() {
        return Ok(());
    }

    let child = Command::new(program)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();

    let child = match child {
        Ok(c) => c,
        Err(e) => {
            emit(Event::Log {
                level: "warn".into(),
                message: format!("path: {program} unavailable ({e}) — falling back to TCP TTL probe"),
            });
            return tcp_ttl_probe(target, max_hops, cancel, emit).await;
        }
    };

    let output = timeout(Duration::from_secs(90), child.wait_with_output()).await;
    let output = match output {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => anyhow::bail!("tracert failed: {e}"),
        Err(_) => {
            emit(Event::Log {
                level: "warn".into(),
                message: "path: traceroute timed out".into(),
            });
            return Ok(());
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{text}\n{err}");
    parse_and_emit_hops(target, &combined, &emit);

    if combined.lines().filter(|l| parse_hop_line(l).is_some()).count() == 0 {
        emit(Event::Log {
            level: "info".into(),
            message: "path: no hops parsed — trying TCP TTL fallback".into(),
        });
        tcp_ttl_probe(target, max_hops.min(16), cancel, emit).await?;
    }

    Ok(())
}

fn parse_and_emit_hops(target: IpAddr, text: &str, emit: &impl Fn(Event)) {
    for line in text.lines() {
        if let Some((hop, addr, rtt, label)) = parse_hop_line(line) {
            emit(Event::PathHop {
                target,
                hop,
                addr,
                rtt_ms: rtt,
                label,
            });
        }
    }
}

/// Parse both Windows tracert and Unix traceroute hop lines.
fn parse_hop_line(line: &str) -> Option<(u8, Option<IpAddr>, Option<u64>, String)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.split_whitespace();
    let hop: u8 = parts.next()?.parse().ok()?;

    // Windows: `  1    <1 ms    <1 ms    <1 ms  192.168.1.1`
    // or `  1     *        *        *     Request timed out.`
    // Unix: ` 1  192.168.1.1  1.234 ms  1.1 ms  1.0 ms`
    let rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        return None;
    }

    if rest.iter().all(|p| *p == "*")
        || rest.join(" ").to_lowercase().contains("timed out")
        || rest.join(" ").contains("* * *")
    {
        return Some((hop, None, None, "timeout".into()));
    }

    // Find first IP-looking token
    let mut addr = None;
    let mut rtt = None;
    for tok in &rest {
        let clean = tok.trim_matches(|c| c == '[' || c == ']');
        if let Ok(ip) = clean.parse::<IpAddr>() {
            addr = Some(ip);
            break;
        }
    }
    for tok in &rest {
        let t = tok.trim_end_matches("ms");
        if let Ok(v) = t.parse::<f64>() {
            rtt = Some(v as u64);
            break;
        }
        if tok.starts_with('<') {
            rtt = Some(1);
            break;
        }
    }

    let label = if let Some(a) = addr {
        a.to_string()
    } else {
        rest.join(" ")
    };
    Some((hop, addr, rtt, label))
}

/// Best-effort TCP connect with rising TTL (limited hop visibility, no ICMP capture).
async fn tcp_ttl_probe(
    target: IpAddr,
    max_hops: u8,
    cancel: CancellationToken,
    emit: impl Fn(Event),
) -> anyhow::Result<()> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

    let dest = SocketAddr::new(target, 80);
    for hop in 1..=max_hops {
        if cancel.is_cancelled() {
            break;
        }
        let domain = if target.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        sock.set_ttl(hop as u32)?;
        sock.set_nonblocking(true)?;
        let start = std::time::Instant::now();
        let _ = sock.connect(&dest.into());
        tokio::time::sleep(Duration::from_millis(300)).await;
        let elapsed = start.elapsed().as_millis() as u64;

        // Without ICMP we cannot see intermediate hops reliably; report attempt.
        emit(Event::PathHop {
            target,
            hop,
            addr: None,
            rtt_ms: Some(elapsed),
            label: format!("tcp-ttl={hop} probe"),
        });

        // If we can connect at this TTL, destination reached.
        let check = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        check.set_ttl(hop as u32)?;
        check.set_nonblocking(false)?;
        let _ = check.set_read_timeout(Some(Duration::from_millis(200)));
        if check.connect(&dest.into()).is_ok() {
            emit(Event::PathHop {
                target,
                hop,
                addr: Some(target),
                rtt_ms: Some(elapsed),
                label: "destination reached (tcp)".into(),
            });
            break;
        }
    }
    Ok(())
}

/// ICMP-ish reachability via system ping (portable).
pub async fn ping_host(addr: IpAddr) -> Option<u64> {
    let (program, args) = if cfg!(windows) {
        (
            "ping",
            vec!["-n".into(), "1".into(), "-w".into(), "1000".into(), addr.to_string()],
        )
    } else {
        (
            "ping",
            vec!["-c".into(), "1".into(), "-W".into(), "1".into(), addr.to_string()],
        )
    };
    let out = timeout(
        Duration::from_secs(3),
        Command::new(program).args(&args).output(),
    )
    .await
    .ok()?
    .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Windows: time=1ms / time<1ms   Linux: time=1.23 ms
    for token in text.split_whitespace() {
        let t = token
            .trim_start_matches("time=")
            .trim_start_matches("time<")
            .trim_end_matches("ms")
            .trim_end_matches("ms");
        if let Ok(v) = t.parse::<f64>() {
            return Some(v as u64);
        }
        if token.contains("time<") {
            return Some(1);
        }
    }
    Some(0)
}
