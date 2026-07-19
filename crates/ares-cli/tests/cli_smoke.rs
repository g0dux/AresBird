//! CLI smoke tests (build the `ares` binary via cargo test).
//!
//! On some Windows hosts Smart App Control (os error 4551) blocks spawning the
//! freshly built test binary — those cases are skipped so `cargo test` stays green locally.
//! Linux CI always runs the full suite.

use std::io;
use std::path::PathBuf;
use std::process::{Command, Output};

fn ares_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ares"))
}

fn is_blocked_by_policy(err: &io::Error) -> bool {
    // Windows Smart App Control / WDAC
    err.raw_os_error() == Some(4551)
}

fn run_ares(args: &[&str]) -> Option<Output> {
    match Command::new(ares_bin())
        .args(args)
        .env("ARES_QUIET", "1")
        .env("NO_COLOR", "1")
        .output()
    {
        Ok(out) => Some(out),
        Err(e) if is_blocked_by_policy(&e) => {
            eprintln!("skip CLI spawn (App Control blocked binary): {e}");
            None
        }
        Err(e) => panic!("spawn ares: {e}"),
    }
}

#[test]
fn version_exits_zero() {
    let Some(out) = run_ares(&["version", "-q"]) else {
        return;
    };
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("AresBird"), "{stdout}");
}

#[test]
fn doctor_exits_zero() {
    let Some(out) = run_ares(&["doctor", "-q"]) else {
        return;
    };
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn scripts_list_finds_default_pack() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let out = match Command::new(ares_bin())
        .args(["scripts", "list", "-q"])
        .current_dir(&root)
        .env("ARES_QUIET", "1")
        .env("ARES_PACKS_DIR", root.join("packs"))
        .output()
    {
        Ok(o) => o,
        Err(e) if is_blocked_by_policy(&e) => {
            eprintln!("skip CLI spawn (App Control blocked binary): {e}");
            return;
        }
        Err(e) => panic!("spawn: {e}"),
    };
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("default"),
        "expected default pack in output: {combined}"
    );
}

#[test]
fn scan_localhost_ephemeral() {
    let Some(out) = run_ares(&[
        "scan",
        "127.0.0.1",
        "-p",
        "22,80,443",
        "-m",
        "fast",
        "-q",
        "--ephemeral",
    ]) else {
        return;
    };
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn probe_quick_localhost_ephemeral() {
    let Some(out) = run_ares(&[
        "probe",
        "quick",
        "127.0.0.1",
        "-m",
        "fast",
        "-q",
        "--ephemeral",
    ]) else {
        return;
    };
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn workspace_roundtrip_via_store() {
    use ares_core::event::Event;
    use ares_core::{AssetGraph, EventCollector};
    use ares_output::RunStore;
    use std::net::{IpAddr, Ipv4Addr};

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("runs.db");
    let store = RunStore::open(&db).expect("open store");
    let mut graph = AssetGraph::new();
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    graph.apply(&Event::HostUp {
        addr,
        latency_ms: Some(1),
        method: "test".into(),
    });
    let collector = EventCollector::new();
    store
        .upsert_workspace("ci-test-ws", &collector, &graph)
        .expect("upsert");

    let loaded = store.load_workspace("ci-test-ws").expect("load");
    assert_eq!(loaded.hosts.len(), 1);
    assert!(loaded.hosts.get(&addr).is_some_and(|h| h.up));
}
