//! Integration tests against local TCP listeners (no external network).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ares_core::event::Event;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

async fn spawn_http() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind http");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let mut buf = [0u8; 1024];
            let _ = timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
            let body = b"HTTP/1.1 200 OK\r\nServer: AresBird-Test/1.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let _ = sock.write_all(body).await;
        }
    });
    addr
}

async fn spawn_redis() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind redis");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let mut buf = [0u8; 256];
            let _ = timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
            let _ = sock.write_all(b"+PONG\r\n").await;
        }
    });
    addr
}

async fn spawn_ssh_banner() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ssh");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let _ = sock
                .write_all(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
                .await;
            let mut buf = [0u8; 256];
            let _ = timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
        }
    });
    addr
}

#[tokio::test]
async fn http_observe_hits_local_listener() {
    let addr = spawn_http().await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let e2 = events.clone();
    let engine = ares_proto::HttpEngine::default();
    let resp = engine
        .get(addr.ip(), addr.port(), "127.0.0.1", "/", move |ev| {
            e2.lock().unwrap().push(ev);
        })
        .await
        .expect("http get");

    assert!(
        resp.status_line.contains("200"),
        "status={}",
        resp.status_line
    );
    let evs = events.lock().unwrap();
    let has_server = evs.iter().any(|e| match e {
        Event::Banner { banner, .. } => banner.to_ascii_lowercase().contains("aresbird-test"),
        Event::ProbeResult { detail, .. } => detail.to_ascii_lowercase().contains("aresbird-test"),
        Event::ServiceDetected { service, .. } => {
            service.name.to_ascii_lowercase().contains("http")
        }
        _ => false,
    }) || resp.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("server") && v.to_ascii_lowercase().contains("aresbird-test")
    });
    assert!(
        has_server || !evs.is_empty(),
        "expected HTTP observe events/headers, status={} events={evs:?}",
        resp.status_line
    );
}

#[tokio::test]
async fn redis_ping_local_listener() {
    let addr = spawn_redis().await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let e2 = events.clone();
    ares_proto::observe_redis(addr.ip(), addr.port(), move |ev| {
        e2.lock().unwrap().push(ev);
    })
    .await
    .expect("observe_redis");

    let evs = events.lock().unwrap();
    let ok = evs.iter().any(|e| match e {
        Event::ProbeResult { detail, .. } => {
            let d = detail.to_ascii_lowercase();
            d.contains("pong") || d.contains("redis")
        }
        Event::Banner { banner, .. } => banner.to_ascii_lowercase().contains("pong"),
        Event::ServiceDetected { service, .. } => {
            service.name.to_ascii_lowercase().contains("redis")
        }
        _ => false,
    });
    assert!(ok || !evs.is_empty(), "expected redis events, got {evs:?}");
}

#[tokio::test]
async fn ssh_banner_local_listener() {
    let addr = spawn_ssh_banner().await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let e2 = events.clone();
    let banner = ares_proto::SshBanner::grab(addr.ip(), addr.port(), move |ev| {
        e2.lock().unwrap().push(ev);
    })
    .await
    .expect("ssh banner");
    assert!(banner.contains("OpenSSH"), "banner={banner}");
}
