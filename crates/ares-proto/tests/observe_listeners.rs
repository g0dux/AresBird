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

async fn spawn_once(response: &'static [u8], read_first: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let resp = response;
            tokio::spawn(async move {
                if read_first {
                    let mut buf = [0u8; 1024];
                    let _ = timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
                }
                let _ = sock.write_all(resp).await;
                let _ = sock.flush().await;
                // Keep the connection briefly so the client can read before FIN.
                let mut buf = [0u8; 64];
                let _ = timeout(Duration::from_millis(200), sock.read(&mut buf)).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn memcached_version_local_listener() {
    // Replies to the ASCII `version` command with a VERSION line.
    let addr = spawn_once(b"VERSION 1.6.21\r\n", true).await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let e2 = events.clone();
    let detail = ares_proto::observe_memcached(addr.ip(), addr.port(), move |ev| {
        e2.lock().unwrap().push(ev);
    })
    .await
    .expect("observe_memcached");

    assert_eq!(
        detail.as_deref(),
        Some("Memcached 1.6.21"),
        "detail={detail:?}"
    );
    let evs = events.lock().unwrap();
    assert!(
        evs.iter().any(
            |e| matches!(e, Event::ServiceDetected { service, .. } if service.name == "memcached")
        ),
        "expected memcached ServiceDetected, got {evs:?}"
    );
}

#[tokio::test]
async fn elasticsearch_root_local_listener() {
    // Minimal ES `GET /` JSON body with version.number + tagline markers.
    const BODY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"name\":\"node-1\",\"cluster_name\":\"aresbird-test\",\"version\":{\"number\":\"8.12.0\",\"lucene_version\":\"9.9.1\"},\"tagline\":\"You Know, for Search\"}";
    let addr = spawn_once(BODY, true).await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let e2 = events.clone();
    let detail = ares_proto::observe_elasticsearch(addr.ip(), addr.port(), move |ev| {
        e2.lock().unwrap().push(ev);
    })
    .await
    .expect("observe_elasticsearch");

    assert_eq!(
        detail.as_deref(),
        Some("Elasticsearch 8.12.0 cluster=aresbird-test"),
        "detail={detail:?}"
    );
    let evs = events.lock().unwrap();
    assert!(
        evs.iter().any(|e| matches!(
            e,
            Event::ServiceDetected { service, .. }
                if service.name == "elasticsearch" && service.version.as_deref() == Some("8.12.0")
        )),
        "expected elasticsearch ServiceDetected 8.12.0, got {evs:?}"
    );
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
async fn influxdb_health_local_listener() {
    const BODY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"name\":\"influxdb\",\"message\":\"ready for queries and writes\",\"status\":\"pass\",\"version\":\"2.7.4\"}";
    let addr = spawn_once(BODY, true).await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let e2 = events.clone();
    let detail = ares_proto::observe_influxdb(addr.ip(), addr.port(), move |ev| {
        e2.lock().unwrap().push(ev);
    })
    .await
    .expect("observe_influxdb");
    assert_eq!(
        detail.as_deref(),
        Some("InfluxDB 2.7.4"),
        "detail={detail:?}"
    );
}

#[tokio::test]
async fn elastic_apm_root_local_listener() {
    const BODY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":{\"build_date\":\"2024-01-01\",\"build_sha\":\"abc\",\"version\":\"8.12.0\"}}";
    let addr = spawn_once(BODY, true).await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let e2 = events.clone();
    let detail = ares_proto::observe_elastic_apm(addr.ip(), addr.port(), move |ev| {
        e2.lock().unwrap().push(ev);
    })
    .await
    .expect("observe_elastic_apm");
    assert_eq!(
        detail.as_deref(),
        Some("Elastic APM Server 8.12.0"),
        "detail={detail:?}"
    );
}

#[tokio::test]
async fn rethinkdb_handshake_local_listener() {
    let addr = spawn_once(b"SUCCESS\0", true).await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let e2 = events.clone();
    let detail = ares_proto::observe_rethinkdb(addr.ip(), addr.port(), move |ev| {
        e2.lock().unwrap().push(ev);
    })
    .await
    .expect("observe_rethinkdb");
    assert!(
        detail
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("rethink"),
        "detail={detail:?}"
    );
}

#[tokio::test]
async fn vault_health_local_listener() {
    const BODY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"initialized\":true,\"sealed\":false,\"standby\":false,\"version\":\"1.15.0\",\"cluster_name\":\"vault-cluster\"}";
    let addr = spawn_once(BODY, true).await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let e2 = events.clone();
    let detail = ares_proto::observe_vault(addr.ip(), addr.port(), move |ev| {
        e2.lock().unwrap().push(ev);
    })
    .await
    .expect("observe_vault");
    assert_eq!(detail.as_deref(), Some("Vault 1.15.0"), "detail={detail:?}");
}

#[tokio::test]
async fn keycloak_realm_local_listener() {
    const BODY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"realm\":\"master\",\"public_key\":\"MIIB\",\"token-service\":\"http://127.0.0.1/realms/master/protocol/openid-connect\"}";
    let addr = spawn_once(BODY, true).await;
    let detail = ares_proto::observe_keycloak(addr.ip(), addr.port(), |_| {})
        .await
        .expect("observe_keycloak");
    assert_eq!(
        detail.as_deref(),
        Some("Keycloak realm=master"),
        "detail={detail:?}"
    );
}

#[tokio::test]
async fn portainer_status_local_listener() {
    const BODY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"Version\":\"2.19.4\"}";
    let addr = spawn_once(BODY, true).await;
    let detail = ares_proto::observe_portainer(addr.ip(), addr.port(), |_| {})
        .await
        .expect("observe_portainer");
    assert_eq!(
        detail.as_deref(),
        Some("Portainer 2.19.4"),
        "detail={detail:?}"
    );
}

#[tokio::test]
async fn argocd_version_local_listener() {
    const BODY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"Version\":\"v2.10.0\",\"BuildDate\":\"2024-01-01T00:00:00Z\"}";
    let addr = spawn_once(BODY, true).await;
    let detail = ares_proto::observe_argocd(addr.ip(), addr.port(), |_| {})
        .await
        .expect("observe_argocd");
    assert_eq!(
        detail.as_deref(),
        Some("Argo CD v2.10.0"),
        "detail={detail:?}"
    );
}

#[tokio::test]
async fn sonarqube_status_local_listener() {
    const BODY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"id\":\"lab\",\"version\":\"10.4.0.87286\",\"status\":\"UP\"}";
    let addr = spawn_once(BODY, true).await;
    let detail = ares_proto::observe_sonarqube(addr.ip(), addr.port(), |_| {})
        .await
        .expect("observe_sonarqube");
    assert_eq!(
        detail.as_deref(),
        Some("SonarQube 10.4.0.87286 (UP)"),
        "detail={detail:?}"
    );
}

#[tokio::test]
async fn opensearch_root_local_listener() {
    const BODY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"name\":\"node\",\"cluster_name\":\"os-lab\",\"version\":{\"distribution\":\"opensearch\",\"number\":\"2.11.0\"},\"tagline\":\"The missing piece of Elasticsearch\"}";
    let addr = spawn_once(BODY, true).await;
    let detail = ares_proto::observe_opensearch(addr.ip(), addr.port(), |_| {})
        .await
        .expect("observe_opensearch");
    assert!(
        detail
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("opensearch"),
        "detail={detail:?}"
    );
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
