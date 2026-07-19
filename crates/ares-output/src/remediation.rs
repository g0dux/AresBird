//! Finding remediation hints (stable finding *strings* stay unchanged for baselines).

/// Suggest a concrete fix for a known finding message (prefix / keyword match).
pub fn remediation_for(finding: &str) -> Option<&'static str> {
    let f = finding.to_ascii_lowercase();

    if f.contains("redis") && (f.contains("without auth") || f.contains("pong")) {
        return Some("Bind to localhost or private net; require `requirepass` / ACL; block 6379 at the edge.");
    }
    if f.contains("redis") && f.contains("requires auth") {
        return Some("Still network-exposed: restrict source IPs / security group even with AUTH.");
    }
    if f.contains("elasticsearch") {
        return Some("Enable native/X-Pack auth; do not expose 9200 publicly; put behind VPN or reverse proxy.");
    }
    if f.contains("memcached") {
        return Some("Bind Memcached to localhost; firewall UDP/TCP 11211; prefer authenticated cache (Redis with ACL).");
    }
    if f.contains("mongodb") {
        return Some(
            "Enable auth + TLS; bind to private interfaces; disable open `0.0.0.0` without auth.",
        );
    }
    if f.contains("docker engine") {
        return Some(
            "Never expose Docker API without TLS client auth; use SSH tunnel or local socket only.",
        );
    }
    if f.contains("etcd") {
        return Some(
            "Enable etcd auth + TLS peer/client certs; restrict 2379/2380 to control plane.",
        );
    }
    if f.contains("consul") {
        return Some("Enable ACLs; TLS; do not expose HTTP API (8500) to the internet.");
    }
    if f.contains("snmp") && f.contains("public") {
        return Some("Change community strings; prefer SNMPv3; ACL management plane; disable v1/v2c if unused.");
    }
    if f.contains("couchdb") {
        return Some("Require admin credentials; bind privately; disable guest access.");
    }
    if f.contains("zookeeper") {
        return Some(
            "Disable four-letter words in production (`4lw.commands.whitelist`); firewall 2181.",
        );
    }
    if f.contains("prometheus") {
        return Some("Do not expose /metrics publicly; put behind auth proxy; scrape only from monitoring net.");
    }
    if f.contains("neo4j") {
        return Some(
            "Require auth; disable remote HTTP/Bolt if unused; network-restrict 7474/7687.",
        );
    }
    if f.contains("jenkins") {
        return Some(
            "Require login; disable anonymous read; keep off public internet; update LTS.",
        );
    }
    if f.contains("grafana") {
        return Some(
            "Force login; disable anonymous; restrict 3000; review datasource credentials.",
        );
    }
    if f.contains("kibana") {
        return Some("Require Elastic auth; network-restrict 5601; avoid public exposure.");
    }
    if f.contains("ftp service exposed") {
        return Some("Prefer SFTP/FTPS; disable anonymous; restrict source nets.");
    }
    if f.contains("rdp service") {
        return Some("Do not expose RDP to internet; use VPN / Just-In-Time; NLA + MFA.");
    }
    if f.contains("vnc") {
        return Some("Tunnel VNC; require strong password; prefer proprietary remote with MFA.");
    }
    if f.contains("kubernetes api") {
        return Some("API server should not be public; use private endpoint + RBAC + audit.");
    }
    if f.contains("directory listing") {
        return Some("Disable autoindex / Options Indexes; return 403 for directory URLs.");
    }
    if f.contains("sensitive path") {
        return Some("Remove or ACL the path; ensure VCS/.env backups are not web-rooted.");
    }
    if f.contains("missing security header: strict-transport-security") || f.contains("hsts") {
        return Some(
            "Serve HTTPS and set `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
        );
    }
    if f.contains("missing security header") {
        return Some(
            "Add the missing header via reverse proxy / app framework security middleware.",
        );
    }
    if f.contains("cors") && f.contains("credentials") {
        return Some("Never combine `Access-Control-Allow-Origin: *` with credentials; use explicit origins.");
    }
    if f.contains("cors") {
        return Some("Tighten ACAO to known frontends; avoid `*` in production APIs.");
    }
    if f.contains("cookie") && f.contains("secure") {
        return Some("Set `Secure; HttpOnly; SameSite=Lax|Strict` on session cookies.");
    }
    if f.contains("cookie") {
        return Some("Review cookie flags (Secure/HttpOnly/SameSite) for session tokens.");
    }
    if f.contains("self-signed") {
        return Some(
            "Use a public CA or internal PKI; avoid self-signed on internet-facing hosts.",
        );
    }
    if f.contains("certificate expired") || f.contains("expires in") {
        return Some("Renew the certificate; automate with ACME/cert-manager; monitor expiry.");
    }
    if f.contains("server version disclosed") || f.contains("stack disclosure") {
        return Some("Strip/alter Server and X-Powered-By headers at the reverse proxy.");
    }
    if f.contains("http cleartext") {
        return Some("Redirect HTTP→HTTPS; enable HSTS after TLS is solid.");
    }
    if f.contains("trace method") {
        return Some("Disable TRACE/TRACK at the web server / WAF.");
    }
    if f.contains("kafka") {
        return Some("Require SASL/SSL; network-restrict brokers; avoid plaintext listeners.");
    }
    if f.contains("amqp") || f.contains("rabbitmq management") {
        return Some("Require auth; TLS; do not expose AMQP/management UI publicly.");
    }
    if f.contains("mqtt") {
        return Some("Require username/password or mTLS; ACL topics; firewall 1883/8883.");
    }
    if f.contains("ldap") {
        return Some("Disable anonymous bind; use LDAPS; restrict to corp networks.");
    }
    if f.contains("mssql") || f.contains("oracle tns") || f.contains("cassandra") {
        return Some("Require strong auth; private subnets only; no public DB listeners.");
    }
    if f.contains("minio") {
        return Some("Force auth; TLS; bucket policies least-privilege; private network.");
    }
    if f.contains("winrm") {
        return Some("Restrict WinRM to management jump hosts; prefer HTTPS listener + firewall.");
    }
    if f.contains("nats") {
        return Some("Enable NATS auth (token/nkey/TLS); do not expose client port publicly.");
    }
    if f.contains("clickhouse") {
        return Some("Require auth; bind privately; disable default user remote access.");
    }
    if f.contains("bolt exposed") || (f.contains("bolt") && f.contains("neo4j")) {
        return Some("Require Neo4j auth; TLS; restrict Bolt (7687) to app tier.");
    }
    if f.contains("debug header") || f.contains("x-debug") || f.contains("x-runtime") {
        return Some(
            "Strip debug/timing headers (`X-Debug`, `X-Runtime`, `X-Powered-By`) at the proxy.",
        );
    }
    if f.contains("options method") {
        return Some("Limit OPTIONS to CORS preflight needs; avoid echoing allow-all methods.");
    }
    if f.contains("control-plane path") {
        return Some(
            "Require auth on control-plane APIs; bind to private networks; block public ingress.",
        );
    }
    if f.contains("port") && f.contains("open — verify auth") {
        return Some("Confirm auth is required; restrict to private networks / jump hosts; close unused listeners.");
    }
    if f.contains("open|filtered") {
        return None;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_and_header_hints() {
        assert!(remediation_for("Redis responds without AUTH (PONG)")
            .unwrap()
            .to_ascii_lowercase()
            .contains("requirepass"));
        assert!(remediation_for("Missing security header: strict-transport-security").is_some());
        assert!(remediation_for("totally unknown finding xyz").is_none());
        assert!(
            remediation_for("NATS INFO greeting reachable — verify auth")
                .unwrap()
                .to_ascii_lowercase()
                .contains("nats")
        );
        assert!(remediation_for("Debug header exposed via X-Runtime: 12ms").is_some());
    }
}
