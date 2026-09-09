//! Finding taxonomy — maps stable finding *strings* to a rule class (id + CWE).
//!
//! Finding messages themselves stay unchanged (baselines/diff depend on them);
//! this layer derives a stable, machine-friendly classification for SARIF rules,
//! dashboards, and metrics without touching the wire text.

/// A stable classification for a finding, used to build tool rules / rule ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingClass {
    /// Stable slug used as a SARIF `ruleId` (kebab-case, never reused).
    pub id: &'static str,
    /// Human-readable rule title.
    pub title: &'static str,
    /// Best-effort CWE identifier (e.g. `"CWE-306"`), when one fits.
    pub cwe: Option<&'static str>,
    /// Coarse category tag for grouping (e.g. `"exposure"`, `"web"`, `"tls"`).
    pub category: &'static str,
}

const fn c(
    id: &'static str,
    title: &'static str,
    cwe: Option<&'static str>,
    category: &'static str,
) -> FindingClass {
    FindingClass {
        id,
        title,
        cwe,
        category,
    }
}

/// Classify a finding message into a stable rule class.
///
/// Uses the same keyword cascade style as [`crate::remediation::remediation_for`]
/// so the two stay in lock-step. Unknown findings fall back to a generic class.
pub fn classify(finding: &str) -> FindingClass {
    let f = finding.to_ascii_lowercase();

    // --- TLS / certificates -------------------------------------------------
    if f.contains("self-signed") {
        return c(
            "tls-self-signed-cert",
            "Self-signed TLS certificate",
            Some("CWE-295"),
            "tls",
        );
    }
    if f.contains("certificate expired") || f.contains("expires in") || f.contains("not_after") {
        return c(
            "tls-cert-expiry",
            "TLS certificate expiry issue",
            Some("CWE-298"),
            "tls",
        );
    }

    // --- HTTP hardening -----------------------------------------------------
    if f.contains("hsts") || f.contains("strict-transport-security") {
        return c(
            "http-missing-hsts",
            "Missing HTTP Strict-Transport-Security",
            Some("CWE-319"),
            "web",
        );
    }
    if f.contains("missing security header") {
        return c(
            "http-missing-security-header",
            "Missing HTTP security header",
            Some("CWE-693"),
            "web",
        );
    }
    if f.contains("cors") {
        return c(
            "http-permissive-cors",
            "Permissive CORS policy",
            Some("CWE-942"),
            "web",
        );
    }
    if f.contains("cookie") {
        return c(
            "http-insecure-cookie",
            "Insecure cookie flags",
            Some("CWE-614"),
            "web",
        );
    }
    if f.contains("http cleartext") {
        return c(
            "http-cleartext",
            "Cleartext HTTP service",
            Some("CWE-319"),
            "web",
        );
    }
    if f.contains("trace method") || f.contains("options method") {
        return c(
            "http-risky-method",
            "Risky HTTP method enabled",
            Some("CWE-16"),
            "web",
        );
    }
    if f.contains("server version disclosed")
        || f.contains("stack disclosure")
        || f.contains("debug header")
        || f.contains("x-debug")
        || f.contains("x-runtime")
        || f.contains("x-powered-by")
    {
        return c(
            "http-info-disclosure",
            "Server / stack information disclosure",
            Some("CWE-200"),
            "web",
        );
    }
    if f.contains("directory listing") {
        return c(
            "http-directory-listing",
            "Directory listing enabled",
            Some("CWE-548"),
            "web",
        );
    }
    if f.contains("sensitive path") {
        return c(
            "http-sensitive-path",
            "Sensitive path exposed",
            Some("CWE-538"),
            "web",
        );
    }
    if f.contains("control-plane path") {
        return c(
            "http-control-plane-exposed",
            "Control-plane API path exposed",
            Some("CWE-284"),
            "exposure",
        );
    }

    // --- Credentials / community strings ------------------------------------
    if f.contains("snmp") && f.contains("public") {
        return c(
            "snmp-default-community",
            "Default SNMP community string",
            Some("CWE-798"),
            "exposure",
        );
    }

    // --- Exposed data stores / services without auth ------------------------
    if f.contains("requires auth") || f.contains("verify auth") {
        return c(
            "service-network-exposed",
            "Sensitive service network-exposed",
            Some("CWE-668"),
            "exposure",
        );
    }
    let unauth_markers = [
        "without auth",
        "no auth",
        "unauthenticated",
        "anonymous",
        "responds without",
        "reachable",
        "exposed",
        "open —",
        "open -",
    ];
    let service_markers = [
        "redis",
        "mongodb",
        "elasticsearch",
        "memcached",
        "docker",
        "etcd",
        "consul",
        "kubernetes",
        "couchdb",
        "zookeeper",
        "prometheus",
        "grafana",
        "kibana",
        "jenkins",
        "keycloak",
        "portainer",
        "argocd",
        "argo cd",
        "sonarqube",
        "neo4j",
        "bolt",
        "clickhouse",
        "influxdb",
        "influx",
        "rethinkdb",
        "scylla",
        "elastic apm",
        "apm",
        "grpc",
        "vault",
        "nomad",
        "solr",
        "hazelcast",
        "opensearch",
        "minio",
        "kafka",
        "amqp",
        "rabbitmq",
        "mqtt",
        "nats",
        "ldap",
        "mssql",
        "oracle",
        "cassandra",
        "winrm",
        "rdp",
        "vnc",
        "ftp",
    ];
    let is_service = service_markers.iter().any(|m| f.contains(m));
    if is_service && unauth_markers.iter().any(|m| f.contains(m)) {
        return c(
            "service-missing-auth",
            "Service exposed without authentication",
            Some("CWE-306"),
            "exposure",
        );
    }
    if is_service {
        return c(
            "service-exposed",
            "Sensitive service exposed",
            Some("CWE-668"),
            "exposure",
        );
    }

    c("generic-finding", "Uncategorized finding", None, "other")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_findings() {
        assert_eq!(
            classify("Redis responds without AUTH (PONG)").id,
            "service-missing-auth"
        );
        assert_eq!(
            classify("Missing security header: strict-transport-security").id,
            "http-missing-hsts"
        );
        assert_eq!(
            classify("Missing security header: X-Frame-Options").id,
            "http-missing-security-header"
        );
        assert_eq!(
            classify("CORS reflects origin with credentials").id,
            "http-permissive-cors"
        );
        assert_eq!(
            classify("SNMP public community string readable").id,
            "snmp-default-community"
        );
        assert_eq!(classify("totally unknown xyz").id, "generic-finding");
        // A known service with only an exposure hint still classifies as exposed.
        assert_eq!(
            classify("MongoDB reachable on 27017").id,
            "service-missing-auth"
        );
    }

    #[test]
    fn cwe_present_for_known_classes() {
        assert_eq!(classify("Self-signed certificate").cwe, Some("CWE-295"));
        assert!(classify("totally unknown xyz").cwe.is_none());
    }
}
