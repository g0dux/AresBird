//! Built-in sensitive-path wordlists for authorized web misconfig observes.
//! Content-matched hits only — not an exploit scanner.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathProfile {
    /// Balanced default (legacy + common leaks)
    Default,
    /// API / swagger / actuator oriented
    Api,
    /// Broader web (backup, admin, debug, cms)
    Web,
    /// Union of profiles (still small / curated)
    All,
}

impl PathProfile {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "default" | "std" | "standard" => Some(Self::Default),
            "api" => Some(Self::Api),
            "web" => Some(Self::Web),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    pub fn paths(self) -> Vec<&'static str> {
        match self {
            Self::Default => DEFAULT_PATHS.to_vec(),
            Self::Api => unique(DEFAULT_PATHS.iter().chain(API_PATHS.iter())),
            Self::Web => unique(DEFAULT_PATHS.iter().chain(WEB_PATHS.iter())),
            Self::All => unique(
                DEFAULT_PATHS
                    .iter()
                    .chain(API_PATHS.iter())
                    .chain(WEB_PATHS.iter()),
            ),
        }
    }
}

fn unique<'a>(iter: impl Iterator<Item = &'a &'static str>) -> Vec<&'static str> {
    let mut out = Vec::new();
    for &p in iter {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

const DEFAULT_PATHS: &[&str] = &[
    "/.git/HEAD",
    "/.git/config",
    "/server-status",
    "/.env",
    "/actuator/health",
    "/actuator/env",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/phpinfo.php",
];

const API_PATHS: &[&str] = &[
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/configprops",
    "/swagger-ui/index.html",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/graphql",
    "/graphiql",
    "/.well-known/openid-configuration",
];

const WEB_PATHS: &[&str] = &[
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.hg/requires",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/env",
    "/config.json",
    "/config.yml",
    "/web.config",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/debug",
    "/debug/default/view",
    "/_debugbar",
    "/console",
    "/admin",
    "/administrator",
    "/wp-admin/",
    "/wp-login.php",
    "/wp-config.php.bak",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/dump.sql",
    "/.DS_Store",
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    // Observability / CI surfaces often left open
    "/metrics",
    "/-/healthy",
    "/-/ready",
    "/api/v1/status/buildinfo",
    "/api/health",
    "/login",
    "/jenkins/login",
    "/script",
    "/manage",
    "/asynchPeople/",
];

/// Severity hint for known paths (unknown custom → low).
pub fn path_severity(path: &str) -> &'static str {
    let p = path.trim_end_matches('/');
    match p {
        "/.git/HEAD" | "/.git/config" | "/.svn/entries" | "/.env" | "/.env.local"
        | "/.env.production" | "/.env.backup" | "/actuator/env" | "/wp-config.php.bak"
        | "/db.sql" | "/dump.sql" | "/script" => "high",
        "/server-status"
        | "/server-info"
        | "/phpinfo.php"
        | "/info.php"
        | "/actuator/beans"
        | "/actuator/mappings"
        | "/actuator/configprops"
        | "/backup.zip"
        | "/backup.tar.gz"
        | "/graphql"
        | "/graphiql"
        | "/debug"
        | "/console"
        | "/metrics"
        | "/manage"
        | "/api/v1/status/buildinfo" => "medium",
        _ => "low",
    }
}

/// Content fingerprint — require 200 + body cues (avoid soft-404 HTML).
pub fn sensitive_path_hit(path: &str, status: &str, body: &str) -> bool {
    if !status.contains("200") || body.trim().is_empty() {
        return false;
    }
    let b = body.to_lowercase();
    let path = path.trim_end_matches('/');

    let allows_html = matches!(
        path,
        "/server-status"
            | "/server-info"
            | "/swagger-ui.html"
            | "/swagger-ui"
            | "/swagger-ui/index.html"
            | "/phpinfo.php"
            | "/info.php"
            | "/graphiql"
            | "/admin"
            | "/administrator"
            | "/wp-admin"
            | "/wp-login.php"
            | "/debug"
            | "/console"
            | "/_debugbar"
            | "/robots.txt"
            | "/sitemap.xml"
            | "/security.txt"
            | "/.well-known/security.txt"
            | "/login"
            | "/jenkins/login"
            | "/manage"
    );
    if b.contains("<html") && !allows_html {
        // Still allow some structured non-leak pages
        if !(b.contains("swagger") || b.contains("openapi") || b.contains("phpinfo")) {
            return false;
        }
    }

    match path {
        "/.git/HEAD" => b.starts_with("ref:") || b.contains("refs/heads"),
        "/.git/config" => b.contains("[core]") || b.contains("repositoryformatversion"),
        "/.svn/entries" => b.contains("dir") || b.contains("svn"),
        "/.hg/requires" => b.contains("dotencode") || b.contains("revlog"),
        "/server-status" | "/server-info" => {
            b.contains("apache") || b.contains("server status") || b.contains("scoreboard")
        }
        p if p.starts_with("/.env") || p == "/env" => {
            b.contains("app_key=")
                || b.contains("db_password=")
                || b.contains("database_url=")
                || b.contains("aws_secret")
                || b.contains("secret_key=")
                || b.lines().any(|l| {
                    let t = l.trim();
                    !t.is_empty()
                        && !t.starts_with('#')
                        && t.contains('=')
                        && !t.contains('<')
                        && t.len() < 200
                })
        }
        "/actuator/health" => b.contains("\"status\"") && (b.contains("up") || b.contains("down")),
        "/actuator/env" | "/actuator/configprops" => {
            b.contains("propertysources")
                || b.contains("systemproperties")
                || b.contains("activeprofiles")
                || b.contains("\"beans\"")
        }
        "/actuator" | "/actuator/info" | "/actuator/beans" | "/actuator/mappings" => {
            b.contains("\"_links\"")
                || b.contains("\"status\"")
                || b.contains("\"beans\"")
                || b.contains("\"contexts\"")
                || b.contains("dispatcherservlets")
                || b.contains("\"mappings\"")
        }
        p if p.contains("swagger") || p.contains("api-docs") || p.contains("openapi") => {
            b.contains("swagger")
                || b.contains("openapi")
                || b.contains("\"paths\"")
                || b.contains("\"info\"")
        }
        "/graphql" => {
            b.contains("graphql")
                || b.contains("\"errors\"")
                || b.contains("query")
                || b.contains("__schema")
        }
        "/graphiql" => b.contains("graphiql") || b.contains("graphql"),
        "/phpinfo.php" | "/info.php" | "/test.php" => {
            b.contains("php version") || b.contains("phpinfo()") || b.contains("phpcredits")
        }
        "/config.json" => {
            b.contains('{') && (b.contains("api") || b.contains("password") || b.contains("secret"))
        }
        "/web.config" => b.contains("<configuration") || b.contains("<system.web"),
        "/wp-config.php.bak" => {
            b.contains("db_name") || b.contains("db_password") || b.contains("<?php")
        }
        "/backup.zip" | "/backup.tar.gz" | "/db.sql" | "/dump.sql" => {
            // binary / SQL cues without claiming exploitability
            body.len() > 64
                && (b.contains("create table")
                    || b.contains("insert into")
                    || body.as_bytes().starts_with(b"PK")
                    || body.as_bytes().starts_with(&[0x1f, 0x8b]))
        }
        "/.DS_Store" => {
            body.len() > 20
                && (b.contains("bud1") || body.as_bytes().starts_with(b"\0\0\0\x01Bud1"))
        }
        "/robots.txt" => b.contains("user-agent") || b.contains("disallow"),
        "/sitemap.xml" => b.contains("<urlset") || b.contains("<sitemapindex"),
        "/security.txt" | "/.well-known/security.txt" => {
            b.contains("contact:") || b.contains("expires:")
        }
        "/.well-known/openid-configuration" => {
            b.contains("issuer") && b.contains("authorization_endpoint")
        }
        "/admin" | "/administrator" | "/wp-admin" | "/wp-login.php" | "/console" | "/debug"
        | "/_debugbar" | "/login" | "/jenkins/login" | "/manage" => {
            b.contains("login")
                || b.contains("password")
                || b.contains("dashboard")
                || b.contains("wordpress")
                || b.contains("debugbar")
                || b.contains("jenkins")
                || b.contains("sign in")
        }
        "/metrics" => b.contains("# help") || b.contains("# type") || b.contains("prometheus_"),
        "/-/healthy" | "/-/ready" => {
            b.contains("prometheus") || b.trim() == "ok" || b.contains("healthy")
        }
        "/api/v1/status/buildinfo" => b.contains("version") || b.contains("prometheus"),
        "/api/health" => b.contains("database") || b.contains("version") || b.contains("\"ok\""),
        "/script" | "/asynchPeople" => b.contains("jenkins") || b.contains("script"),
        _ => {
            // Custom file paths: treat non-HTML 200 with content as weak signal
            !b.contains("<html") && body.len() > 20
        }
    }
}

/// Load extra paths from a text file (# comments, one path per line).
pub fn load_paths_file(path: &std::path::Path) -> anyhow::Result<Vec<String>> {
    let text = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let p = if line.starts_with('/') {
            line.to_string()
        } else {
            format!("/{line}")
        };
        if !out.contains(&p) {
            out.push(p);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_head_hit() {
        assert!(sensitive_path_hit(
            "/.git/HEAD",
            "HTTP/1.1 200 OK",
            "ref: refs/heads/main\n"
        ));
    }

    #[test]
    fn soft404_html_ignored_for_env() {
        assert!(!sensitive_path_hit(
            "/.env",
            "HTTP/1.1 200 OK",
            "<html><body>not found</body></html>"
        ));
    }

    #[test]
    fn profiles_grow() {
        assert!(PathProfile::All.paths().len() > PathProfile::Default.paths().len());
    }
}
