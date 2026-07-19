use std::net::IpAddr;
use std::time::Duration;

use ares_core::event::Event;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use tracing::warn;

pub struct DnsEngine {
    resolver: TokioAsyncResolver,
}

impl DnsEngine {
    pub fn system() -> anyhow::Result<Self> {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(3);
        opts.attempts = 2;
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);
        Ok(Self { resolver })
    }

    pub async fn resolve_a(&self, name: &str, emit: impl Fn(Event)) -> Vec<IpAddr> {
        let mut out = Vec::new();
        match self.resolver.lookup_ip(name).await {
            Ok(lookup) => {
                for ip in lookup.iter() {
                    emit(Event::DnsRecord {
                        name: name.to_string(),
                        record_type: if ip.is_ipv4() {
                            "A".into()
                        } else {
                            "AAAA".into()
                        },
                        value: ip.to_string(),
                    });
                    out.push(ip);
                }
            }
            Err(e) => warn!(name, error = %e, "DNS lookup failed"),
        }
        out
    }

    pub async fn query_mx(&self, name: &str, emit: impl Fn(Event)) {
        if let Ok(mx) = self.resolver.mx_lookup(name).await {
            for rec in mx.iter() {
                emit(Event::DnsRecord {
                    name: name.to_string(),
                    record_type: "MX".into(),
                    value: format!("{} {}", rec.preference(), rec.exchange()),
                });
            }
        }
    }

    pub async fn query_ns(&self, name: &str, emit: impl Fn(Event)) {
        if let Ok(ns) = self.resolver.ns_lookup(name).await {
            for rec in ns.iter() {
                emit(Event::DnsRecord {
                    name: name.to_string(),
                    record_type: "NS".into(),
                    value: rec.to_string(),
                });
            }
        }
    }

    pub async fn query_txt(&self, name: &str, emit: impl Fn(Event)) {
        if let Ok(txt) = self.resolver.txt_lookup(name).await {
            for rec in txt.iter() {
                let data = rec
                    .txt_data()
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect::<Vec<_>>()
                    .join("");
                emit(Event::DnsRecord {
                    name: name.to_string(),
                    record_type: "TXT".into(),
                    value: data,
                });
            }
        }
    }

    /// Full recon-oriented resolution for a domain.
    pub async fn enrich_domain(
        &self,
        name: &str,
        emit: impl Fn(Event) + Send + Sync + Clone,
    ) -> Vec<IpAddr> {
        let ips = self.resolve_a(name, emit.clone()).await;
        self.query_mx(name, emit.clone()).await;
        self.query_ns(name, emit.clone()).await;
        self.query_txt(name, emit.clone()).await;
        for sub in [
            "www", "mail", "ftp", "vpn", "api", "dev", "staging", "admin", "portal", "ns1",
        ] {
            let fqdn = format!("{sub}.{name}");
            let _ = self.resolve_a(&fqdn, emit.clone()).await;
        }
        ips
    }
}
