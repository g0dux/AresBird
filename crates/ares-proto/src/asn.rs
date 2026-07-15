//! ASN / org / CDN enrichment helpers.

use std::net::IpAddr;

use ares_core::event::Event;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

/// Well-known CDN / cloud fingerprints by DNS name fragment.
const CDN_HINTS: &[(&str, &str)] = &[
    ("cloudflare", "Cloudflare"),
    ("one.one.one.one", "Cloudflare"),
    ("cloudfront.net", "AWS CloudFront"),
    ("amazonaws.com", "AWS"),
    ("akamai", "Akamai"),
    ("akamaiedge", "Akamai"),
    ("fastly", "Fastly"),
    ("azureedge.net", "Azure CDN"),
    ("azure.com", "Azure"),
    ("googleusercontent", "Google"),
    ("googleapis", "Google"),
    ("googlevideo", "Google"),
    ("incapsula", "Imperva"),
    ("sucuri", "Sucuri"),
    ("stackpath", "StackPath"),
    ("edgekey.net", "Akamai"),
    ("edgesuite.net", "Akamai"),
    ("cdn77", "CDN77"),
    ("hwcdn", "Highwinds"),
    ("netdna", "StackPath/MaxCDN"),
];

/// ASN → CDN provider (when PTR/CNAME lacks an obvious hint).
const ASN_CDN: &[(&str, &str)] = &[
    ("AS13335", "Cloudflare"),
    ("AS54113", "Fastly"),
    ("AS16509", "AWS"),
    ("AS14618", "AWS"),
    ("AS20940", "Akamai"),
    ("AS16625", "Akamai"),
    ("AS15169", "Google"),
    ("AS8075", "Azure"),
    ("AS19551", "Incapsula"),
];

pub struct AsnEngine {
    resolver: TokioAsyncResolver,
}

impl AsnEngine {
    pub fn system() -> anyhow::Result<Self> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(Self { resolver })
    }

    /// Lookup ASN via Team Cymru DNS (IPv4) or best-effort IPv6 origin6.
    pub async fn lookup_asn(&self, addr: IpAddr, emit: impl Fn(Event)) -> Option<(String, String)> {
        let qname = match addr {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
            }
            IpAddr::V6(_) => {
                // IPv6 Cymru origin6 omitted in this version — skip silently
                return None;
            }
        };

        match self.resolver.txt_lookup(&qname).await {
            Ok(txt) => {
                for rec in txt.iter() {
                    let data = rec
                        .txt_data()
                        .iter()
                        .map(|b| String::from_utf8_lossy(b).to_string())
                        .collect::<Vec<_>>()
                        .join("");
                    // Format: "15169 | 8.8.8.0/24 | US | arin | 2023-01-01"
                    let parts: Vec<_> = data.split('|').map(|s| s.trim()).collect();
                    if let Some(asn) = parts.first() {
                        let org = if parts.len() >= 4 {
                            format!("{} / {}", parts.get(2).unwrap_or(&""), parts.get(3).unwrap_or(&""))
                        } else {
                            data.clone()
                        };
                        let asn = if asn.starts_with("AS") {
                            asn.to_string()
                        } else {
                            format!("AS{asn}")
                        };
                        emit(Event::AsnInfo {
                            addr,
                            asn: asn.clone(),
                            org: org.clone(),
                        });
                        if let Some(cdn) = Self::cdn_for_asn(&asn) {
                            emit(Event::ProbeResult {
                                addr,
                                port: 0,
                                probe: "cdn-detect".into(),
                                detail: format!("{cdn} (via {asn})"),
                                confidence: 0.7,
                            });
                        }
                        return Some((asn, org));
                    }
                }
                None
            }
            Err(_) => None,
        }
    }

    /// Detect CDN from a hostname / CNAME value.
    pub fn detect_cdn(name: &str) -> Option<&'static str> {
        let l = name.to_lowercase();
        for (needle, label) in CDN_HINTS {
            if l.contains(needle) {
                return Some(label);
            }
        }
        None
    }

    pub fn cdn_for_asn(asn: &str) -> Option<&'static str> {
        let upper = asn.to_ascii_uppercase();
        ASN_CDN
            .iter()
            .find(|(a, _)| *a == upper)
            .map(|(_, label)| *label)
    }

    /// Reverse DNS + CDN hint for an IP.
    pub async fn enrich_host(&self, addr: IpAddr, emit: impl Fn(Event) + Clone) {
        self.lookup_asn(addr, emit.clone()).await;

        // PTR
        let ptr_name = match addr {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
            }
            IpAddr::V6(_) => return,
        };
        if let Ok(ptr) = self.resolver.reverse_lookup(addr).await {
            for name in ptr.iter() {
                let s = name.to_string().trim_end_matches('.').to_string();
                emit(Event::DnsRecord {
                    name: ptr_name.clone(),
                    record_type: "PTR".into(),
                    value: s.clone(),
                });
                if let Some(cdn) = Self::detect_cdn(&s) {
                    emit(Event::ProbeResult {
                        addr,
                        port: 0,
                        probe: "cdn-detect".into(),
                        detail: format!("{cdn} (via PTR {s})"),
                        confidence: 0.75,
                    });
                }
            }
        }
    }

    /// CDN detect from already-known DNS names in graph / recon.
    pub fn emit_cdn_for_name(addr: Option<IpAddr>, name: &str, emit: impl Fn(Event)) {
        if let Some(cdn) = Self::detect_cdn(name) {
            if let Some(addr) = addr {
                emit(Event::ProbeResult {
                    addr,
                    port: 0,
                    probe: "cdn-detect".into(),
                    detail: format!("{cdn} (via {name})"),
                    confidence: 0.8,
                });
            } else {
                emit(Event::Log {
                    level: "info".into(),
                    message: format!("CDN hint: {cdn} for {name}"),
                });
            }
        }
    }
}
