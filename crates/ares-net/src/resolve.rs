use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;

use ares_core::error::{CoreError, Result};
use ipnet::IpNet;

#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub addr: IpAddr,
    pub original: String,
}

/// Resolve hostnames, single IPs, and CIDR ranges into concrete addresses.
pub fn resolve_targets(specs: &[String]) -> Result<Vec<ResolvedTarget>> {
    let mut out = Vec::new();
    for spec in specs {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        if let Ok(net) = IpNet::from_str(spec) {
            // Cap huge ranges for safety in v0.1 (caller can override later)
            let hosts: Vec<IpAddr> = net.hosts().collect();
            if hosts.len() > 65_536 {
                return Err(CoreError::InvalidTarget(format!(
                    "CIDR {spec} expands to {} hosts (max 65536 in this version)",
                    hosts.len()
                )));
            }
            for addr in hosts {
                out.push(ResolvedTarget {
                    addr,
                    original: spec.to_string(),
                });
            }
            continue;
        }
        if let Ok(addr) = IpAddr::from_str(spec) {
            out.push(ResolvedTarget {
                addr,
                original: spec.to_string(),
            });
            continue;
        }
        // hostname — resolve via system DNS
        let lookup = format!("{spec}:0");
        match lookup.to_socket_addrs() {
            Ok(iter) => {
                let mut found = false;
                for sa in iter {
                    out.push(ResolvedTarget {
                        addr: sa.ip(),
                        original: spec.to_string(),
                    });
                    found = true;
                }
                if !found {
                    return Err(CoreError::InvalidTarget(format!(
                        "hostname resolved to nothing: {spec}"
                    )));
                }
            }
            Err(e) => {
                return Err(CoreError::InvalidTarget(format!(
                    "cannot resolve '{spec}': {e}"
                )));
            }
        }
    }
    if out.is_empty() {
        return Err(CoreError::InvalidTarget("no targets".into()));
    }
    // Dedup by IP preserving order
    let mut seen = std::collections::HashSet::new();
    out.retain(|t| seen.insert(t.addr));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_ip() {
        let t = resolve_targets(&["127.0.0.1".into()]).unwrap();
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn resolve_cidr_small() {
        let t = resolve_targets(&["192.168.0.0/30".into()]).unwrap();
        assert_eq!(t.len(), 2); // /30 has 2 usable hosts
    }
}
