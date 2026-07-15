use std::net::IpAddr;

use ares_core::event::Event;

/// Latency / locality bucket (low confidence — overwritten by banner/protocol hints).
pub fn guess_os_from_ttl_rtt(addr: IpAddr, rtt_ms: Option<u64>, emit: impl Fn(Event)) {
    let (os, confidence) = match rtt_ms {
        Some(0..=5) => ("local/low-latency endpoint", 0.2),
        Some(6..=50) => ("nearby host / LAN or close WAN", 0.15),
        Some(_) => ("remote host", 0.1),
        None => ("unknown", 0.05),
    };
    emit_os(addr, os, confidence, emit);
}

/// Classic IP initial-TTL buckets when an observed reply TTL is available.
///
/// Common defaults: Linux/Unix≈64, Windows≈128, some network gear≈255.
pub fn guess_os_from_observed_ttl(addr: IpAddr, observed_ttl: u8, emit: impl Fn(Event)) {
    let (os, confidence) = ttl_family(observed_ttl);
    emit_os_ttl(addr, os, confidence, Some(observed_ttl), emit);
}

fn ttl_family(observed_ttl: u8) -> (&'static str, f32) {
    if (32..=64).contains(&observed_ttl) {
        ("Linux/Unix family (TTL≈64)", 0.45)
    } else if (65..=128).contains(&observed_ttl) {
        ("Windows family (TTL≈128)", 0.45)
    } else if observed_ttl > 128 {
        ("network appliance / high-TTL stack (TTL≈255)", 0.35)
    } else {
        ("unknown (low TTL — many hops)", 0.15)
    }
}

/// Passive OS hints from service banners / HTTP Server headers / SSH ids.
pub fn guess_os_from_banner(addr: IpAddr, banner: &str, emit: impl Fn(Event)) {
    if let Some((os, conf)) = infer_from_text(banner) {
        emit_os(addr, os, conf, emit);
    }
}

/// Correlate banner (+ optional observed TTL) into a stronger single guess.
pub fn guess_os_correlated(
    addr: IpAddr,
    banner: Option<&str>,
    observed_ttl: Option<u8>,
    emit: impl Fn(Event),
) {
    let banner_hit = banner.and_then(infer_from_text);
    let ttl_hit = observed_ttl.map(ttl_family);

    match (banner_hit, ttl_hit) {
        (Some((bos, bc)), Some((tos, tc))) => {
            let b = bos.to_ascii_lowercase();
            let t = tos.to_ascii_lowercase();
            let agree_windows = b.contains("windows") && t.contains("windows");
            let agree_unix = (b.contains("linux")
                || b.contains("unix")
                || b.contains("bsd")
                || b.contains("darwin")
                || b.contains("macos"))
                && (t.contains("linux") || t.contains("unix"));
            if agree_windows || agree_unix {
                let conf = (bc + 0.25).min(0.92);
                let label = format!("{bos} (TTL agrees)");
                emit_os_ttl(addr, &label, conf, observed_ttl, emit);
            } else if bc >= tc {
                emit_os_ttl(addr, bos, bc, observed_ttl, emit);
            } else {
                emit_os_ttl(addr, tos, tc, observed_ttl, emit);
            }
        }
        (Some((os, conf)), None) => emit_os(addr, os, conf, emit),
        (None, Some((os, conf))) => emit_os_ttl(addr, os, conf, observed_ttl, emit),
        (None, None) => {}
    }
}

/// SMB negotiate → soft Windows/Samba family hint.
pub fn guess_os_from_smb(addr: IpAddr, dialect: &str, emit: impl Fn(Event)) {
    let d = dialect.to_ascii_uppercase();
    let (os, conf) = if d.contains("3.1.1") || d.contains("3.0") {
        ("Windows family (SMB3)", 0.6)
    } else if d.contains("SMB 2") || d.contains("SMB2") {
        ("Windows family (SMB2+)", 0.55)
    } else if d.contains("SMB1") {
        ("Windows/Samba family (SMB1)", 0.45)
    } else {
        ("Windows/Samba family (SMB)", 0.4)
    };
    emit_os(addr, os, conf, emit);
}

fn emit_os(addr: IpAddr, os: &str, confidence: f32, emit: impl Fn(Event)) {
    emit_os_ttl(addr, os, confidence, None, emit);
}

fn emit_os_ttl(
    addr: IpAddr,
    os: &str,
    confidence: f32,
    observed_ttl: Option<u8>,
    emit: impl Fn(Event),
) {
    emit(Event::OsGuess {
        addr,
        os: os.into(),
        confidence,
        observed_ttl,
    });
}

fn infer_from_text(text: &str) -> Option<(&'static str, f32)> {
    let t = text.to_lowercase();

    // Explicit OS tokens first
    if t.contains("windows") || t.contains("microsoft-iis") || t.contains("microsoft-httpapi") {
        return Some(("Windows", 0.7));
    }
    if t.contains("win32") || t.contains("win64") || t.contains("mingw") {
        return Some(("Windows", 0.65));
    }
    if t.contains("exchange") || t.contains("outlook") {
        return Some(("Windows (Exchange/Outlook)", 0.65));
    }
    if t.contains("darwin") || t.contains("macos") || t.contains("mac os") {
        return Some(("macOS / Darwin", 0.65));
    }
    if t.contains("freebsd") {
        return Some(("FreeBSD", 0.6));
    }
    if t.contains("openbsd") {
        return Some(("OpenBSD", 0.6));
    }
    if t.contains("netbsd") {
        return Some(("NetBSD", 0.6));
    }
    if t.contains("ubuntu") {
        return Some(("Linux (Ubuntu)", 0.6));
    }
    if t.contains("debian") {
        return Some(("Linux (Debian)", 0.6));
    }
    if t.contains("centos")
        || t.contains("red hat")
        || t.contains("rhel")
        || t.contains("rocky")
        || t.contains("alma")
    {
        return Some(("Linux (RHEL-like)", 0.6));
    }
    if t.contains("fedora") {
        return Some(("Linux (Fedora)", 0.55));
    }
    if t.contains("amazon linux") || t.contains("amzn") {
        return Some(("Linux (Amazon)", 0.55));
    }
    if t.contains("suse") || t.contains("opensuse") {
        return Some(("Linux (SUSE)", 0.55));
    }
    if t.contains("alpine") {
        return Some(("Linux (Alpine)", 0.6));
    }
    if t.contains("rasp") || t.contains("raspberry") {
        return Some(("Linux (Raspberry Pi)", 0.55));
    }
    if t.contains("android") {
        return Some(("Android", 0.55));
    }
    if t.contains("mikrotik") || t.contains("routeros") {
        return Some(("MikroTik RouterOS", 0.7));
    }
    if t.contains("cisco") || t.contains("ios-xe") || t.contains("nx-os") {
        return Some(("Cisco IOS / network OS", 0.6));
    }
    if t.contains("juniper") || t.contains("junos") {
        return Some(("Juniper Junos", 0.6));
    }
    if t.contains("fortinet") || t.contains("fortigate") {
        return Some(("Fortinet FortiOS", 0.6));
    }
    if t.contains("dropbear") {
        return Some(("embedded Linux (Dropbear)", 0.55));
    }
    if t.contains("busybox") {
        return Some(("embedded Linux (BusyBox)", 0.55));
    }

    // Mail / FTP stacks (usually Unix)
    if t.contains("postfix") || t.contains("exim") || t.contains("dovecot") {
        return Some(("Linux/Unix (mail stack)", 0.55));
    }
    if t.contains("vsftpd") || t.contains("proftpd") || t.contains("pure-ftpd") {
        return Some(("Linux/Unix (FTP)", 0.55));
    }
    if t.contains("filezilla") {
        return Some(("Windows (FileZilla Server)", 0.55));
    }

    // App banners → soft host family (labs/cloud mostly Linux)
    if t.contains("mariadb") {
        return Some(("Linux/Unix (MariaDB)", 0.45));
    }
    if t.contains("mysql") && !t.contains("windows") {
        return Some(("Linux/Unix (MySQL)", 0.4));
    }
    if t.contains("postgresql") || t.contains("postgres") {
        return Some(("Linux/Unix (PostgreSQL)", 0.4));
    }
    if t.contains("redis") {
        return Some(("Linux/Unix (Redis)", 0.4));
    }
    if t.contains("mongodb") {
        return Some(("Linux/Unix (MongoDB)", 0.4));
    }
    if t.contains("elasticsearch") {
        return Some(("Linux/Unix (Elasticsearch)", 0.4));
    }
    if t.contains("memcached") {
        return Some(("Linux/Unix (Memcached)", 0.4));
    }
    if t.contains("kafka") {
        return Some(("Linux/Unix (Kafka)", 0.4));
    }
    if t.contains("rabbitmq") || t.contains("amqp") {
        return Some(("Linux/Unix (AMQP/RabbitMQ)", 0.4));
    }
    if t.contains("nats") {
        return Some(("Linux/Unix (NATS)", 0.4));
    }
    if t.contains("mqtt") {
        return Some(("IoT / MQTT broker", 0.35));
    }
    if t.contains("microsoft ad")
        || t.contains("defaultnamingcontext")
        || (t.contains("ldap") && t.contains("microsoft"))
    {
        return Some(("Windows (Active Directory LDAP)", 0.7));
    }
    if t.contains("openldap") {
        return Some(("Linux/Unix (OpenLDAP)", 0.55));
    }
    if t.contains("kerberos") {
        return Some(("Windows/AD or MIT Kerberos KDC", 0.55));
    }
    if t.starts_with("vnc rfb") || t.contains("vnc/rfb") {
        return Some(("VNC desktop endpoint", 0.35));
    }
    if t.contains("winrm") || t.contains("microsoft-httpapi") {
        return Some(("Windows (WinRM)", 0.7));
    }
    if t.contains("snmp sysdescr") || t.starts_with("snmp ") {
        // sysDescr often embeds OS tokens already handled above; soft network-device hint
        return Some(("SNMP-managed host / network device", 0.35));
    }

    // Web servers (weaker OS signal)
    if t.contains("microsoft-iis") {
        return Some(("Windows", 0.7));
    }
    if t.contains("apache") && t.contains("win32") {
        return Some(("Windows (Apache)", 0.6));
    }

    // SSH / FTP product heuristics
    if t.contains("openssh") {
        if t.contains("windows") {
            return Some(("Windows (OpenSSH)", 0.7));
        }
        return Some(("Linux/Unix (OpenSSH)", 0.55));
    }
    if t.starts_with("ssh-") && t.contains("windows") {
        return Some(("Windows (OpenSSH)", 0.7));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    #[test]
    fn banner_windows_iis() {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let events = Arc::new(Mutex::new(Vec::new()));
        let e2 = events.clone();
        guess_os_from_banner(addr, "Server: Microsoft-IIS/10.0", move |e| {
            e2.lock().unwrap().push(e);
        });
        let events = events.lock().unwrap();
        assert!(matches!(
            &events[0],
            Event::OsGuess { os, confidence, .. }
                if os.contains("Windows") && *confidence >= 0.7
        ));
    }

    #[test]
    fn ttl_windows_bucket() {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let events = Arc::new(Mutex::new(Vec::new()));
        let e2 = events.clone();
        guess_os_from_observed_ttl(addr, 120, move |e| {
            e2.lock().unwrap().push(e);
        });
        let events = events.lock().unwrap();
        assert!(matches!(
            &events[0],
            Event::OsGuess { os, .. } if os.contains("Windows")
        ));
    }

    #[test]
    fn correlated_agrees_boosts() {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let events = Arc::new(Mutex::new(Vec::new()));
        let e2 = events.clone();
        guess_os_correlated(addr, Some("OpenSSH_8.9p1 Ubuntu"), Some(64), move |e| {
            e2.lock().unwrap().push(e);
        });
        let events = events.lock().unwrap();
        assert!(matches!(
            &events[0],
            Event::OsGuess { os, confidence, .. }
                if os.contains("Ubuntu") && os.contains("agrees") && *confidence >= 0.7
        ));
    }

    #[test]
    fn mongo_banner_hint() {
        assert!(infer_from_text("MongoDB 7.0.5 (maxWireVersion=21)")
            .unwrap()
            .0
            .contains("MongoDB"));
    }
}
