//! Linux ARP helpers (feature = "raw").
//! Requires CAP_NET_RAW / root. Used by syn-raw next-hop MAC and `discover --arp`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use ares_core::event::Event;
use pnet::datalink::{self, Channel::Ethernet, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct LinkInfo {
    pub iface: NetworkInterface,
    pub src_ip: Ipv4Addr,
    pub src_mac: MacAddr,
}

pub fn pick_iface() -> anyhow::Result<LinkInfo> {
    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| i.is_up() && !i.is_loopback() && i.mac.is_some())
        .ok_or_else(|| anyhow::anyhow!("no usable interface for ARP"))?;
    let src_ip = iface
        .ips
        .iter()
        .find_map(|ip| match ip {
            ipnetwork::IpNetwork::V4(v) => Some(v.ip()),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("no IPv4 on {}", iface.name))?;
    let src_mac = iface.mac.unwrap_or(MacAddr::zero());
    Ok(LinkInfo {
        iface,
        src_ip,
        src_mac,
    })
}

pub fn open_channel(
    iface: &NetworkInterface,
) -> anyhow::Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    match datalink::channel(iface, Default::default()) {
        Ok(Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => anyhow::bail!("unsupported datalink channel"),
        Err(e) => anyhow::bail!("datalink channel: {e}"),
    }
}

/// True if `dst` shares an IPv4 subnet with any address on `iface`.
pub fn is_on_link(iface: &NetworkInterface, dst: Ipv4Addr) -> bool {
    iface.ips.iter().any(|ip| match ip {
        ipnetwork::IpNetwork::V4(v) => v.contains(dst),
        _ => false,
    })
}

/// Default IPv4 gateway for `iface_name` from `/proc/net/route` (Linux).
pub fn default_gateway(iface_name: &str) -> Option<Ipv4Addr> {
    let Ok(data) = fs::read_to_string("/proc/net/route") else {
        return None;
    };
    for line in data.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        if cols[0] != iface_name {
            continue;
        }
        // Destination 00000000 = default route
        if cols[1] != "00000000" {
            continue;
        }
        let flags = u16::from_str_radix(cols[3], 16).unwrap_or(0);
        // RTF_UP | RTF_GATEWAY
        if flags & 0x2 == 0 {
            continue;
        }
        if let Some(gw) = parse_proc_hex_ip(cols[2]) {
            if gw != Ipv4Addr::UNSPECIFIED {
                return Some(gw);
            }
        }
    }
    None
}

fn parse_proc_hex_ip(s: &str) -> Option<Ipv4Addr> {
    let n = u32::from_str_radix(s, 16).ok()?;
    // /proc/net/route stores little-endian
    Some(Ipv4Addr::from(n.to_le_bytes()))
}

/// Next-hop IP for Ethernet framing: on-link host or default gateway.
pub fn next_hop_ip(link: &LinkInfo, dst: Ipv4Addr) -> Ipv4Addr {
    if is_on_link(&link.iface, dst) {
        dst
    } else {
        default_gateway(&link.iface.name).unwrap_or(dst)
    }
}

fn craft_arp_request(buf: &mut [u8], src_mac: MacAddr, src_ip: Ipv4Addr, target_ip: Ipv4Addr) {
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..14]).unwrap();
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    {
        let mut arp = MutableArpPacket::new(&mut buf[14..42]).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }
}

fn parse_arp_reply(packet: &[u8], want_ip: Ipv4Addr) -> Option<MacAddr> {
    let eth = EthernetPacket::new(packet)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    if arp.get_sender_proto_addr() != want_ip {
        return None;
    }
    Some(arp.get_sender_hw_addr())
}

/// Resolve MAC for a single IPv4 via ARP who-has (with retries).
pub fn arp_resolve(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn DataLinkReceiver>,
    link: &LinkInfo,
    target_ip: Ipv4Addr,
    timeout: Duration,
) -> Option<MacAddr> {
    let mut buf = [0u8; 42];
    craft_arp_request(&mut buf, link.src_mac, link.src_ip, target_ip);
    let deadline = Instant::now() + timeout;
    let mut attempts = 0u8;
    while Instant::now() < deadline && attempts < 4 {
        let _ = tx.send_to(&buf, None);
        attempts += 1;
        let slice = Duration::from_millis(150);
        let slice_deadline = Instant::now() + slice;
        while Instant::now() < slice_deadline && Instant::now() < deadline {
            match rx.next() {
                Ok(packet) => {
                    if let Some(mac) = parse_arp_reply(packet, target_ip) {
                        return Some(mac);
                    }
                }
                Err(_) => break,
            }
        }
    }
    None
}

/// Resolve next-hop MACs for a set of destinations. Falls back to broadcast on miss.
pub fn resolve_next_hop_macs(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn DataLinkReceiver>,
    link: &LinkInfo,
    destinations: &[Ipv4Addr],
    timeout: Duration,
    emit: &(impl Fn(Event) + Send + Sync),
) -> HashMap<Ipv4Addr, MacAddr> {
    let mut hop_ips: HashSet<Ipv4Addr> = HashSet::new();
    let mut dst_to_hop: HashMap<Ipv4Addr, Ipv4Addr> = HashMap::new();
    for &dst in destinations {
        let hop = next_hop_ip(link, dst);
        dst_to_hop.insert(dst, hop);
        hop_ips.insert(hop);
    }

    let mut hop_macs: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
    for hop in hop_ips {
        match arp_resolve(tx, rx, link, hop, timeout) {
            Some(mac) => {
                emit(Event::Log {
                    level: "info".into(),
                    message: format!("arp {hop} → {mac}"),
                });
                hop_macs.insert(hop, mac);
            }
            None => {
                emit(Event::Log {
                    level: "warn".into(),
                    message: format!("arp {hop} unresolved — using broadcast"),
                });
                hop_macs.insert(hop, MacAddr::broadcast());
            }
        }
    }

    let mut out = HashMap::new();
    for (&dst, &hop) in &dst_to_hop {
        let mac = hop_macs
            .get(&hop)
            .copied()
            .unwrap_or(MacAddr::broadcast());
        out.insert(dst, mac);
    }
    out
}

/// L2 ARP sweep: who-has for each IPv4, emit HostUp for replies.
pub fn arp_sweep(
    addrs: &[IpAddr],
    timeout: Duration,
    cancel: CancellationToken,
    emit: &(impl Fn(Event) + Send + Sync),
) -> anyhow::Result<Vec<IpAddr>> {
    let link = pick_iface()?;
    let (mut tx, mut rx) = open_channel(&link.iface)?;
    let mut targets: Vec<Ipv4Addr> = addrs
        .iter()
        .filter_map(|a| match a {
            IpAddr::V4(v) => Some(*v),
            _ => None,
        })
        .collect();
    targets.sort();
    targets.dedup();

    emit(Event::Log {
        level: "info".into(),
        message: format!(
            "arp-sweep iface={} src={} hosts={}",
            link.iface.name,
            link.src_ip,
            targets.len()
        ),
    });

    let mut buf = [0u8; 42];
    let mut pending: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let start = Instant::now();

    // Burst who-has
    for &ip in &targets {
        if cancel.is_cancelled() {
            break;
        }
        craft_arp_request(&mut buf, link.src_mac, link.src_ip, ip);
        let _ = tx.send_to(&buf, None);
    }

    let mut up = Vec::new();
    let deadline = start + timeout.max(Duration::from_millis(400));
    while Instant::now() < deadline && !pending.is_empty() && !cancel.is_cancelled() {
        match rx.next() {
            Ok(packet) => {
                let Some(eth) = EthernetPacket::new(packet) else {
                    continue;
                };
                if eth.get_ethertype() != EtherTypes::Arp {
                    continue;
                }
                let Some(arp) = ArpPacket::new(eth.payload()) else {
                    continue;
                };
                if arp.get_operation() != ArpOperations::Reply {
                    continue;
                }
                let sip = arp.get_sender_proto_addr();
                if pending.remove(&sip) {
                    let mac = arp.get_sender_hw_addr();
                    let rtt = start.elapsed().as_millis() as u64;
                    emit(Event::HostUp {
                        addr: IpAddr::V4(sip),
                        latency_ms: Some(rtt),
                        method: format!("arp/{mac}"),
                    });
                    up.push(IpAddr::V4(sip));
                }
            }
            Err(_) => break,
        }
    }

    Ok(up)
}
