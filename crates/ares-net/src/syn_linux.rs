//! Linux raw SYN scanner using pnet (feature = "raw").
//! Requires CAP_NET_RAW / root.
//!
//! Per-port tracking: each probe uses a unique source port + seq cookie so
//! SYN-ACK/RST replies map back to (dst_ip, dport).
//! Next-hop Ethernet MAC comes from ARP (on-link or default gateway).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ares_core::event::Event;
use ares_core::model::PortState;
use ares_core::timing::TimingProfile;
use parking_lot::Mutex;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::util::MacAddr;
use tokio_util::sync::CancellationToken;

use crate::arp::{self, LinkInfo};
use crate::connect::ScanStats;

#[derive(Clone, Copy)]
struct Pending {
    addr: IpAddr,
    port: u16,
    seq: u32,
    dst_ip: Ipv4Addr,
}

pub async fn syn_scan_emit(
    targets: &[(IpAddr, u16)],
    timing: TimingProfile,
    show_closed: bool,
    show_filtered: bool,
    cancel: CancellationToken,
    emit: &(impl Fn(Event) + Send + Sync),
) -> anyhow::Result<ScanStats> {
    let link = arp::pick_iface()?;
    let LinkInfo {
        iface,
        src_ip,
        src_mac,
    } = link.clone();

    let (mut tx, mut rx) = arp::open_channel(&iface)?;
    // Share TX so the recv thread can RST open sockets (half-open hygiene).
    let tx_shared = Arc::new(Mutex::new(tx));

    let unique_dsts: Vec<Ipv4Addr> = {
        let mut v: Vec<_> = targets
            .iter()
            .filter_map(|(a, _)| match a {
                IpAddr::V4(ip) => Some(*ip),
                _ => None,
            })
            .collect();
        v.sort();
        v.dedup();
        v
    };
    let arp_timeout = timing
        .timeout
        .min(Duration::from_secs(2))
        .max(Duration::from_millis(400));
    let dst_macs = arp::resolve_next_hop_macs(
        &mut *tx_shared.lock(),
        &mut rx,
        &link,
        &unique_dsts,
        arp_timeout,
        emit,
    );
    let default_mac = MacAddr::broadcast();

    let open = Arc::new(AtomicU64::new(0));
    let closed = Arc::new(AtomicU64::new(0));
    let filtered = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    let pending: Arc<Mutex<HashMap<u16, Pending>>> = Arc::new(Mutex::new(HashMap::new()));
    let results: Arc<Mutex<Vec<(IpAddr, u16, PortState, u8)>>> = Arc::new(Mutex::new(Vec::new()));

    let listen_window = timing.timeout.max(Duration::from_millis(500))
        + Duration::from_millis((targets.len() as u64 / 100).saturating_mul(10));

    let pending_r = pending.clone();
    let results_r = results.clone();
    let open_r = open.clone();
    let closed_r = closed.clone();
    let cancel_r = cancel.clone();
    let tx_r = tx_shared.clone();
    let src_mac_r = src_mac;
    let src_ip_r = src_ip;
    let dst_macs_r = dst_macs.clone();
    let recv_handle = std::thread::spawn(move || {
        let deadline = Instant::now() + listen_window + Duration::from_secs(2);
        let mut rst_buf = vec![0u8; 66];
        while Instant::now() < deadline && !cancel_r.is_cancelled() {
            match rx.next() {
                Ok(packet) => {
                    if let Some(eth) = EthernetPacket::new(packet) {
                        if eth.get_ethertype() != EtherTypes::Ipv4 {
                            continue;
                        }
                        if let Some(ip) = pnet::packet::ipv4::Ipv4Packet::new(eth.payload()) {
                            if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                                continue;
                            }
                            let Some(tcp) = TcpPacket::new(ip.payload()) else {
                                continue;
                            };
                            let our_sport = tcp.get_destination();
                            let mut map = pending_r.lock();
                            let Some(p) = map.get(&our_sport).copied() else {
                                continue;
                            };
                            if ip.get_source() != p.dst_ip {
                                continue;
                            }
                            let ack = tcp.get_acknowledgement();
                            if ack != p.seq.wrapping_add(1) {
                                continue;
                            }
                            let flags = tcp.get_flags();
                            let state = if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0
                            {
                                open_r.fetch_add(1, Ordering::Relaxed);
                                // Tear down half-open: RST|ACK toward the listener.
                                let dst_mac = dst_macs_r
                                    .get(&p.dst_ip)
                                    .copied()
                                    .unwrap_or(MacAddr::broadcast());
                                craft_rst(
                                    &mut rst_buf,
                                    src_mac_r,
                                    dst_mac,
                                    src_ip_r,
                                    p.dst_ip,
                                    our_sport,
                                    p.port,
                                    p.seq.wrapping_add(1),
                                    tcp.get_sequence().wrapping_add(1),
                                );
                                let _ = tx_r.lock().send_to(&rst_buf, None);
                                PortState::Open
                            } else if flags & TcpFlags::RST != 0 {
                                closed_r.fetch_add(1, Ordering::Relaxed);
                                PortState::Closed
                            } else {
                                continue;
                            };
                            let reply_ttl = ip.get_ttl();
                            map.remove(&our_sport);
                            drop(map);
                            results_r.lock().push((p.addr, p.port, state, reply_ttl));
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut buf = vec![0u8; 66];
    let mut sent = 0u64;
    let mut next_sport: u16 = 30_000;
    for &(addr, port) in targets {
        if cancel.is_cancelled() {
            break;
        }
        let IpAddr::V4(dst_ip) = addr else {
            continue;
        };
        let dst_mac = dst_macs.get(&dst_ip).copied().unwrap_or(default_mac);
        // Unique source port while probe is pending (avoid %20000 collisions).
        let sport = {
            let mut map = pending.lock();
            let mut tries = 0u32;
            loop {
                next_sport = next_sport.wrapping_add(1);
                if next_sport < 30_000 {
                    next_sport = 30_000;
                }
                if !map.contains_key(&next_sport) {
                    break next_sport;
                }
                tries += 1;
                if tries > 65_000 {
                    drop(map);
                    std::thread::sleep(Duration::from_millis(2));
                    map = pending.lock();
                    tries = 0;
                }
            }
        };
        let seq = cookie(src_ip, dst_ip, sport, port);
        pending.lock().insert(
            sport,
            Pending {
                addr,
                port,
                seq,
                dst_ip,
            },
        );
        craft_syn(&mut buf, src_mac, dst_mac, src_ip, dst_ip, sport, port, seq);
        let _ = tx_shared.lock().send_to(&buf, None);
        sent += 1;
        if let Some(pps) = timing.rate_pps {
            if pps > 0 {
                tokio::time::sleep(Duration::from_nanos(1_000_000_000 / pps)).await;
            }
        }
    }

    tokio::time::sleep(listen_window).await;
    let _ = recv_handle.join();

    {
        let left = pending.lock();
        for p in left.values() {
            filtered.fetch_add(1, Ordering::Relaxed);
            results
                .lock()
                .push((p.addr, p.port, PortState::Filtered, 0));
        }
    }

    let elapsed = start.elapsed();
    let o = open.load(Ordering::Relaxed);
    let c = closed.load(Ordering::Relaxed);
    let f = filtered.load(Ordering::Relaxed);

    let mut ttl_guessed = std::collections::HashSet::new();
    for (addr, port, state, reply_ttl) in results.lock().drain(..) {
        // Always emit for store/resume; live renderer applies --show-closed/--show-filtered.
        let _ = (show_closed, show_filtered);
        emit(Event::PortResult {
            addr,
            port,
            protocol: "tcp".into(),
            state,
            rtt_ms: None,
        });
        if reply_ttl > 0 && ttl_guessed.insert(addr) {
            if let Some((os, confidence)) = os_from_reply_ttl(reply_ttl) {
                emit(Event::OsGuess {
                    addr,
                    os: os.into(),
                    confidence,
                    observed_ttl: Some(reply_ttl),
                });
            }
        }
    }

    emit(Event::Log {
        level: "info".into(),
        message: format!(
            "syn-raw sent={sent} open={o} closed={c} filtered={f} (arp+cookie tracking)"
        ),
    });
    emit(Event::Stats {
        pps: if elapsed.as_secs_f64() > 0.0 {
            sent as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        },
        open: o,
        closed: c,
        filtered: f,
        elapsed_ms: elapsed.as_millis() as u64,
    });

    Ok(ScanStats {
        open: o,
        closed: c,
        filtered: f,
        elapsed,
        total: targets.len() as u64,
    })
}

fn os_from_reply_ttl(ttl: u8) -> Option<(&'static str, f32)> {
    if (32..=64).contains(&ttl) {
        Some(("Linux/Unix family (TTL≈64)", 0.45))
    } else if (65..=128).contains(&ttl) {
        Some(("Windows family (TTL≈128)", 0.45))
    } else if ttl > 128 {
        Some(("network appliance / high-TTL stack (TTL≈255)", 0.35))
    } else {
        None
    }
}

fn cookie(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> u32 {
    let s = src.octets();
    let d = dst.octets();
    let mut x = u32::from_be_bytes([s[0] ^ d[0], s[1] ^ d[1], s[2] ^ d[2], s[3] ^ d[3]]);
    x = x
        .wrapping_mul(0x9E37_79B1)
        .wrapping_add(u32::from(sport) << 16 | u32::from(dport));
    x ^= x >> 16;
    x
}

fn craft_syn(
    buf: &mut [u8],
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
) {
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..14]).unwrap();
        eth.set_source(src_mac);
        eth.set_destination(dst_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[14..34]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_identification(0x1337);
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
    }
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[34..54]).unwrap();
        tcp.set_source(sport);
        tcp.set_destination(dport);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(64240);
        tcp.set_urgent_ptr(0);
        let checksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src, &dst);
        tcp.set_checksum(checksum);
    }
}

fn craft_rst(
    buf: &mut [u8],
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
) {
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..14]).unwrap();
        eth.set_source(src_mac);
        eth.set_destination(dst_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[14..34]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_identification(0x1338);
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
    }
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[34..54]).unwrap();
        tcp.set_source(sport);
        tcp.set_destination(dport);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::RST | TcpFlags::ACK);
        tcp.set_window(0);
        tcp.set_urgent_ptr(0);
        let checksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src, &dst);
        tcp.set_checksum(checksum);
    }
}
