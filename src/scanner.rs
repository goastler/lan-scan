use crate::device::MacAddr;
use anyhow::{Context, Result};
use ipnetwork::Ipv4Network;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr as PnetMac;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const ETH_FRAME_LEN: usize = 42;
const BROADCAST: PnetMac = PnetMac(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
const ZERO_MAC: PnetMac = PnetMac(0, 0, 0, 0, 0, 0);

pub fn build_arp_request(sender_mac: PnetMac, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut buf = vec![0u8; ETH_FRAME_LEN];
    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(BROADCAST);
        eth.set_source(sender_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    {
        let mut arp = MutableArpPacket::new(&mut buf[14..]).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(sender_mac);
        arp.set_sender_proto_addr(sender_ip);
        arp.set_target_hw_addr(ZERO_MAC);
        arp.set_target_proto_addr(target_ip);
    }
    buf
}

pub fn parse_arp_reply(frame: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    Some((arp.get_sender_proto_addr(), MacAddr::from_pnet(arp.get_sender_hw_addr())))
}

pub fn arp_scan(
    iface: &NetworkInterface,
    network: Ipv4Network,
    sender_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<Vec<(Ipv4Addr, MacAddr)>> {
    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(100)),
        ..Default::default()
    };
    let (mut tx, mut rx) = match datalink::channel(iface, config)
        .context("Failed to open channel (need root/CAP_NET_RAW)")?
    {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => anyhow::bail!("Unexpected channel type"),
    };

    let sender_mac = iface.mac.ok_or_else(|| anyhow::anyhow!("Interface has no MAC"))?;

    let net = network;
    std::thread::spawn(move || {
        for ip in net.iter() {
            if ip == net.network() || ip == net.broadcast() || ip == sender_ip {
                continue;
            }
            let frame = build_arp_request(sender_mac, sender_ip, ip);
            let _ = tx.send_to(&frame, None);
        }
    });

    let deadline = Instant::now() + timeout;
    let mut seen: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
    loop {
        if Instant::now() >= deadline {
            break;
        }
        match rx.next() {
            Ok(frame) => {
                if let Some((ip, mac)) = parse_arp_reply(frame) {
                    if network.contains(ip) {
                        seen.entry(ip).or_insert(mac);
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
    }

    Ok(seen.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::util::MacAddr as PnetMac;
    use std::net::Ipv4Addr;

    fn test_mac() -> PnetMac {
        PnetMac(0x90, 0x2e, 0x16, 0x93, 0xb9, 0x03)
    }
    fn src_ip() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 0, 225)
    }
    fn dst_ip() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 0, 1)
    }

    #[test]
    fn arp_request_frame_length() {
        let f = build_arp_request(test_mac(), src_ip(), dst_ip());
        assert_eq!(f.len(), 42);
    }

    #[test]
    fn arp_request_dest_is_broadcast() {
        let f = build_arp_request(test_mac(), src_ip(), dst_ip());
        assert_eq!(&f[0..6], &[0xff; 6]);
    }

    #[test]
    fn arp_request_ethertype_is_0806() {
        let f = build_arp_request(test_mac(), src_ip(), dst_ip());
        assert_eq!(f[12], 0x08);
        assert_eq!(f[13], 0x06);
    }

    #[test]
    fn arp_request_operation_is_1() {
        let f = build_arp_request(test_mac(), src_ip(), dst_ip());
        assert_eq!(f[20], 0x00);
        assert_eq!(f[21], 0x01);
    }

    #[test]
    fn parse_non_arp_returns_none() {
        let mut f = vec![0u8; 60];
        f[12] = 0x08;
        f[13] = 0x00; // IPv4
        assert!(parse_arp_reply(&f).is_none());
    }

    #[test]
    fn parse_arp_request_returns_none() {
        let f = build_arp_request(test_mac(), src_ip(), dst_ip());
        assert!(parse_arp_reply(&f).is_none());
    }

    #[test]
    fn parse_synthetic_arp_reply() {
        let mut f = vec![0u8; 42];
        f[12] = 0x08;
        f[13] = 0x06; // ARP ethertype
        f[14] = 0x00;
        f[15] = 0x01; // hw type = Ethernet
        f[16] = 0x08;
        f[17] = 0x00; // proto = IPv4
        f[18] = 6;
        f[19] = 4;
        f[20] = 0x00;
        f[21] = 0x02; // operation = reply
        f[22..28].copy_from_slice(&[0x54, 0xdf, 0x1b, 0x1f, 0x7a, 0x06]); // sender MAC
        f[28..32].copy_from_slice(&[192, 168, 0, 247]); // sender IP

        let (ip, mac) = parse_arp_reply(&f).expect("should parse");
        assert_eq!(ip, Ipv4Addr::new(192, 168, 0, 247));
        assert_eq!(mac.to_string(), "54:df:1b:1f:7a:06");
    }

    #[test]
    #[ignore]
    fn live_scan_finds_at_least_one_device() {
        use crate::network;
        let iface = network::select_interface(None).unwrap();
        let net = network::get_network(&iface).unwrap();
        let lip = network::local_ipv4(&iface).unwrap();
        let found = arp_scan(&iface, net, lip, Duration::from_secs(3)).unwrap();
        println!("Found {} devices", found.len());
        assert!(!found.is_empty());
    }
}
