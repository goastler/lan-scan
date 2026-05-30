use anyhow::{anyhow, Result};
use ipnetwork::Ipv4Network;
use pnet::datalink::{self, NetworkInterface};
use std::net::Ipv4Addr;

pub fn select_interface(name: Option<&str>) -> Result<NetworkInterface> {
    let interfaces = datalink::interfaces();
    if let Some(n) = name {
        return interfaces
            .into_iter()
            .find(|iface| iface.name == n)
            .ok_or_else(|| anyhow!("Interface '{}' not found", n));
    }
    interfaces
        .into_iter()
        .filter(|iface| {
            !iface.is_loopback() && iface.is_up() && iface.ips.iter().any(|ip| ip.is_ipv4())
        })
        .min_by_key(|iface| if iface.name.starts_with("wl") { 1u8 } else { 0u8 })
        .ok_or_else(|| anyhow!("No suitable network interface found"))
}

pub fn get_network(iface: &NetworkInterface) -> Result<Ipv4Network> {
    for ip_net in &iface.ips {
        if let ipnetwork::IpNetwork::V4(v4) = ip_net {
            return Ok(*v4);
        }
    }
    Err(anyhow!("Interface '{}' has no IPv4 address", iface.name))
}

pub fn local_ipv4(iface: &NetworkInterface) -> Result<Ipv4Addr> {
    get_network(iface).map(|net| net.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ipv4_slash24_has_256_addrs() {
        let net: ipnetwork::Ipv4Network = "192.168.0.0/24".parse().unwrap();
        assert_eq!(net.iter().count(), 256);
    }

    #[test]
    fn ipv4_slash24_has_254_hosts() {
        let net: ipnetwork::Ipv4Network = "192.168.0.0/24".parse().unwrap();
        let hosts: Vec<_> = net
            .iter()
            .filter(|ip| *ip != net.network() && *ip != net.broadcast())
            .collect();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], "192.168.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(hosts[253], "192.168.0.254".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn ipv4_slash30_has_4_addrs() {
        let net: ipnetwork::Ipv4Network = "10.0.0.0/30".parse().unwrap();
        assert_eq!(net.size(), 4);
    }

    #[test]
    #[ignore]
    fn select_and_get_network_live() {
        let iface = select_interface(None).unwrap();
        println!("Interface: {}", iface.name);
        let net = get_network(&iface).unwrap();
        println!("Network: {net}");
        assert!(iface.is_up());
        assert!(!iface.is_loopback());
        assert!(net.prefix() <= 32);
    }
}
