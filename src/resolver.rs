use std::net::Ipv4Addr;

pub fn resolve_hostname(ip: Ipv4Addr) -> String {
    let addr = std::net::IpAddr::V4(ip);
    dns_lookup::lookup_addr(&addr).unwrap_or_else(|_| "(unknown)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn loopback_resolves() {
        let h = resolve_hostname(Ipv4Addr::new(127, 0, 0, 1));
        assert!(!h.is_empty());
        assert_ne!(h, "(unknown)");
    }

    #[test]
    fn unroutable_returns_unknown() {
        let h = resolve_hostname(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(h, "(unknown)");
    }

    #[test]
    #[ignore]
    fn live_router_resolves() {
        let h = resolve_hostname(Ipv4Addr::new(192, 168, 0, 1));
        println!("Router hostname: {h}");
        assert_ne!(h, "(unknown)");
    }
}
