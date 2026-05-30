use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        let mut bytes = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(p, 16).ok()?;
        }
        Some(MacAddr(bytes))
    }

    pub fn from_pnet(m: pnet::util::MacAddr) -> Self {
        MacAddr([m.0, m.1, m.2, m.3, m.4, m.5])
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

#[derive(Debug, Clone)]
pub struct Device {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub hostname: String,
}

impl Device {
    pub fn new(ip: Ipv4Addr, mac: MacAddr, hostname: impl Into<String>) -> Self {
        Device { ip, mac, hostname: hostname.into() }
    }
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\t{}\t{}", self.ip, self.mac, self.hostname)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn mac_display_lowercase_hex() {
        let mac = super::MacAddr([0x54, 0xdf, 0x1b, 0x1f, 0x7a, 0x06]);
        assert_eq!(mac.to_string(), "54:df:1b:1f:7a:06");
    }
    #[test]
    fn mac_parse_roundtrip() {
        let s = "54:df:1b:1f:7a:06";
        let mac = super::MacAddr::parse(s).expect("valid MAC");
        assert_eq!(mac.to_string(), s);
    }
    #[test]
    fn mac_parse_invalid_returns_none() {
        assert!(super::MacAddr::parse("zz:gg:hh:00:00:00").is_none());
        assert!(super::MacAddr::parse("aa:bb:cc").is_none());
        assert!(super::MacAddr::parse("").is_none());
    }
    #[test]
    fn mac_all_zeroes() {
        let mac = super::MacAddr([0u8; 6]);
        assert_eq!(mac.to_string(), "00:00:00:00:00:00");
    }
    #[test]
    fn device_display() {
        use std::net::Ipv4Addr;
        let d = super::Device::new(
            Ipv4Addr::new(192, 168, 0, 1),
            super::MacAddr([0x4c, 0x22, 0xf3, 0x6a, 0x0b, 0x4f]),
            "router.local",
        );
        assert_eq!(d.to_string(), "192.168.0.1\t4c:22:f3:6a:0b:4f\trouter.local");
    }
}
