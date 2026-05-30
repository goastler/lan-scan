use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

const BATCH: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpState {
    /// Service responded with data.
    Open,
    /// ICMP Port Unreachable received — no service on this port.
    Closed,
    /// No response within timeout — port may be open or firewalled.
    OpenFiltered,
}

impl std::fmt::Display for UdpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpState::Open => write!(f, "open"),
            UdpState::Closed => write!(f, "closed"),
            UdpState::OpenFiltered => write!(f, "open|filtered"),
        }
    }
}

/// TCP connect scan: returns sorted list of open ports.
pub fn tcp_scan(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> Vec<u16> {
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel();
    for chunk in ports.chunks(BATCH) {
        let handles: Vec<_> = chunk
            .iter()
            .map(|&port| {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let addr = SocketAddr::new(IpAddr::V4(ip), port);
                    if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                        let _ = tx.send(port);
                    }
                })
            })
            .collect();
        for h in handles {
            let _ = h.join();
        }
    }
    drop(tx);
    let mut open: Vec<u16> = rx.into_iter().collect();
    open.sort_unstable();
    open
}

/// UDP probe scan: returns (port, state) for every non-Closed port.
/// Closed ports (ICMP Port Unreachable → ECONNREFUSED) are filtered out.
pub fn udp_scan(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> Vec<(u16, UdpState)> {
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel();
    for chunk in ports.chunks(BATCH) {
        let handles: Vec<_> = chunk
            .iter()
            .map(|&port| {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let state = probe_udp(ip, port, timeout);
                    if state != UdpState::Closed {
                        let _ = tx.send((port, state));
                    }
                })
            })
            .collect();
        for h in handles {
            let _ = h.join();
        }
    }
    drop(tx);
    let mut results: Vec<(u16, UdpState)> = rx.into_iter().collect();
    results.sort_unstable_by_key(|(p, _)| *p);
    results
}

fn probe_udp(ip: Ipv4Addr, port: u16, timeout: Duration) -> UdpState {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return UdpState::OpenFiltered;
    };
    let target = SocketAddr::new(IpAddr::V4(ip), port);
    if sock.connect(target).is_err() {
        return UdpState::OpenFiltered;
    }
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.send(&[]);
    let mut buf = [0u8; 512];
    match sock.recv(&mut buf) {
        Ok(_) => UdpState::Open,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => UdpState::Closed,
        Err(_) => UdpState::OpenFiltered,
    }
}

/// Parse a port specification like `"22,80,100-200,443"` into a sorted,
/// deduplicated list of port numbers.
pub fn parse_ports(s: &str) -> anyhow::Result<Vec<u16>> {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u16 = lo.trim().parse()?;
            let hi: u16 = hi.trim().parse()?;
            for p in lo..=hi {
                set.insert(p);
            }
        } else {
            set.insert(part.parse::<u16>()?);
        }
    }
    Ok(set.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};
    use std::time::Duration;

    // ── parse_ports ────────────────────────────────────────────────────────

    #[test]
    fn parse_single_port() {
        assert_eq!(parse_ports("22").unwrap(), vec![22]);
    }

    #[test]
    fn parse_range() {
        assert_eq!(parse_ports("20-22").unwrap(), vec![20, 21, 22]);
    }

    #[test]
    fn parse_mixed() {
        assert_eq!(parse_ports("22,80,100-102").unwrap(), vec![22, 80, 100, 101, 102]);
    }

    #[test]
    fn parse_dedup() {
        assert_eq!(parse_ports("22,22,80").unwrap(), vec![22, 80]);
    }

    #[test]
    fn parse_invalid_returns_err() {
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("22,xyz").is_err());
    }

    // ── tcp_scan ───────────────────────────────────────────────────────────

    #[test]
    fn tcp_scan_finds_open_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let open = tcp_scan(Ipv4Addr::LOCALHOST, &[port], Duration::from_millis(500));
        assert_eq!(open, vec![port]);
    }

    #[test]
    fn tcp_scan_closed_port_returns_empty() {
        // Bind then drop to free the port; race is negligible in practice.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // Listener dropped here — port is now closed.
        let open = tcp_scan(Ipv4Addr::LOCALHOST, &[port], Duration::from_millis(200));
        assert!(open.is_empty(), "expected closed port, got: {open:?}");
    }

    #[test]
    fn tcp_scan_multiple_ports_returns_only_open() {
        let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
        let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let p1 = l1.local_addr().unwrap().port();
        let p2 = l2.local_addr().unwrap().port();
        // p3 is not bound
        let p3 = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut ports = vec![p1, p2, p3];
        ports.sort_unstable();
        let open = tcp_scan(Ipv4Addr::LOCALHOST, &ports, Duration::from_millis(300));
        assert!(open.contains(&p1));
        assert!(open.contains(&p2));
        assert!(!open.contains(&p3));
    }

    // ── udp_scan ───────────────────────────────────────────────────────────

    #[test]
    fn udp_scan_bound_port_is_open_filtered() {
        // A bound UDP socket absorbs the probe but never responds → timeout → OpenFiltered.
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        let results = udp_scan(Ipv4Addr::LOCALHOST, &[port], Duration::from_millis(500));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, port);
        assert_eq!(results[0].1, UdpState::OpenFiltered);
    }

    #[test]
    fn udp_scan_unbound_port_is_absent() {
        // Unbound port → ICMP Port Unreachable → ECONNREFUSED → Closed → filtered out.
        let port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // Socket dropped; port now unbound.
        let results = udp_scan(Ipv4Addr::LOCALHOST, &[port], Duration::from_millis(200));
        assert!(
            results.is_empty(),
            "expected closed port to be absent, got: {results:?}"
        );
    }
}
