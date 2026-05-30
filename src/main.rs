mod device;
mod network;
mod port_scanner;
mod resolver;
mod scanner;

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::mpsc;
use std::time::Duration;

/// LAN network scanner — discovers devices via ARP, optionally scans ports
#[derive(Parser, Debug)]
#[command(name = "lan", version, about)]
struct Cli {
    /// Network interface to scan (default: auto-detect)
    #[arg(short, long)]
    interface: Option<String>,

    /// Seconds to wait for ARP replies
    #[arg(short, long, default_value_t = 3)]
    timeout: u64,

    /// TCP connect scan; optional port list e.g. "22,80,100-200" (default: 1-65535)
    #[arg(long, value_name = "PORTS", num_args = 0..=1, default_missing_value = "1-65535")]
    tcp: Option<String>,

    /// UDP probe scan; optional port list e.g. "53,123,161" (default: 1-65535)
    #[arg(long, value_name = "PORTS", num_args = 0..=1, default_missing_value = "1-65535")]
    udp: Option<String>,

    /// Per-port timeout in milliseconds for TCP/UDP scanning
    #[arg(long, default_value_t = 200)]
    scan_timeout: u64,
}

struct PortResults {
    ip: std::net::Ipv4Addr,
    tcp_open: Vec<u16>,
    udp_results: Vec<(u16, port_scanner::UdpState)>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let tcp_ports: Option<Vec<u16>> = cli
        .tcp
        .as_deref()
        .map(|s| port_scanner::parse_ports(s).context("invalid --tcp port spec"))
        .transpose()?;
    let udp_ports: Option<Vec<u16>> = cli
        .udp
        .as_deref()
        .map(|s| port_scanner::parse_ports(s).context("invalid --udp port spec"))
        .transpose()?;

    let iface = network::select_interface(cli.interface.as_deref())?;
    let net = network::get_network(&iface)?;
    let local_ip = network::local_ipv4(&iface)?;

    eprintln!("Scanning {} on {} ({local_ip}) …\n", net, iface.name);

    // ── Phase 1: ARP discovery, stream each device immediately ───────────
    println!("{:<15}  {:<17}  {}", "IP Address", "MAC Address", "Hostname");
    println!("{}", "─".repeat(55));

    let arp_rx = scanner::arp_scan(&iface, net, local_ip, Duration::from_secs(cli.timeout))?;
    let mut discovered: Vec<std::net::Ipv4Addr> = Vec::new();

    for (ip, mac) in arp_rx {
        let hostname = resolver::resolve_hostname(ip);
        println!("{:<15}  {:<17}  {}", ip, mac, hostname);
        discovered.push(ip);
    }

    eprintln!("\n{} device(s) found.", discovered.len());

    if tcp_ports.is_none() && udp_ports.is_none() {
        return Ok(());
    }

    // ── Phase 2: Port scanning, one thread per host, stream results ───────
    let scan_timeout = Duration::from_millis(cli.scan_timeout);
    let port_desc = match (&tcp_ports, &udp_ports) {
        (Some(t), Some(u)) => format!("TCP {} ports, UDP {} ports", t.len(), u.len()),
        (Some(t), None) => format!("TCP {} ports", t.len()),
        (None, Some(u)) => format!("UDP {} ports", u.len()),
        (None, None) => unreachable!(),
    };
    eprintln!("\nPort scanning {} device(s) ({port_desc})…\n", discovered.len());

    println!("{:<15}  {:<30}  {}", "IP Address", "TCP Open", "UDP Open / Filtered");
    println!("{}", "─".repeat(75));

    let (result_tx, result_rx) = mpsc::channel::<PortResults>();
    for ip in discovered {
        let tx = result_tx.clone();
        let tcp = tcp_ports.clone();
        let udp = udp_ports.clone();
        let t = scan_timeout;
        std::thread::spawn(move || {
            let tcp_open = tcp.map(|p| port_scanner::tcp_scan(ip, &p, t)).unwrap_or_default();
            let udp_results = udp.map(|p| port_scanner::udp_scan(ip, &p, t)).unwrap_or_default();
            let _ = tx.send(PortResults { ip, tcp_open, udp_results });
        });
    }
    drop(result_tx);

    for r in result_rx {
        let tcp_str = if r.tcp_open.is_empty() {
            "(none)".to_string()
        } else {
            r.tcp_open.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        };

        let udp_str = if r.udp_results.is_empty() {
            "(none)".to_string()
        } else {
            r.udp_results
                .iter()
                .map(|(p, s)| match s {
                    port_scanner::UdpState::Open => p.to_string(),
                    port_scanner::UdpState::OpenFiltered => format!("{p}?"),
                    port_scanner::UdpState::Closed => unreachable!(),
                })
                .collect::<Vec<_>>()
                .join(", ")
        };

        println!("{:<15}  {:<30}  {}", r.ip, tcp_str, udp_str);
    }

    Ok(())
}
