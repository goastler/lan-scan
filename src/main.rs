mod device;
mod network;
mod resolver;
mod scanner;

use anyhow::Result;
use clap::Parser;
use std::time::Duration;

/// LAN network scanner — discovers devices via ARP
#[derive(Parser, Debug)]
#[command(name = "lan", version, about)]
struct Cli {
    /// Network interface to scan (default: auto-detect)
    #[arg(short, long)]
    interface: Option<String>,

    /// Seconds to wait for ARP replies
    #[arg(short, long, default_value_t = 3)]
    timeout: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let iface = network::select_interface(cli.interface.as_deref())?;
    let net = network::get_network(&iface)?;
    let local_ip = network::local_ipv4(&iface)?;

    eprintln!("Scanning {} on {} ({local_ip}) …\n", net, iface.name);

    println!("{:<15}  {:<17}  {}", "IP Address", "MAC Address", "Hostname");
    println!("{}", "─".repeat(55));

    let rx = scanner::arp_scan(&iface, net, local_ip, Duration::from_secs(cli.timeout))?;
    let mut count = 0usize;
    for (ip, mac) in rx {
        let hostname = resolver::resolve_hostname(ip);
        println!("{:<15}  {:<17}  {}", ip, mac, hostname);
        count += 1;
    }

    eprintln!("\n{count} device(s) found.");
    Ok(())
}
