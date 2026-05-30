mod device;
mod network;
mod resolver;
mod scanner;

use anyhow::Result;
use clap::Parser;
use comfy_table::{presets::UTF8_FULL, Table};
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

    eprintln!("Scanning {} on {} ({local_ip}) …", net, iface.name);

    let timeout = Duration::from_secs(cli.timeout);
    let mut pairs = scanner::arp_scan(&iface, net, local_ip, timeout)?;
    pairs.sort_by_key(|(ip, _)| *ip);

    let devices: Vec<device::Device> = pairs
        .into_iter()
        .map(|(ip, mac)| {
            let hostname = resolver::resolve_hostname(ip);
            device::Device::new(ip, mac, hostname)
        })
        .collect();

    eprintln!("Found {} device(s).\n", devices.len());

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(["IP Address", "MAC Address", "Hostname"]);
    for d in &devices {
        table.add_row([d.ip.to_string(), d.mac.to_string(), d.hostname.clone()]);
    }
    println!("{table}");

    Ok(())
}
