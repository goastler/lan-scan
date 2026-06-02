# lanscan

A fast LAN network scanner. Discovers devices on the local network via ARP and optionally scans TCP/UDP ports. Results stream to stdout as they arrive.

Built out of frustration with router web GUIs that don't show all connected devices — looking at you, BT Home Hub.

## Install

**cargo:**
```bash
cargo install lanscan
```

**AUR (Arch Linux):**
```bash
yay -S lanscan
```

**Binary releases:** download a pre-built binary for your platform from the [releases page](https://github.com/goastler/lan-scan/releases/latest).

## Requirements

- Linux (or macOS)
- `sudo` or `CAP_NET_RAW` — required for raw Ethernet sockets used by ARP scanning

## Usage

```
LAN network scanner — discovers devices via ARP, optionally scans TCP/UDP ports

Usage: lanscan [OPTIONS]

Options:
  -i, --interface <INTERFACE>        Network interface to scan (default: auto-detect)
  -t, --timeout <TIMEOUT>            Seconds to wait for ARP replies [default: 3]
      --tcp [<PORTS>]                TCP connect scan; optional port list e.g. "22,80,100-200" (default: 1-65535)
      --udp [<PORTS>]                UDP probe scan; optional port list e.g. "53,123,161" (default: 1-65535)
  -n, --network <CIDR>               IP range to scan in CIDR notation, e.g. 10.0.0.0/24 (default: interface subnet)
      --scan-timeout <SCAN_TIMEOUT>  Per-port timeout in milliseconds for TCP/UDP scanning [default: 200]
  -h, --help                         Print help
  -V, --version                      Print version
```

### ARP discovery only

```bash
sudo lanscan
```

```
Scanning 192.168.0.0/24 on eth0 (192.168.0.225) …

IP Address       MAC Address        Hostname
───────────────────────────────────────────────────────
192.168.0.1      4c:22:f3:6a:0b:4f  router.local
192.168.0.206    6c:ad:f8:2c:6e:05  desktop.local
192.168.0.247    54:df:1b:1f:7a:06  (unknown)

3 device(s) found.
```

### TCP port scan (all ports)

```bash
sudo lanscan --tcp
```

### TCP port scan (specific ports)

```bash
sudo lanscan --tcp 22,80,443,8080
```

### UDP probe scan

```bash
sudo lanscan --udp 53,123,161,5353
```

### TCP and UDP together

```bash
sudo lanscan --tcp 22,80,443 --udp 53,123
```

Port scan output appends after ARP discovery:

```
IP Address       TCP Open                        UDP Open / Filtered
───────────────────────────────────────────────────────────────────────────────
192.168.0.1      22, 80, 443                     53, 5353?
192.168.0.206    22                              (none)
192.168.0.247    (none)                          (none)
```

A `?` suffix on a UDP port means *open|filtered* — no response was received within the timeout, so the port may be open or silently firewalled.

### Scan a specific IP range

```bash
sudo lanscan --network 10.0.10.0/24
```

Useful when scanning a subnet different from your interface's own, or the WiFi subnet from a wired interface:

```bash
sudo lanscan --interface eth0 --network 192.168.1.0/24
```

### Scan a specific interface

```bash
sudo lanscan --interface wlan0
```

### Tune timeouts

```bash
# Wait 5 seconds for ARP replies (useful on slow/busy networks)
sudo lanscan --timeout 5

# Use 500ms per-port timeout for TCP/UDP (useful across VPNs or slow links)
sudo lanscan --tcp --scan-timeout 500
```

## How it works

**ARP discovery** — sends raw ARP request frames to every host address in the subnet (broadcast `ff:ff:ff:ff:ff:ff`). Devices reply with their MAC address. Hostnames are resolved via reverse DNS.

**TCP scanning** — standard connect scan (`TcpStream::connect_timeout`). Open means a full TCP handshake completed; closed means connection was refused.

**UDP scanning** — sends an empty datagram to each port. `ECONNREFUSED` (ICMP Port Unreachable) means closed; a data response means open; timeout means open|filtered.

## WiFi devices

WiFi and wired devices are treated identically — ARP operates at the broadcast-domain level, not the physical medium. As long as WiFi clients are on the same subnet as the scanning host, they will be discovered.

If your router separates wired and wireless into different subnets, use `--network` to target the other subnet explicitly (and ensure your interface can route to it).

## Running tests

```bash
cargo test                            # unit tests only (no root required)
sudo cargo test -- --include-ignored  # includes live ARP and DNS tests
```
