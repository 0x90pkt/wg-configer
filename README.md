# wg-configer

WireGuard configuration generator. Produces paired server + client `.conf` files ready for `wg-quick`.

## Features

- Generates keypairs and per-client pre-shared keys via `wg` tools
- Supports user-provided keys for existing deployments
- Multi-client generation (`--clients N`) with auto-sized subnets
- Configurable masquerade (iptables NAT) rules with selectable outbound interface
- DNS control: custom servers, or disable entirely
- Full tunnel (default) or split tunnel via `--allowed-ips`
- IPv6 support (opt-in via `--ipv6`)
- Dry-run mode for previewing configs before writing
- Configs written with 0600 permissions
- Auto-generated two-word petnames for unnamed configs

## Requirements

- Python 3
- `wg` (WireGuard tools) in PATH
- `petname` Python package (only needed if `--name` is not provided)

```bash
pip install petname
```

## Usage

```
wg-configer.py --endpoint <host:port> [options]
```

### Quick Start

```bash
# Basic -- generates server + client configs in ./neatorca/ (random name)
python3 wg-configer.py --endpoint vpn.example.com:51820

# Named config with 5 clients
python3 wg-configer.py --endpoint vpn.lab:51820 --name labtunnel --clients 5

# Split tunnel, no masquerade, custom DNS
python3 wg-configer.py --endpoint vpn.lab:51820 \
  --allowed-ips 10.0.0.0/8,172.16.0.0/12 \
  --no-masquerade --dns 9.9.9.9

# Preview without writing files
python3 wg-configer.py --endpoint vpn.lab:51820 --dry-run

# Custom subnet, IPv6, NAT keepalive
python3 wg-configer.py --endpoint vpn.lab:51820 \
  --subnet 10.66.66.0/24 --ipv6 --persistent-keepalive 25

# Disable DNS, use wlan0 for masquerade
python3 wg-configer.py --endpoint vpn.lab:51820 --no-dns --masq-interface wlan0

# Provide your own keys
python3 wg-configer.py --endpoint vpn.lab:51820 \
  --server-privkey <base64_key> --client-privkey <base64_key>
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-e, --endpoint` | *(none)* | Server endpoint `host:port` |
| `-n, --name` | random petname | Config directory and filename prefix |
| `-o, --output-dir` | cwd | Parent directory for config folder |
| `-c, --clients N` | 1 | Number of client configs to generate |
| `-p, --listen-port` | 51820 | Server listen port |
| `--subnet` | auto-sized from 10.0.0.0 | VPN subnet CIDR |
| `--allowed-ips` | `0.0.0.0/0` | Client AllowedIPs (comma-separated CIDRs) |
| `--ipv6` | off | Add `::/0` to client AllowedIPs |
| `--dns` | `1.1.1.1, 1.0.0.1` | Client DNS servers |
| `--no-dns` | | Omit DNS line entirely |
| `--no-masquerade` | | Disable iptables NAT rules on server |
| `--masq-interface` | eth0 | Outbound interface for masquerade |
| `--mtu` | *(auto)* | Override interface MTU |
| `--persistent-keepalive` | off | Keepalive interval in seconds |
| `--server-privkey` | *(generated)* | Provide server private key |
| `--client-privkey` | *(generated)* | Provide client private key (single-client only) |
| `--psk` | *(generated)* | Provide pre-shared key (single-client only) |
| `--no-psk` | | Skip pre-shared key generation |
| `--save-config` | | Add `SaveConfig = true` to server config |
| `--table` | auto | Routing table (`off` to skip route management) |
| `--dry-run` | | Print to stdout, don't write files |

### Output Structure

```
<output-dir>/<name>/
  <name>-server.conf
  <name>-client.conf          # single client
  <name>-client1.conf         # multi-client
  <name>-client2.conf
  ...
```

### Subnet Auto-Sizing

When `--subnet` is not specified, the subnet prefix auto-sizes to fit the requested number of clients:

| Clients | Prefix | Usable Hosts |
|---|---|---|
| 1-5 | /29 | 6 |
| 6-13 | /28 | 14 |
| 14-29 | /27 | 30 |
| 30-61 | /26 | 62 |
| 62-125 | /25 | 126 |
| 126-253 | /24 | 254 |

When `--subnet` is explicitly provided, the tool validates that the subnet has enough addresses and exits with an error if not.
