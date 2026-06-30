#!/usr/bin/env python3
"""wg-configer: WireGuard configuration generator.

Generates paired server/client WireGuard configs with key management,
masquerade rules, DNS, and flexible networking options.
"""

import argparse
import ipaddress
import math
import os
import subprocess
import sys
import textwrap

try:
    import petname
except ImportError:
    petname = None


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def _run_wg(*args, stdin_data=None):
    """Run a wg subcommand and return stripped stdout."""
    result = subprocess.run(
        ["wg", *args],
        input=stdin_data,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.exit(f"[!] wg {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def gen_privkey():
    return _run_wg("genkey")


def gen_pubkey(privkey):
    return _run_wg("pubkey", stdin_data=privkey)


def gen_psk():
    return _run_wg("genpsk")


def gen_keypair():
    priv = gen_privkey()
    pub = gen_pubkey(priv)
    return priv, pub


# ---------------------------------------------------------------------------
# Subnet sizing
# ---------------------------------------------------------------------------

def smallest_prefix_for_hosts(count):
    """Return the largest prefix length (smallest subnet) that fits `count` usable hosts.

    IPv4 subnets have 2^(32-prefix) - 2 usable addresses (network + broadcast excluded).
    A /31 is special (point-to-point, 2 usable) but we avoid it for clarity.
    """
    # Need 2^(32-N) - 2 >= count  =>  2^(32-N) >= count+2  =>  32-N >= ceil(log2(count+2))
    bits_needed = math.ceil(math.log2(count + 2))
    prefix = 32 - bits_needed
    # Clamp to reasonable range: /8 at most, /29 at smallest (6 usable hosts)
    return max(8, min(prefix, 29))


def auto_subnet(num_clients, base="10.0.0.0"):
    """Build a subnet sized for 1 server + num_clients clients."""
    needed = num_clients + 1  # server + clients
    prefix = smallest_prefix_for_hosts(needed)
    network = ipaddress.ip_network(f"{base}/{prefix}", strict=False)
    return network


# ---------------------------------------------------------------------------
# Config rendering
# ---------------------------------------------------------------------------

def build_server_config(
    server_privkey,
    server_address,
    listen_port,
    peers,
    masquerade=True,
    masq_interface="eth0",
    dns=None,
    no_dns=False,
    mtu=None,
    save_config=False,
    table=None,
):
    """Build server config with one or more [Peer] sections.

    peers: list of dicts with keys: pubkey, psk (or None), allowed_ips
    """
    lines = ["[Interface]"]
    lines.append(f"PrivateKey = {server_privkey}")
    lines.append(f"Address = {server_address}")
    lines.append(f"ListenPort = {listen_port}")

    if mtu:
        lines.append(f"MTU = {mtu}")

    if not no_dns and dns:
        lines.append(f"DNS = {dns}")

    if save_config:
        lines.append("SaveConfig = true")

    if table:
        lines.append(f"Table = {table}")

    if masquerade:
        lines.append(
            f"PostUp = iptables -A FORWARD -i %i -j ACCEPT; "
            f"iptables -t nat -A POSTROUTING -o {masq_interface} -j MASQUERADE"
        )
        lines.append(
            f"PostDown = iptables -D FORWARD -i %i -j ACCEPT; "
            f"iptables -t nat -D POSTROUTING -o {masq_interface} -j MASQUERADE"
        )

    for peer in peers:
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {peer['pubkey']}")
        if peer.get("psk"):
            lines.append(f"PresharedKey = {peer['psk']}")
        lines.append(f"AllowedIPs = {peer['allowed_ips']}")

    return "\n".join(lines) + "\n"


def build_client_config(
    client_privkey,
    client_address,
    server_pubkey,
    endpoint,
    allowed_ips,
    psk=None,
    dns=None,
    no_dns=False,
    mtu=None,
    persistent_keepalive=None,
    table=None,
):
    lines = ["[Interface]"]
    lines.append(f"PrivateKey = {client_privkey}")
    lines.append(f"Address = {client_address}")

    if mtu:
        lines.append(f"MTU = {mtu}")

    if not no_dns:
        if dns:
            lines.append(f"DNS = {dns}")
        else:
            lines.append("DNS = 1.1.1.1, 1.0.0.1")

    if table:
        lines.append(f"Table = {table}")

    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_pubkey}")

    if psk:
        lines.append(f"PresharedKey = {psk}")

    if endpoint:
        lines.append(f"Endpoint = {endpoint}")

    lines.append(f"AllowedIPs = {allowed_ips}")

    if persistent_keepalive is not None:
        lines.append(f"PersistentKeepalive = {persistent_keepalive}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_allowed_ips(value):
    """Validate a comma-separated list of CIDR networks."""
    parts = [p.strip() for p in value.split(",")]
    for part in parts:
        try:
            ipaddress.ip_network(part, strict=False)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"Invalid network in AllowedIPs: {part!r}"
            )
    return ", ".join(parts)


def validate_endpoint(value):
    """Basic sanity check: must contain host:port."""
    if ":" not in value:
        raise argparse.ArgumentTypeError(
            f"Endpoint must be in host:port format, got: {value!r}"
        )
    host, port_str = value.rsplit(":", 1)
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Endpoint port must be 1-65535, got: {port_str!r}"
        )
    return value


def validate_port(value):
    port = int(value)
    if not (1 <= port <= 65535):
        raise argparse.ArgumentTypeError(f"Port must be 1-65535, got: {value}")
    return port


def generate_name():
    """Two-word petname with no separator."""
    if petname is None:
        sys.exit(
            "[!] petname module not installed. "
            "Install it (pip install petname) or provide --name."
        )
    return petname.generate(words=2, separator="")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="wg-configer",
        description="Generate paired WireGuard server + client configurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s --endpoint vpn.example.com:51820
              %(prog)s --name mytunnel --endpoint 203.0.113.1:51820 --no-masquerade
              %(prog)s --endpoint vpn.lab:51820 --allowed-ips 10.0.0.0/8,192.168.0.0/16
              %(prog)s --endpoint vpn.lab:51820 --server-privkey <key> --client-privkey <key>
              %(prog)s --endpoint vpn.lab:51820 --no-dns --subnet 10.66.66.0/24
              %(prog)s --endpoint vpn.lab:51820 --clients 5
              %(prog)s --endpoint vpn.lab:51820 --clients 3 --subnet 10.66.66.0/24
              %(prog)s --endpoint vpn.lab:51820 --ipv6
        """),
    )

    # -- Naming / output --
    naming = p.add_argument_group("naming and output")
    naming.add_argument(
        "-n", "--name",
        help="Config name (used for directory and .conf filenames). "
             "Defaults to a random two-word petname.",
    )
    naming.add_argument(
        "-o", "--output-dir",
        help="Parent directory for the config folder. Defaults to cwd.",
    )

    # -- Networking --
    net = p.add_argument_group("networking")
    net.add_argument(
        "-e", "--endpoint",
        type=validate_endpoint,
        help="Server endpoint in host:port format (e.g. vpn.example.com:51820). "
             "Required for a usable client config.",
    )
    net.add_argument(
        "-p", "--listen-port",
        type=validate_port,
        default=51820,
        help="Server listen port (default: 51820).",
    )
    net.add_argument(
        "-c", "--clients",
        type=int,
        default=1,
        metavar="N",
        help="Number of client configs to generate (default: 1). "
             "Subnet auto-sizes to fit when --subnet is not set.",
    )
    net.add_argument(
        "--subnet",
        default=None,
        help="VPN subnet in CIDR notation (default: auto-sized from 10.0.0.0). "
             "Server gets .1; clients get .2, .3, etc.",
    )
    net.add_argument(
        "--allowed-ips",
        type=validate_allowed_ips,
        default=None,
        help="Client AllowedIPs (default: '0.0.0.0/0' or '0.0.0.0/0, ::/0' with --ipv6). "
             "Comma-separated CIDRs for split tunnel.",
    )
    net.add_argument(
        "--ipv6",
        action="store_true",
        help="Include IPv6 catch-all (::/0) in client AllowedIPs. "
             "Off by default.",
    )
    net.add_argument(
        "--mtu",
        type=int,
        help="Interface MTU (omitted by default; wg-quick auto-detects). "
             "Common: 1420 for most setups, 1280 behind restrictive NATs.",
    )
    net.add_argument(
        "--persistent-keepalive",
        type=int,
        metavar="SECONDS",
        help="PersistentKeepalive interval for client peer (default: off). "
             "Use 25 for NAT traversal.",
    )
    net.add_argument(
        "--table",
        help="Routing table (default: auto). Set to 'off' to skip route management.",
    )

    # -- DNS --
    dns_group = p.add_argument_group("dns")
    dns_mx = dns_group.add_mutually_exclusive_group()
    dns_mx.add_argument(
        "--dns",
        help="DNS server(s) for client config, comma-separated "
             "(default: '1.1.1.1, 1.0.0.1').",
    )
    dns_mx.add_argument(
        "--no-dns",
        action="store_true",
        help="Omit DNS line entirely from configs.",
    )

    # -- Masquerade --
    masq = p.add_argument_group("masquerade (NAT)")
    masq.add_argument(
        "--no-masquerade",
        action="store_true",
        help="Disable PostUp/PostDown masquerade rules on server.",
    )
    masq.add_argument(
        "--masq-interface",
        default="eth0",
        metavar="IFACE",
        help="Outbound interface for masquerade rules (default: eth0).",
    )

    # -- Keys --
    keys = p.add_argument_group("key management")
    keys.add_argument("--server-privkey", help="Provide server private key (base64).")
    keys.add_argument(
        "--client-privkey",
        help="Provide client private key (base64). Only valid with --clients 1.",
    )
    keys.add_argument(
        "--psk",
        help="Provide a pre-shared key (base64). Only valid with --clients 1. "
             "If omitted, one is generated per client.",
    )
    keys.add_argument(
        "--no-psk",
        action="store_true",
        help="Skip pre-shared key entirely (less post-quantum resistance).",
    )

    # -- Misc --
    misc = p.add_argument_group("misc")
    misc.add_argument(
        "--save-config",
        action="store_true",
        help="Add SaveConfig = true to server config.",
    )
    misc.add_argument(
        "--dry-run",
        action="store_true",
        help="Print configs to stdout instead of writing files.",
    )

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    num_clients = args.clients
    if num_clients < 1:
        sys.exit("[!] --clients must be >= 1.")

    # Validate single-client-only flags
    if num_clients > 1:
        if args.client_privkey:
            sys.exit("[!] --client-privkey can only be used with --clients 1.")
        if args.psk:
            sys.exit("[!] --psk can only be used with --clients 1.")

    # -- Resolve AllowedIPs default based on --ipv6 --
    if args.allowed_ips is not None:
        allowed_ips = args.allowed_ips
    elif args.ipv6:
        allowed_ips = "0.0.0.0/0, ::/0"
    else:
        allowed_ips = "0.0.0.0/0"

    # -- Name --
    name = args.name or generate_name()

    # -- Subnet --
    if args.subnet:
        try:
            network = ipaddress.ip_network(args.subnet, strict=False)
        except ValueError:
            sys.exit(f"[!] Invalid subnet: {args.subnet}")
        hosts = list(network.hosts())
        needed = num_clients + 1
        if len(hosts) < needed:
            sys.exit(
                f"[!] Subnet {network} has {len(hosts)} usable hosts, "
                f"but {needed} are needed (1 server + {num_clients} client(s)). "
                f"Use a larger subnet or reduce --clients."
            )
    else:
        network = auto_subnet(num_clients)
        hosts = list(network.hosts())

    prefix = network.prefixlen
    server_addr = f"{hosts[0]}/{prefix}"

    # -- Server keys --
    if args.server_privkey:
        server_priv = args.server_privkey
        server_pub = gen_pubkey(server_priv)
    else:
        server_priv, server_pub = gen_keypair()

    # -- Generate per-client data --
    clients = []
    for i in range(num_clients):
        client_ip = hosts[i + 1]  # .2, .3, .4, ...
        client_addr = f"{client_ip}/{prefix}"
        client_peer_ip = f"{client_ip}/32"

        if args.client_privkey:
            c_priv = args.client_privkey
            c_pub = gen_pubkey(c_priv)
        else:
            c_priv, c_pub = gen_keypair()

        if args.no_psk:
            c_psk = None
        elif args.psk:
            c_psk = args.psk
        else:
            c_psk = gen_psk()

        clients.append({
            "index": i + 1,
            "privkey": c_priv,
            "pubkey": c_pub,
            "psk": c_psk,
            "address": client_addr,
            "peer_ip": client_peer_ip,
        })

    # -- Endpoint --
    endpoint = args.endpoint
    listen_port = args.listen_port

    if endpoint:
        _, ep_port_str = endpoint.rsplit(":", 1)
        ep_port = int(ep_port_str)
        if ep_port != listen_port:
            print(
                f"[*] Note: endpoint port ({ep_port}) differs from "
                f"listen-port ({listen_port}). This is fine if port "
                f"forwarding is in play."
            )

    # -- Build server config with all peers --
    server_peers = [
        {"pubkey": c["pubkey"], "psk": c["psk"], "allowed_ips": c["peer_ip"]}
        for c in clients
    ]

    server_cfg = build_server_config(
        server_privkey=server_priv,
        server_address=server_addr,
        listen_port=listen_port,
        peers=server_peers,
        masquerade=not args.no_masquerade,
        masq_interface=args.masq_interface,
        dns=args.dns,
        no_dns=args.no_dns,
        mtu=args.mtu,
        save_config=args.save_config,
        table=args.table,
    )

    # -- Build client configs --
    client_cfgs = []
    for c in clients:
        cfg = build_client_config(
            client_privkey=c["privkey"],
            client_address=c["address"],
            server_pubkey=server_pub,
            endpoint=endpoint,
            allowed_ips=allowed_ips,
            psk=c["psk"],
            dns=args.dns,
            no_dns=args.no_dns,
            mtu=args.mtu,
            persistent_keepalive=args.persistent_keepalive,
            table=args.table,
        )
        client_cfgs.append((c, cfg))

    # -- Client filename helper --
    def client_filename(idx):
        if num_clients == 1:
            return f"{name}-client.conf"
        return f"{name}-client{idx}.conf"

    # -- Output --
    if args.dry_run:
        print(f"# --- {name} server ({name}-server.conf) ---")
        print(server_cfg)
        for c, cfg in client_cfgs:
            fname = client_filename(c["index"])
            print(f"# --- {name} client {c['index']} ({fname}) ---")
            print(cfg)
        _print_summary(name, network, server_addr, clients, endpoint,
                        listen_port, allowed_ips, args)
        return

    parent = args.output_dir or os.getcwd()
    config_dir = os.path.join(parent, name)
    os.makedirs(config_dir, exist_ok=True)

    server_path = os.path.join(config_dir, f"{name}-server.conf")
    _write_secure(server_path, server_cfg)

    written_files = [f"{name}-server.conf"]
    for c, cfg in client_cfgs:
        fname = client_filename(c["index"])
        client_path = os.path.join(config_dir, fname)
        _write_secure(client_path, cfg)
        written_files.append(fname)

    print(f"[+] Configs written to: {config_dir}/")
    for f in written_files:
        print(f"    {f}")
    _print_summary(name, network, server_addr, clients, endpoint,
                    listen_port, allowed_ips, args)


def _write_secure(path, content):
    """Write file with 0600 permissions."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)


def _print_summary(name, network, server_addr, clients, endpoint,
                    listen_port, allowed_ips, args):
    print()
    print(f"  Name:           {name}")
    print(f"  Subnet:         {network}")
    print(f"  Server address: {server_addr}")
    if len(clients) == 1:
        print(f"  Client address: {clients[0]['address']}")
    else:
        first = clients[0]["address"]
        last = clients[-1]["address"]
        print(f"  Client addresses: {first} .. {last} ({len(clients)} clients)")
    print(f"  Listen port:    {listen_port}")
    print(f"  Endpoint:       {endpoint or '(not set - fill in before use)'}")
    print(f"  Masquerade:     {'off' if args.no_masquerade else args.masq_interface}")
    print(f"  AllowedIPs:     {allowed_ips}")
    print(f"  DNS:            {'off' if args.no_dns else (args.dns or '1.1.1.1, 1.0.0.1')}")
    print(f"  PSK:            {'off' if args.no_psk else 'enabled (per client)'}")
    if args.ipv6:
        print(f"  IPv6:           enabled")
    if args.mtu:
        print(f"  MTU:            {args.mtu}")
    if args.persistent_keepalive:
        print(f"  Keepalive:      {args.persistent_keepalive}s")


if __name__ == "__main__":
    main()
