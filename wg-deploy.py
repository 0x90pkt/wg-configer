#!/usr/bin/env python3
"""wg-deploy.py: chained WireGuard + SSH hardening deployment helper.

This tool renders and optionally deploys a linear WireGuard chain:

    VPS1 <-> VPS2 <-> VPS3 <-> ...

Each VPS has one WireGuard interface and at most two VPS peers: the previous
and next host in the inventory. AllowedIPs are directional, so traffic to
downstream nodes moves to the next peer and traffic to upstream nodes moves to
the previous peer. This is deliberately not a full mesh.

The script is stdlib-only except for the local `wg` binary when it needs to
generate or derive WireGuard keys.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_SAMPLE = """\
{
  "name": "vps-chain",
  "wg_subnet": "10.88.0.0/24",
  "interface": "wg0",
  "wg_port": 51820,
  "ssh_port": 2222,
  "bootstrap_ssh_port": 22,
  "ssh_user": "root",
  "persistent_keepalive": 25,
  "ssh_private_key": "{{SSH_KEY}}",
  "authorized_keys_file": "{{AUTHORIZED_KEYS_FILE}}",
  "operator": {
    "enabled": true,
    "name": "operator",
    "wg_ip": "10.88.0.254"
  },
  "hardening": {
    "lock_public_ssh": true,
    "firewall": "ufw",
    "fail2ban": true,
    "install_packages": true,
    "allow_tcp_forwarding": true
  },
  "hosts": [
    {
      "name": "vps1",
      "public_ip": "{{VPS1_IP}}"
    },
    {
      "name": "vps2",
      "public_ip": "{{VPS2_IP}}"
    },
    {
      "name": "vps3",
      "public_ip": "{{VPS3_IP}}"
    }
  ]
}
"""


TEMPLATE_RE = re.compile(r"{{\s*([A-Za-z_][A-Za-z0-9_]*)\s*}}")
WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def log(msg: str) -> None:
    sys.stderr.write(msg + "\n")


def die(msg: str, code: int = 1) -> "None":
    log(f"ERROR: {msg}")
    sys.exit(code)


def run_local(cmd: list[str], *, stdin_data: str | None = None) -> str:
    result = subprocess.run(
        cmd,
        input=stdin_data,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip()
        die(f"{' '.join(cmd)} failed: {stderr}")
    return result.stdout.strip()


def have_wg() -> bool:
    return shutil.which("wg") is not None


def wg_genkey() -> str:
    return run_local(["wg", "genkey"])


def wg_pubkey(private_key: str) -> str:
    return run_local(["wg", "pubkey"], stdin_data=private_key)


def wg_genpsk() -> str:
    return run_local(["wg", "genpsk"])


def read_text(path: str | Path) -> str:
    try:
        return Path(path).expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        die(f"cannot read {path!r}: {exc}")


def read_secret_ref(value: str | None) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    if value.startswith("file:"):
        return read_text(value[5:]).strip()
    return value


def parse_set(values: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            die(f"--set must be KEY=VALUE, got {item!r}")
        key, val = item.split("=", 1)
        key = key.strip()
        if not key:
            die(f"--set has an empty key in {item!r}")
        out[key] = val
    return out


def apply_template(raw: str, variables: dict[str, str]) -> str:
    missing: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key in variables:
            return variables[key]
        if key in os.environ:
            return os.environ[key]
        missing.add(key)
        return match.group(0)

    rendered = TEMPLATE_RE.sub(replace, raw)
    if missing:
        names = ", ".join(sorted(missing))
        die(f"unresolved template variable(s): {names}. Provide --set KEY=VALUE or environment variables.")
    return rendered


def load_inventory(path: str, variables: dict[str, str]) -> dict[str, Any]:
    raw = read_text(path)
    rendered = apply_template(raw, variables)
    try:
        data = json.loads(rendered)
    except json.JSONDecodeError as exc:
        die(f"inventory JSON is invalid after templating: {exc}")
    if not isinstance(data, dict):
        die("inventory root must be a JSON object")
    return data


def merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_dict(merged[key], val)
        else:
            merged[key] = val
    return merged


def as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    die(f"invalid boolean value: {value!r}")


def as_int(value: Any, name: str, default: int | None = None) -> int | None:
    if value is None:
        return default
    try:
        out = int(value)
    except (TypeError, ValueError):
        die(f"{name} must be an integer, got {value!r}")
    return out


def validate_port(value: int | None, name: str) -> int | None:
    if value is None:
        return None
    if not (1 <= value <= 65535):
        die(f"{name} must be 1-65535, got {value}")
    return value


def safe_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return safe.strip("._") or "host"


def write_secure(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, mode)


def ip_without_prefix(value: str) -> str:
    text = str(value).strip()
    if "/" in text:
        return str(ipaddress.ip_interface(text).ip)
    return str(ipaddress.ip_address(text))


@dataclass
class Hardening:
    lock_public_ssh: bool = True
    firewall: str = "ufw"
    fail2ban: bool = True
    install_packages: bool = True
    allow_tcp_forwarding: bool = True
    disable_ipv6: bool = False


@dataclass
class Host:
    index: int
    name: str
    public_ip: str
    endpoint: str
    wg_ip: str
    wg_port: int
    ssh_port: int
    bootstrap_ssh_port: int
    ssh_user: str
    ssh_private_key: str | None
    authorized_keys: list[str] = field(default_factory=list)
    wg_private_key: str | None = None
    wg_public_key: str | None = None
    mtu: int | None = None
    persistent_keepalive: int | None = None
    table: str | None = None


@dataclass
class OperatorPeer:
    enabled: bool
    name: str = "operator"
    wg_ip: str | None = None
    private_key: str | None = None
    public_key: str | None = None
    preshared_key: str | None = None
    persistent_keepalive: int | None = 25


@dataclass
class Link:
    index: int
    left: str
    right: str
    preshared_key: str | None


@dataclass
class Plan:
    name: str
    interface: str
    wg_subnet: ipaddress.IPv4Network | ipaddress.IPv6Network
    hosts: list[Host]
    links: list[Link]
    operator: OperatorPeer
    hardening: Hardening
    out_root: Path


def normalize_inventory(data: dict[str, Any], args: argparse.Namespace) -> Plan:
    name = safe_name(str(data.get("name") or "vps-chain"))
    interface = str(data.get("interface") or "wg0")
    try:
        wg_subnet = ipaddress.ip_network(str(data.get("wg_subnet") or "10.88.0.0/24"), strict=False)
    except ValueError as exc:
        die(f"invalid wg_subnet: {exc}")

    hardening_data = merge_dict(
        {
            "lock_public_ssh": True,
            "firewall": "ufw",
            "fail2ban": True,
            "install_packages": True,
            "allow_tcp_forwarding": True,
            "disable_ipv6": False,
        },
        data.get("hardening") or {},
    )
    hardening = Hardening(
        lock_public_ssh=as_bool(hardening_data.get("lock_public_ssh"), True),
        firewall=str(hardening_data.get("firewall") or "ufw").lower(),
        fail2ban=as_bool(hardening_data.get("fail2ban"), True),
        install_packages=as_bool(hardening_data.get("install_packages"), True),
        allow_tcp_forwarding=as_bool(hardening_data.get("allow_tcp_forwarding"), True),
        disable_ipv6=as_bool(hardening_data.get("disable_ipv6"), False),
    )
    if hardening.firewall not in {"ufw", "iptables", "none"}:
        die("hardening.firewall must be one of: ufw, iptables, none")

    defaults = {
        "wg_port": data.get("wg_port", 51820),
        "ssh_port": data.get("ssh_port", 2222),
        "bootstrap_ssh_port": data.get("bootstrap_ssh_port", 22),
        "ssh_user": data.get("ssh_user", "root"),
        "ssh_private_key": data.get("ssh_private_key"),
        "authorized_keys": data.get("authorized_keys", []),
        "authorized_keys_file": data.get("authorized_keys_file"),
        "mtu": data.get("mtu"),
        "persistent_keepalive": data.get("persistent_keepalive", 25),
        "table": data.get("table"),
    }

    host_items = data.get("hosts")
    if not isinstance(host_items, list) or not host_items:
        die("inventory must contain a non-empty hosts array")
    if len(host_items) < 2:
        die("chain deployment needs at least two hosts")

    assigned_ips = allocate_wg_ips(wg_subnet, host_items, data.get("operator") or {})

    hosts: list[Host] = []
    for idx, item in enumerate(host_items):
        if not isinstance(item, dict):
            die(f"hosts[{idx}] must be an object")
        merged = merge_dict(defaults, item)
        public_ip = str(merged.get("public_ip") or "").strip()
        if not public_ip:
            die(f"hosts[{idx}] is missing public_ip")
        host_name = safe_name(str(merged.get("name") or f"vps{idx + 1}"))
        endpoint = str(merged.get("endpoint") or public_ip).strip()
        ssh_user = str(merged.get("ssh_user") or "root")
        if ssh_user != "root":
            die(f"{host_name}: ssh_user must be root for this deployment model")

        ssh_port = validate_port(as_int(merged.get("ssh_port"), f"{host_name}.ssh_port"), f"{host_name}.ssh_port")
        bootstrap_port = validate_port(
            as_int(merged.get("bootstrap_ssh_port"), f"{host_name}.bootstrap_ssh_port"),
            f"{host_name}.bootstrap_ssh_port",
        )
        wg_port = validate_port(as_int(merged.get("wg_port"), f"{host_name}.wg_port"), f"{host_name}.wg_port")
        if ssh_port == 22 and not args.allow_standard_ssh_port:
            die(f"{host_name}: ssh_port is 22. Use a non-standard port or pass --allow-standard-ssh-port.")

        authorized_keys = collect_authorized_keys(merged)
        ssh_private_key = merged.get("ssh_private_key")
        if args.ssh_key:
            ssh_private_key = args.ssh_key
        if ssh_private_key:
            ssh_private_key = str(Path(str(ssh_private_key)).expanduser())

        hosts.append(
            Host(
                index=idx,
                name=host_name,
                public_ip=public_ip,
                endpoint=endpoint,
                wg_ip=assigned_ips[idx],
                wg_port=int(wg_port),
                ssh_port=int(ssh_port),
                bootstrap_ssh_port=int(bootstrap_port),
                ssh_user=ssh_user,
                ssh_private_key=ssh_private_key,
                authorized_keys=authorized_keys,
                wg_private_key=read_secret_ref(merged.get("wg_private_key")),
                wg_public_key=read_secret_ref(merged.get("wg_public_key")),
                mtu=as_int(merged.get("mtu"), f"{host_name}.mtu"),
                persistent_keepalive=as_int(merged.get("persistent_keepalive"), f"{host_name}.persistent_keepalive"),
                table=str(merged.get("table")) if merged.get("table") is not None else None,
            )
        )

    operator_data = data.get("operator") or {}
    operator = OperatorPeer(
        enabled=as_bool(operator_data.get("enabled"), False),
        name=safe_name(str(operator_data.get("name") or "operator")),
        wg_ip=assigned_ips[-1] if as_bool(operator_data.get("enabled"), False) else None,
        private_key=read_secret_ref(operator_data.get("private_key")),
        public_key=read_secret_ref(operator_data.get("public_key")),
        preshared_key=read_secret_ref(operator_data.get("preshared_key")),
        persistent_keepalive=as_int(operator_data.get("persistent_keepalive"), "operator.persistent_keepalive", 25),
    )

    if hardening.lock_public_ssh and not operator.enabled and not args.no_operator_ok:
        die(
            "hardening.lock_public_ssh=true without operator.enabled=true will remove your normal entrypoint. "
            "Enable the operator peer or pass --no-operator-ok if you really mean it."
        )

    out_root = Path(args.out_dir or data.get("out_dir") or os.getcwd()).expanduser().resolve()
    links = build_links(data.get("links") or [], hosts)
    if not args.rotate_keys:
        reuse_existing_keys(out_root, name, interface, hosts, links, operator)
    ensure_wireguard_keys(hosts, links, operator)

    return Plan(
        name=name,
        interface=interface,
        wg_subnet=wg_subnet,
        hosts=hosts,
        links=links,
        operator=operator,
        hardening=hardening,
        out_root=out_root,
    )


def allocate_wg_ips(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    host_items: list[Any],
    operator_data: dict[str, Any],
) -> list[str]:
    used: set[str] = set()
    hosts_available = list(network.hosts())
    if len(hosts_available) < len(host_items) + (1 if as_bool(operator_data.get("enabled"), False) else 0):
        die(f"wg_subnet {network} is too small for hosts plus optional operator peer")

    out: list[str] = []
    cursor = 0
    for idx, item in enumerate(host_items):
        requested = item.get("wg_ip") or item.get("wg_address") if isinstance(item, dict) else None
        if requested:
            wg_ip = ip_without_prefix(str(requested))
        else:
            while str(hosts_available[cursor]) in used:
                cursor += 1
            wg_ip = str(hosts_available[cursor])
            cursor += 1
        if ipaddress.ip_address(wg_ip) not in network:
            die(f"hosts[{idx}].wg_ip {wg_ip} is outside wg_subnet {network}")
        if wg_ip in used:
            die(f"duplicate wg_ip: {wg_ip}")
        used.add(wg_ip)
        out.append(wg_ip)

    if as_bool(operator_data.get("enabled"), False):
        requested_op = operator_data.get("wg_ip") or operator_data.get("wg_address")
        if requested_op:
            op_ip = ip_without_prefix(str(requested_op))
        else:
            op_ip = str(hosts_available[-1])
        if ipaddress.ip_address(op_ip) not in network:
            die(f"operator.wg_ip {op_ip} is outside wg_subnet {network}")
        if op_ip in used:
            die(f"operator.wg_ip {op_ip} duplicates a host wg_ip")
        out.append(op_ip)
    return out


def collect_authorized_keys(item: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    raw_keys = item.get("authorized_keys") or []
    if isinstance(raw_keys, str):
        raw_keys = [raw_keys]
    if not isinstance(raw_keys, list):
        die("authorized_keys must be a string or array of strings")
    for key in raw_keys:
        key_text = read_secret_ref(str(key))
        if key_text:
            keys.extend(line.strip() for line in key_text.splitlines() if line.strip() and not line.startswith("#"))

    auth_file = item.get("authorized_keys_file")
    if auth_file:
        text = read_text(str(Path(str(auth_file)).expanduser()))
        keys.extend(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#"))
    return sorted(set(keys))


def build_links(link_items: list[Any], hosts: list[Host]) -> list[Link]:
    links: list[Link] = []
    for idx in range(len(hosts) - 1):
        cfg: dict[str, Any] = {}
        if idx < len(link_items):
            item = link_items[idx]
            if not isinstance(item, dict):
                die(f"links[{idx}] must be an object")
            cfg = item
            left = cfg.get("left")
            right = cfg.get("right")
            if left and str(left) != hosts[idx].name:
                die(f"links[{idx}].left is {left!r}; expected {hosts[idx].name!r}")
            if right and str(right) != hosts[idx + 1].name:
                die(f"links[{idx}].right is {right!r}; expected {hosts[idx + 1].name!r}")
        links.append(
            Link(
                index=idx,
                left=hosts[idx].name,
                right=hosts[idx + 1].name,
                preshared_key=read_secret_ref(cfg.get("preshared_key")),
            )
        )
    return links


def reuse_existing_keys(
    out_root: Path,
    name: str,
    interface: str,
    hosts: list[Host],
    links: list[Link],
    operator: OperatorPeer,
) -> None:
    """Reuse previously rendered secrets unless the inventory explicitly overrides them."""
    for host in hosts:
        conf = out_root / safe_name(host.public_ip) / f"{interface}.conf"
        if conf.exists() and not host.wg_private_key:
            host.wg_private_key = parse_wg_value(conf, "PrivateKey")

    manifest_path = out_root / f"{name}-global" / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            manifest = {}
        existing_links = manifest.get("links") if isinstance(manifest, dict) else None
        if isinstance(existing_links, list):
            by_name = {
                (str(item.get("left")), str(item.get("right"))): item.get("preshared_key")
                for item in existing_links
                if isinstance(item, dict)
            }
            for link in links:
                if not link.preshared_key:
                    psk = by_name.get((link.left, link.right))
                    if psk:
                        link.preshared_key = str(psk)

    if operator.enabled:
        op_conf = out_root / f"{name}-global" / f"{operator.name}.conf"
        if op_conf.exists():
            if not operator.private_key:
                operator.private_key = parse_wg_value(op_conf, "PrivateKey")
            if not operator.preshared_key:
                operator.preshared_key = parse_wg_value(op_conf, "PresharedKey")


def parse_wg_value(path: Path, key: str) -> str | None:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=\s*(.+?)\s*$", re.IGNORECASE)
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = pattern.match(line)
            if match:
                return match.group(1).strip()
    except OSError:
        return None
    return None


def ensure_wireguard_keys(hosts: list[Host], links: list[Link], operator: OperatorPeer) -> None:
    needs_wg = False
    for host in hosts:
        if not host.wg_private_key:
            needs_wg = True
        elif not host.wg_public_key:
            needs_wg = True
    for link in links:
        if not link.preshared_key:
            needs_wg = True
    if operator.enabled and (not operator.private_key or not operator.public_key or not operator.preshared_key):
        needs_wg = True

    if needs_wg and not have_wg():
        die("local `wg` binary is required to generate/derive keys. Install WireGuard tools or provide all keys.")

    for host in hosts:
        if not host.wg_private_key:
            host.wg_private_key = wg_genkey()
        if not host.wg_public_key:
            host.wg_public_key = wg_pubkey(host.wg_private_key)
        if not looks_like_wg_key(host.wg_private_key):
            die(f"{host.name}: wg_private_key does not look like a WireGuard key")
        if not looks_like_wg_key(host.wg_public_key):
            die(f"{host.name}: wg_public_key does not look like a WireGuard key")

    for link in links:
        if not link.preshared_key:
            link.preshared_key = wg_genpsk()
        if not looks_like_wg_key(link.preshared_key):
            die(f"link {link.left}<->{link.right}: preshared_key does not look like a WireGuard key")

    if operator.enabled:
        if not operator.private_key:
            operator.private_key = wg_genkey()
        if not operator.public_key:
            operator.public_key = wg_pubkey(operator.private_key)
        if not operator.preshared_key:
            operator.preshared_key = wg_genpsk()
        if not looks_like_wg_key(operator.private_key):
            die("operator.private_key does not look like a WireGuard key")
        if not looks_like_wg_key(operator.public_key):
            die("operator.public_key does not look like a WireGuard key")
        if not looks_like_wg_key(operator.preshared_key):
            die("operator.preshared_key does not look like a WireGuard key")


def looks_like_wg_key(value: str | None) -> bool:
    return bool(value and WG_KEY_RE.match(value.strip()))


def host_allowed_ips(plan: Plan, host_index: int, peer_index: int) -> list[str]:
    if peer_index < host_index:
        ips = [wg_cidr(plan, plan.hosts[i].wg_ip) for i in range(0, host_index)]
        if plan.operator.enabled and plan.operator.wg_ip:
            ips.append(wg_cidr(plan, plan.operator.wg_ip))
        return ips
    if peer_index > host_index:
        return [wg_cidr(plan, plan.hosts[i].wg_ip) for i in range(host_index + 1, len(plan.hosts))]
    die("peer_index cannot equal host_index")


def wg_cidr(plan: Plan, ip: str) -> str:
    return f"{ip}/{plan.wg_subnet.max_prefixlen}"


def build_host_wg_conf(plan: Plan, host: Host) -> str:
    lines = [
        "[Interface]",
        f"# {plan.name}: {host.name}",
        f"PrivateKey = {host.wg_private_key}",
        f"Address = {wg_cidr(plan, host.wg_ip)}",
        f"ListenPort = {host.wg_port}",
    ]
    if host.mtu:
        lines.append(f"MTU = {host.mtu}")
    if host.table:
        lines.append(f"Table = {host.table}")

    idx = host.index
    if idx > 0:
        prev = plan.hosts[idx - 1]
        link = plan.links[idx - 1]
        add_peer(lines, prev, link.preshared_key, host_allowed_ips(plan, idx, idx - 1), host.persistent_keepalive)
    if idx < len(plan.hosts) - 1:
        nxt = plan.hosts[idx + 1]
        link = plan.links[idx]
        add_peer(lines, nxt, link.preshared_key, host_allowed_ips(plan, idx, idx + 1), host.persistent_keepalive)
    if idx == 0 and plan.operator.enabled and plan.operator.public_key and plan.operator.wg_ip:
        lines.extend(
            [
                "",
                f"[Peer]",
                f"# {plan.operator.name} access peer",
                f"PublicKey = {plan.operator.public_key}",
                f"PresharedKey = {plan.operator.preshared_key}",
                f"AllowedIPs = {wg_cidr(plan, plan.operator.wg_ip)}",
            ]
        )
    return "\n".join(lines) + "\n"


def add_peer(lines: list[str], peer: Host, psk: str | None, allowed_ips: list[str], keepalive: int | None) -> None:
    lines.extend(
        [
            "",
            "[Peer]",
            f"# {peer.name}",
            f"PublicKey = {peer.wg_public_key}",
        ]
    )
    if psk:
        lines.append(f"PresharedKey = {psk}")
    lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")
    lines.append(f"Endpoint = {peer.endpoint}:{peer.wg_port}")
    if keepalive is not None:
        lines.append(f"PersistentKeepalive = {keepalive}")


def build_operator_conf(plan: Plan) -> str | None:
    op = plan.operator
    if not op.enabled or not op.wg_ip:
        return None
    first = plan.hosts[0]
    allowed = [wg_cidr(plan, host.wg_ip) for host in plan.hosts]
    lines = [
        "[Interface]",
        f"# {plan.name}: {op.name}",
        f"PrivateKey = {op.private_key}",
        f"Address = {wg_cidr(plan, op.wg_ip)}",
        "",
        "[Peer]",
        f"# {first.name}",
        f"PublicKey = {first.wg_public_key}",
        f"PresharedKey = {op.preshared_key}",
        f"AllowedIPs = {', '.join(allowed)}",
        f"Endpoint = {first.endpoint}:{first.wg_port}",
    ]
    if op.persistent_keepalive is not None:
        lines.append(f"PersistentKeepalive = {op.persistent_keepalive}")
    return "\n".join(lines) + "\n"


def build_sshd_snippet(plan: Plan, host: Host) -> str:
    forwarding = "yes" if plan.hardening.allow_tcp_forwarding else "no"
    return textwrap.dedent(
        f"""\
        # Managed by wg-deploy for {plan.name}. Do not edit in place.
        Port {host.ssh_port}
        PermitRootLogin prohibit-password
        AuthenticationMethods publickey
        PubkeyAuthentication yes
        PasswordAuthentication no
        KbdInteractiveAuthentication no
        ChallengeResponseAuthentication no
        PermitEmptyPasswords no
        AllowUsers root
        MaxAuthTries 3
        X11Forwarding no
        AllowAgentForwarding no
        AllowTcpForwarding {forwarding}
        ClientAliveInterval 300
        ClientAliveCountMax 2
        UseDNS no
        """
    )


def build_install_script(plan: Plan, host: Host) -> str:
    h = plan.hardening
    vars_block = textwrap.indent(
        "\n".join(
            [
                f"WG_IFACE={shlex.quote(plan.interface)}",
                f"WG_PORT={host.wg_port}",
                f"WG_IP={shlex.quote(host.wg_ip)}",
                f"SSH_PORT={host.ssh_port}",
                f"LOCK_PUBLIC_SSH={1 if h.lock_public_ssh else 0}",
                f"FIREWALL_MODE={shlex.quote(h.firewall)}",
                f"INSTALL_PACKAGES={1 if h.install_packages else 0}",
                f"ENABLE_FAIL2BAN={1 if h.fail2ban else 0}",
                f"DISABLE_IPV6={1 if h.disable_ipv6 else 0}",
            ]
        ),
        "        ",
    )
    return textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        set -euo pipefail

{vars_block}
        STAGE_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"

        log() {{ printf '[wg-deploy] %s\\n' "$*"; }}
        have() {{ command -v "$1" >/dev/null 2>&1; }}

        if [ "$(id -u)" != "0" ]; then
          echo "ERROR: run as root" >&2
          exit 1
        fi

        install_packages() {{
          [ "$INSTALL_PACKAGES" = "1" ] || return 0
          if have apt-get; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y wireguard iproute2 iptables openssh-server ca-certificates
            if [ "$FIREWALL_MODE" = "ufw" ]; then apt-get install -y ufw; fi
            if [ "$ENABLE_FAIL2BAN" = "1" ]; then apt-get install -y fail2ban; fi
          elif have dnf; then
            dnf install -y wireguard-tools iproute iptables openssh-server ca-certificates
            if [ "$FIREWALL_MODE" = "ufw" ]; then dnf install -y ufw || true; fi
            if [ "$ENABLE_FAIL2BAN" = "1" ]; then dnf install -y fail2ban || true; fi
          elif have yum; then
            yum install -y wireguard-tools iproute iptables openssh-server ca-certificates
            if [ "$FIREWALL_MODE" = "ufw" ]; then yum install -y ufw || true; fi
            if [ "$ENABLE_FAIL2BAN" = "1" ]; then yum install -y fail2ban || true; fi
          elif have apk; then
            apk add --no-cache wireguard-tools iproute2 iptables openssh-server ca-certificates
            if [ "$FIREWALL_MODE" = "ufw" ]; then apk add --no-cache ufw || true; fi
            if [ "$ENABLE_FAIL2BAN" = "1" ]; then apk add --no-cache fail2ban || true; fi
          elif have pacman; then
            pacman -Sy --noconfirm wireguard-tools iproute2 iptables openssh
            if [ "$FIREWALL_MODE" = "ufw" ]; then pacman -S --noconfirm ufw || true; fi
            if [ "$ENABLE_FAIL2BAN" = "1" ]; then pacman -S --noconfirm fail2ban || true; fi
          else
            echo "ERROR: unsupported package manager; install wireguard-tools, iproute2, iptables, openssh-server manually" >&2
            exit 1
          fi
        }}

        configure_sysctl() {{
          install -d -m 0755 /etc/sysctl.d
          cat >/etc/sysctl.d/99-wg-deploy.conf <<SYSCTL
        net.ipv4.ip_forward=1
        net.ipv4.conf.all.rp_filter=2
        net.ipv4.conf.default.rp_filter=2
        net.ipv4.tcp_syncookies=1
        net.ipv4.conf.all.accept_redirects=0
        net.ipv4.conf.default.accept_redirects=0
        net.ipv4.conf.all.send_redirects=0
        net.ipv4.conf.default.send_redirects=0
        net.ipv4.conf.all.accept_source_route=0
        net.ipv4.conf.default.accept_source_route=0
        SYSCTL
          if [ "$DISABLE_IPV6" = "1" ]; then
            cat >>/etc/sysctl.d/99-wg-deploy.conf <<SYSCTL
        net.ipv6.conf.all.disable_ipv6=1
        net.ipv6.conf.default.disable_ipv6=1
        SYSCTL
          else
            cat >>/etc/sysctl.d/99-wg-deploy.conf <<SYSCTL
        net.ipv6.conf.all.accept_redirects=0
        net.ipv6.conf.default.accept_redirects=0
        net.ipv6.conf.all.accept_source_route=0
        net.ipv6.conf.default.accept_source_route=0
        SYSCTL
          fi
          sysctl --system >/dev/null || sysctl -p /etc/sysctl.d/99-wg-deploy.conf >/dev/null || true
        }}

        install_wireguard() {{
          install -d -m 0700 /etc/wireguard
          install -m 0600 "$STAGE_DIR/{plan.interface}.conf" "/etc/wireguard/${{WG_IFACE}}.conf"
          if have systemctl; then
            systemctl enable "wg-quick@${{WG_IFACE}}" >/dev/null
            systemctl restart "wg-quick@${{WG_IFACE}}"
          else
            wg-quick down "$WG_IFACE" >/dev/null 2>&1 || true
            wg-quick up "$WG_IFACE"
          fi
        }}

        install_ssh() {{
          install -d -m 0700 /root/.ssh
          if [ -s "$STAGE_DIR/authorized_keys.root" ]; then
            install -m 0600 "$STAGE_DIR/authorized_keys.root" /root/.ssh/authorized_keys
          fi
          if [ ! -s /root/.ssh/authorized_keys ]; then
            echo "ERROR: /root/.ssh/authorized_keys is empty; refusing to enforce key-only root SSH" >&2
            exit 1
          fi

          install -d -m 0755 /etc/ssh/sshd_config.d
          install -m 0644 "$STAGE_DIR/99-wg-deploy.conf" /etc/ssh/sshd_config.d/99-wg-deploy.conf
          if have sshd; then sshd -t; fi
          if have systemctl; then
            systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd
          else
            service sshd restart >/dev/null 2>&1 || service ssh restart >/dev/null 2>&1 || true
          fi
        }}

        iptables_add_once() {{
          local table="$1"
          shift
          if [ "$table" = "filter" ]; then
            iptables -C "$@" >/dev/null 2>&1 || iptables -A "$@"
          else
            iptables -t "$table" -C "$@" >/dev/null 2>&1 || iptables -t "$table" -A "$@"
          fi
        }}

        configure_iptables_fallback() {{
          have iptables || return 0
          iptables_add_once filter INPUT -p udp --dport "$WG_PORT" -j ACCEPT
          iptables_add_once filter INPUT -i "$WG_IFACE" -j ACCEPT
          iptables_add_once filter FORWARD -i "$WG_IFACE" -o "$WG_IFACE" -j ACCEPT
          if [ "$LOCK_PUBLIC_SSH" = "1" ]; then
            iptables_add_once filter INPUT -p tcp --dport "$SSH_PORT" ! -i "$WG_IFACE" -j DROP
          else
            iptables_add_once filter INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
          fi
          if have netfilter-persistent; then netfilter-persistent save >/dev/null 2>&1 || true; fi
          if have iptables-save && [ -d /etc/iptables ]; then iptables-save >/etc/iptables/rules.v4 2>/dev/null || true; fi
        }}

        configure_firewall() {{
          case "$FIREWALL_MODE" in
            none)
              log "firewall changes disabled"
              ;;
            ufw)
              if have ufw; then
                ufw default deny incoming >/dev/null || true
                ufw default allow outgoing >/dev/null || true
                if [ -f /etc/default/ufw ]; then
                  sed -i.bak 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw || true
                fi
                ufw allow "$WG_PORT/udp" comment 'wg-deploy WireGuard' >/dev/null || true
                ufw allow in on "$WG_IFACE" comment 'wg-deploy tunnel ingress' >/dev/null || true
                ufw route allow in on "$WG_IFACE" out on "$WG_IFACE" comment 'wg-deploy chain forwarding' >/dev/null || true
                if [ "$LOCK_PUBLIC_SSH" = "0" ]; then
                  ufw allow "$SSH_PORT/tcp" comment 'wg-deploy public SSH fallback' >/dev/null || true
                fi
                ufw --force enable >/dev/null || true
              else
                log "ufw requested but unavailable; falling back to iptables"
                configure_iptables_fallback
              fi
              ;;
            iptables)
              configure_iptables_fallback
              ;;
            *)
              echo "ERROR: invalid FIREWALL_MODE=$FIREWALL_MODE" >&2
              exit 1
              ;;
          esac
        }}

        enable_fail2ban() {{
          [ "$ENABLE_FAIL2BAN" = "1" ] || return 0
          have fail2ban-client || return 0
          if have systemctl; then
            systemctl enable --now fail2ban >/dev/null 2>&1 || true
          fi
        }}

        log "installing packages"
        install_packages
        log "configuring sysctl"
        configure_sysctl
        log "installing WireGuard"
        install_wireguard
        log "configuring SSH"
        install_ssh
        log "configuring firewall"
        configure_firewall
        log "enabling fail2ban where available"
        enable_fail2ban

        log "complete: SSH should be reachable at root@${{WG_IP}} -p $SSH_PORT over $WG_IFACE"
        wg show "$WG_IFACE" || true
        """
    )


def render_plan(plan: Plan) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    global_dir = plan.out_root / f"{plan.name}-global"
    global_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "name": plan.name,
        "topology": "linear-chain",
        "interface": plan.interface,
        "wg_subnet": str(plan.wg_subnet),
        "hardening": plan.hardening.__dict__,
        "hosts": [],
        "links": [link.__dict__ for link in plan.links],
        "operator": {
            "enabled": plan.operator.enabled,
            "name": plan.operator.name,
            "wg_ip": plan.operator.wg_ip,
            "public_key": plan.operator.public_key,
        },
    }

    for host in plan.hosts:
        host_dir = plan.out_root / safe_name(host.public_ip)
        host_dir.mkdir(parents=True, exist_ok=True)
        wg_conf = build_host_wg_conf(plan, host)
        sshd = build_sshd_snippet(plan, host)
        install = build_install_script(plan, host)
        auth_keys = "\n".join(host.authorized_keys) + ("\n" if host.authorized_keys else "")

        write_secure(host_dir / f"{plan.interface}.conf", wg_conf, 0o600)
        write_secure(host_dir / "99-wg-deploy.conf", sshd, 0o644)
        write_secure(host_dir / "install.sh", install, 0o700)
        if auth_keys:
            write_secure(host_dir / "authorized_keys.root", auth_keys, 0o600)
        else:
            write_secure(host_dir / "authorized_keys.root", "", 0o600)

        host_manifest = {
            "name": host.name,
            "public_ip": host.public_ip,
            "endpoint": host.endpoint,
            "wg_ip": host.wg_ip,
            "wg_port": host.wg_port,
            "ssh_port": host.ssh_port,
            "bootstrap_ssh_port": host.bootstrap_ssh_port,
            "ssh_private_key": host.ssh_private_key,
            "wg_public_key": host.wg_public_key,
            "artifact_dir": str(host_dir),
            "ssh_after_lockdown": f"ssh -p {host.ssh_port} root@{host.wg_ip}",
        }
        write_secure(host_dir / "manifest.json", json.dumps(host_manifest, indent=2) + "\n", 0o600)
        manifest["hosts"].append(host_manifest)
        paths[host.name] = host_dir

    operator_conf = build_operator_conf(plan)
    if operator_conf:
        write_secure(global_dir / f"{plan.operator.name}.conf", operator_conf, 0o600)
        paths["operator_conf"] = global_dir / f"{plan.operator.name}.conf"

    write_secure(global_dir / "manifest.json", json.dumps(manifest, indent=2) + "\n", 0o600)
    write_secure(global_dir / "ssh_config", build_ssh_config(plan), 0o600)
    paths["global"] = global_dir
    return paths


def build_ssh_config(plan: Plan) -> str:
    lines = [
        f"# Managed by wg-deploy for {plan.name}",
        "# Bring up the operator WireGuard config first if public SSH is locked.",
        "",
    ]
    for host in plan.hosts:
        lines.extend(
            [
                f"Host {plan.name}-{host.name}",
                f"  HostName {host.wg_ip}",
                "  User root",
                f"  Port {host.ssh_port}",
                "  IdentitiesOnly yes",
            ]
        )
        if host.ssh_private_key:
            lines.append(f"  IdentityFile {host.ssh_private_key}")
        lines.append("")
    return "\n".join(lines)


def create_tarball(plan: Plan, host: Host, host_dir: Path) -> Path:
    tar_path = host_dir / f"{plan.name}-{host.name}.tgz"
    with tarfile.open(tar_path, "w:gz") as tf:
        for filename in [f"{plan.interface}.conf", "99-wg-deploy.conf", "authorized_keys.root", "install.sh"]:
            path = host_dir / filename
            tf.add(path, arcname=filename)
    os.chmod(tar_path, 0o600)
    return tar_path


def ssh_base_args(host: Host) -> list[str]:
    args = [
        "ssh",
        "-p",
        str(host.bootstrap_ssh_port),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    if host.ssh_private_key:
        args.extend(["-i", host.ssh_private_key])
    return args


def scp_base_args(host: Host) -> list[str]:
    args = [
        "scp",
        "-P",
        str(host.bootstrap_ssh_port),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    if host.ssh_private_key:
        args.extend(["-i", host.ssh_private_key])
    return args


def deploy_plan(plan: Plan, paths: dict[str, Path], *, assume_yes: bool = False) -> None:
    if not shutil.which("ssh") or not shutil.which("scp"):
        die("deploy mode requires local ssh and scp binaries")

    print_deploy_warning(plan)
    if not assume_yes:
        answer = input("Type 'deploy' to push configs and harden these VPS hosts: ").strip()
        if answer != "deploy":
            die("aborted by user", code=2)

    for host in plan.hosts:
        host_dir = paths[host.name]
        tarball = create_tarball(plan, host, host_dir)
        remote_tar = f"/tmp/{plan.name}-{host.name}.tgz"
        remote_dir = f"/root/.wg-deploy/{plan.name}-{host.name}"
        target = f"{host.ssh_user}@{host.public_ip}"

        log(f"[{host.name}] uploading staged deployment to {target}:{remote_tar}")
        scp_cmd = scp_base_args(host) + [str(tarball), f"{target}:{remote_tar}"]
        subprocess.run(scp_cmd, check=True)

        remote_cmd = (
            f"mkdir -p {shlex.quote(remote_dir)} && "
            f"tar -xzf {shlex.quote(remote_tar)} -C {shlex.quote(remote_dir)} && "
            f"bash {shlex.quote(remote_dir)}/install.sh"
        )
        log(f"[{host.name}] applying WireGuard, SSH, and hardening")
        ssh_cmd = ssh_base_args(host) + [target, remote_cmd]
        subprocess.run(ssh_cmd, check=True)


def print_deploy_warning(plan: Plan) -> None:
    rows = []
    for host in plan.hosts:
        rows.append(
            f"  {host.name:16} public={host.public_ip:20} wg={host.wg_ip:15} "
            f"ssh={host.ssh_port} bootstrap={host.bootstrap_ssh_port}"
        )
    log("")
    log("Deployment target summary:")
    for row in rows:
        log(row)
    if plan.hardening.lock_public_ssh:
        log("")
        log("Public SSH will be blocked by firewall policy after deployment.")
        if plan.operator.enabled:
            log("Use the generated operator config before relying on post-lockdown access.")
        else:
            log("No operator peer is configured. This is a lockout footgun with the safety off.")
    log("")


def cmd_sample(_: argparse.Namespace) -> None:
    sys.stdout.write(DEFAULT_SAMPLE)


def cmd_render(args: argparse.Namespace) -> None:
    data = load_inventory(args.inventory, parse_set(args.set))
    plan = normalize_inventory(data, args)
    paths = render_plan(plan)
    print_render_summary(plan, paths)


def cmd_deploy(args: argparse.Namespace) -> None:
    data = load_inventory(args.inventory, parse_set(args.set))
    plan = normalize_inventory(data, args)
    paths = render_plan(plan)
    print_render_summary(plan, paths)
    deploy_plan(plan, paths, assume_yes=args.yes)


def print_render_summary(plan: Plan, paths: dict[str, Path]) -> None:
    print(f"[+] Rendered {len(plan.hosts)} host(s) for chain {plan.name!r}")
    print(f"    Global: {paths['global']}")
    if "operator_conf" in paths:
        print(f"    Operator: {paths['operator_conf']}")
    for host in plan.hosts:
        print(f"    {host.name}: {paths[host.name]}  wg={host.wg_ip}  ssh=root@{host.wg_ip}:{host.ssh_port}")
    if plan.hardening.lock_public_ssh:
        print("[!] Public SSH lockdown is enabled. Post-deploy access is through WireGuard.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wg-deploy.py",
        description="Render/deploy a chained point-to-point-to-point WireGuard VPS tunnel with SSH hardening.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            examples:
              wg-deploy.py sample > chain.template.json
              wg-deploy.py render -i chain.template.json --set VPS1_IP=203.0.113.10 --set VPS2_IP=203.0.113.11 --set VPS3_IP=203.0.113.12 --set SSH_KEY=$HOME/.ssh/id_ed25519 --set AUTHORIZED_KEYS_FILE=$HOME/.ssh/authorized_keys
              wg-deploy.py deploy -i populated-chain.json --yes

            topology:
              hosts are chained in inventory order. For three hosts, vps1 only peers
              with vps2, vps2 peers with vps1 and vps3, and vps3 only peers with vps2.
            """
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sample = sub.add_parser("sample", help="print a templated sample inventory")
    sample.set_defaults(func=cmd_sample)

    for name, help_text in [
        ("render", "render local configs/scripts only"),
        ("deploy", "render then push/apply over root SSH"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("-i", "--inventory", required=True, help="JSON inventory file")
        p.add_argument("-o", "--out-dir", help="Output parent directory. Defaults to cwd.")
        p.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="Template replacement value")
        p.add_argument("--ssh-key", help="Override deployment SSH private key for all hosts")
        p.add_argument(
            "--allow-standard-ssh-port",
            action="store_true",
            help="Allow final ssh_port=22. Default refuses because the requested posture is non-standard SSH.",
        )
        p.add_argument(
            "--no-operator-ok",
            action="store_true",
            help="Permit lock_public_ssh=true without an operator peer. Dangerous unless you have another entrypoint.",
        )
        p.add_argument(
            "--rotate-keys",
            action="store_true",
            help="Generate fresh WireGuard keys instead of reusing previously rendered local artifacts.",
        )
        p.set_defaults(func=cmd_render if name == "render" else cmd_deploy)
        if name == "deploy":
            p.add_argument("-y", "--yes", action="store_true", help="Do not prompt before deployment")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
