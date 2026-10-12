from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


MAX_PROBE_HOSTS = 256
_MAC_RE = re.compile(r"(?i)([0-9a-f]{2}(?::[0-9a-f]{2}){5})")
_IP_RE = re.compile(r"inet\s+(\d+(?:\.\d+){3})")
_NETMASK_RE = re.compile(r"netmask\s+(0x[0-9a-fA-F]+|\d+(?:\.\d+){3})")


@dataclass(frozen=True)
class NetworkInfo:
    interface: str
    local_ip: str
    gateway: Optional[str]
    subnet: str
    local_mac: Optional[str] = None


@dataclass(frozen=True)
class DiscoveredDevice:
    ip: str
    mac: Optional[str]
    source: str
    hostname: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        return asdict(self)


class DiscoveryError(RuntimeError):
    """Raised when local network discovery cannot determine a safe scope."""


def _run(command: Sequence[str], timeout: float = 3.0) -> str:
    try:
        result = subprocess.run(
            list(command),
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DiscoveryError("command failed: {}".format(" ".join(command))) from exc
    return result.stdout


def parse_default_route(output: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (gateway, interface) from `route -n get default` output."""
    gateway = None
    interface = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            gateway = line.split(":", 1)[1].strip() or None
        elif line.startswith("interface:"):
            interface = line.split(":", 1)[1].strip() or None
    return gateway, interface


def _netmask_to_prefix(netmask: str) -> int:
    if netmask.lower().startswith("0x"):
        value = int(netmask, 16)
        octets = [(value >> shift) & 0xFF for shift in (24, 16, 8, 0)]
        return ipaddress.IPv4Network("0.0.0.0/" + ".".join(map(str, octets)), strict=False).prefixlen
    return ipaddress.IPv4Network("0.0.0.0/" + netmask, strict=False).prefixlen


def parse_interface_ipv4(output: str) -> Tuple[str, str]:
    """Return (IPv4 address, netmask) from `ifconfig <iface>` output."""
    ip_match = _IP_RE.search(output)
    mask_match = _NETMASK_RE.search(output)
    if not ip_match or not mask_match:
        raise DiscoveryError("could not determine IPv4 address/netmask")
    return ip_match.group(1), mask_match.group(1)


def parse_interface_mac(output: str) -> Optional[str]:
    """Return the interface's hardware MAC from `ifconfig` output."""
    match = re.search(r"(?im)^\s*ether\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", output)
    return match.group(1).lower() if match else None


def get_network_info() -> NetworkInfo:
    gateway, interface = parse_default_route(_run(["route", "-n", "get", "default"]))
    if not interface:
        raise DiscoveryError("no default network interface found")

    interface_output = _run(["ifconfig", interface])
    local_ip, netmask = parse_interface_ipv4(interface_output)
    local_mac = parse_interface_mac(interface_output)
    address = ipaddress.ip_address(local_ip)
    if address.version != 4 or not address.is_private:
        raise DiscoveryError("refusing discovery outside a private IPv4 network")

    prefix = _netmask_to_prefix(netmask)
    subnet = ipaddress.ip_network("{}/{}".format(local_ip, prefix), strict=False)
    if not subnet.is_private:
        raise DiscoveryError("refusing discovery outside a private IPv4 subnet")

    return NetworkInfo(
        interface=interface,
        local_ip=local_ip,
        gateway=gateway,
        subnet=str(subnet),
        local_mac=local_mac,
    )


def parse_arp_table(output: str, interface: Optional[str] = None) -> List[DiscoveredDevice]:
    """Parse macOS `arp -an` output, ignoring incomplete entries."""
    devices: List[DiscoveredDevice] = []
    seen = set()

    for line in output.splitlines():
        match = re.search(r"\(([^)]+)\)\s+at\s+([^\s]+)(?:\s+on\s+(\S+))?", line)
        if not match:
            continue

        ip_text, mac_text, entry_interface = match.groups()
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        if ip.version != 4 or not ip.is_private:
            continue

        mac_match = _MAC_RE.fullmatch(mac_text)
        if not mac_match:
            continue

        if interface and entry_interface and entry_interface != interface:
            continue

        key = (str(ip), mac_match.group(1).lower())
        if key in seen:
            continue
        seen.add(key)
        devices.append(
            DiscoveredDevice(
                ip=str(ip),
                mac=mac_match.group(1).lower(),
                source="arp",
            )
        )

    return devices


def _resolve_hostname(ip: str) -> Optional[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        if host and host != ip:
            return host
    except (OSError, socket.herror, socket.gaierror):
        pass
    return None


def add_hostnames(devices: Iterable[DiscoveredDevice], timeout: float = 1.0) -> List[DiscoveredDevice]:
    """Best-effort local reverse-DNS names without making them required."""
    items = list(devices)
    if not items:
        return items

    with ThreadPoolExecutor(max_workers=min(8, len(items))) as executor:
        futures = {executor.submit(_resolve_hostname, d.ip): d for d in items}
        names: Dict[str, Optional[str]] = {}
        for future in as_completed(futures):
            device = futures[future]
            try:
                names[device.ip] = future.result(timeout=timeout)
            except Exception:
                names[device.ip] = None

    return [DiscoveredDevice(d.ip, d.mac, d.source, names.get(d.ip)) for d in items]


def _probe_host(ip: str, timeout_ms: int = 300) -> bool:
    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_ms), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1.0, timeout_ms / 1000.0 + 0.5),
            check=False,
        )
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def probe_subnet(subnet: str, local_ip: str, gateway: Optional[str]) -> int:
    """Ping hosts only inside the detected private subnet, then refresh ARP."""
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(host) for host in network.hosts() if str(host) != local_ip]
    if gateway:
        hosts = [host for host in hosts if host != gateway]

    if len(hosts) > MAX_PROBE_HOSTS:
        raise DiscoveryError(
            "refusing probe of {} hosts; maximum is {}".format(len(hosts), MAX_PROBE_HOSTS)
        )

    with ThreadPoolExecutor(max_workers=min(32, max(1, len(hosts)))) as executor:
        futures = [executor.submit(_probe_host, host) for host in hosts]
        return sum(1 for future in as_completed(futures) if future.result())


def discover(probe: bool = False) -> Tuple[NetworkInfo, List[DiscoveredDevice]]:
    info = get_network_info()

    if probe:
        probe_subnet(info.subnet, info.local_ip, info.gateway)

    arp_output = _run(["arp", "-an"], timeout=5.0)
    arp_devices = parse_arp_table(arp_output, interface=info.interface)

    # Ignore the subnet broadcast pseudo-device; it is not a connected host.
    subnet_obj = ipaddress.ip_network(info.subnet, strict=False)
    broadcast_ip = str(subnet_obj.broadcast_address)
    devices = [d for d in arp_devices if d.ip != broadcast_ip]

    local = DiscoveredDevice(info.local_ip, info.local_mac, "local", socket.gethostname())
    by_ip: Dict[str, DiscoveredDevice] = {d.ip: d for d in devices}
    by_ip[local.ip] = local

    if info.gateway:
        by_ip.setdefault(info.gateway, DiscoveredDevice(info.gateway, None, "gateway"))

    ordered = sorted(by_ip.values(), key=lambda d: ipaddress.ip_address(d.ip))
    return info, add_hostnames(ordered)
