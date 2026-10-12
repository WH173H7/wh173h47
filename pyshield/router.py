from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional


MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", re.IGNORECASE)
DEFAULT_TIMEOUT = 3.0


class RouterError(RuntimeError):
    """Raised when read-only router telemetry cannot be retrieved or parsed."""


@dataclass(frozen=True)
class RouterStations:
    gateway: str
    mac_addresses: List[str]
    station_count: int

    @property
    def normalized_macs(self) -> List[str]:
        return [mac.lower() for mac in self.mac_addresses]


def _validate_mac(value: str) -> Optional[str]:
    mac = value.strip().lower()
    if MAC_RE.fullmatch(mac):
        return mac
    return None


def parse_station_response(payload: str, gateway: str) -> RouterStations:
    """Parse the MF935 station response without trusting malformed values."""
    try:
        data = json.loads(payload)
    except (TypeError, ValueError) as exc:
        raise RouterError("router returned invalid JSON") from exc

    if not isinstance(data, dict):
        raise RouterError("router returned an unexpected response shape")

    raw_macs = data.get("station_mac", "")
    raw_count = data.get("sta_count", "0")

    if raw_macs is None:
        raw_macs = ""
    if not isinstance(raw_macs, str):
        raise RouterError("router station_mac field is invalid")

    macs: List[str] = []
    seen = set()
    for raw_mac in raw_macs.split(";"):
        mac = _validate_mac(raw_mac)
        if mac and mac not in seen:
            seen.add(mac)
            macs.append(mac)

    try:
        station_count = int(str(raw_count))
    except (TypeError, ValueError) as exc:
        raise RouterError("router sta_count field is invalid") from exc

    if station_count < 0:
        raise RouterError("router sta_count field is invalid")

    return RouterStations(
        gateway=gateway,
        mac_addresses=macs,
        station_count=station_count,
    )


def fetch_station_info(gateway: str, timeout: float = DEFAULT_TIMEOUT) -> RouterStations:
    """Read connected Wi-Fi station metadata from a ZTE MF935 gateway.

    This is intentionally read-only: it uses the router's GET command endpoint
    and does not submit configuration changes or credentials.
    """
    if not gateway:
        raise RouterError("router gateway is not available")

    query = urllib.parse.urlencode(
        {
            "multi_data": "1",
            "isTest": "false",
            "cmd": "station_mac,sta_count,m_sta_count",
        }
    )
    url = "http://{}/goform/goform_get_cmd_process?{}".format(gateway, query)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, text/plain, */*",
            "Referer": "http://{}/".format(gateway),
            "X-Requested-With": "XMLHttpRequest",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise RouterError("could not reach router at {}".format(gateway)) from exc

    return parse_station_response(payload, gateway)


def merge_router_macs(devices, router_stations: RouterStations):
    """Annotate ARP/local discoveries with router station evidence.

    Existing IP/MAC records are preserved. A router-reported MAC that has no
    matching ARP record is represented with an unknown IP instead of inventing
    an address.
    """
    # Imported lazily to avoid making router.py depend on discovery at import time.
    from .discovery import DiscoveredDevice

    items = list(devices)
    by_mac: Dict[str, int] = {}
    for index, device in enumerate(items):
        if device.mac:
            by_mac[device.mac.lower()] = index

    for mac in router_stations.normalized_macs:
        index = by_mac.get(mac)
        if index is not None:
            current = items[index]
            if current.source == "arp":
                items[index] = DiscoveredDevice(
                    current.ip, current.mac, "router+arp", current.hostname
                )
            continue

        items.append(DiscoveredDevice("unknown", mac, "router", None))

    return items
