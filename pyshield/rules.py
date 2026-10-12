from __future__ import annotations
import ipaddress
from dataclasses import dataclass
from typing import Optional, List, Tuple
from typing import Any


@dataclass(frozen=True)
class Rule:
    name: str
    action: str
    ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    description: str = ""

    def matches(self, remote_ip: Optional[str], remote_port: Optional[int], protocol: Optional[str]) -> bool:
        if self.ip and remote_ip:
            try:
                if "/" in self.ip:
                    if ipaddress.ip_address(remote_ip) not in ipaddress.ip_network(self.ip, strict=False):
                        return False
                elif ipaddress.ip_address(remote_ip) != ipaddress.ip_address(self.ip):
                    return False
            except ValueError:
                return False
        elif self.ip and not remote_ip:
            return False

        if self.port is not None and remote_port != self.port:
            return False
        if self.protocol and protocol and self.protocol.lower() != protocol.lower():
            return False
        if self.protocol and not protocol:
            return False
        return True


def load_rules(path: str) -> list[Rule]:
    import json
    with open(path, "r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
    rules = []
    for item in data.get("rules", []):
        action = str(item.get("action", "LOG")).upper()
        if action not in {"ALLOW", "BLOCK", "LOG"}:
            raise ValueError(f"Unsupported action: {action}")
        rules.append(Rule(
            name=str(item["name"]),
            action=action,
            ip=item.get("ip"),
            port=int(item["port"]) if item.get("port") is not None else None,
            protocol=item.get("protocol"),
            description=str(item.get("description", "")),
        ))
    return rules


def evaluate(rules: List[Rule], remote_ip: Optional[str], remote_port: Optional[int], protocol: Optional[str]) -> Tuple[str, str]:
    for rule in rules:
        if rule.matches(remote_ip, remote_port, protocol):
            return rule.action, rule.name
    return "ALLOW", "default-allow"
