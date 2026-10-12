from __future__ import annotations
import platform
from dataclasses import dataclass


@dataclass
class EnforcementPlan:
    platform: str
    supported: bool
    command_preview: str
    note: str


def plan_block(ip: str) -> EnforcementPlan:
    system = platform.system()
    if system == "Linux":
        cmd = f"sudo nft add rule inet pyshield input ip saddr {ip} drop"
        note = "Preview only. Review and apply through the host's approved firewall change process."
        return EnforcementPlan(system, True, cmd, note)
    if system == "Windows":
        cmd = f'netsh advfirewall firewall add rule name="PyShield-{ip}" dir=in action=block remoteip={ip}'
        note = "Preview only. Requires Administrator privileges and change approval."
        return EnforcementPlan(system, True, cmd, note)
    if system == "Darwin":
        cmd = f"# pfctl rule preview: block drop quick from {ip} to any"
        note = "Preview only. macOS pf rules should be managed carefully and tested in an isolated environment."
        return EnforcementPlan(system, True, cmd, note)
    return EnforcementPlan(system, False, "", "No built-in enforcement adapter for this operating system.")
