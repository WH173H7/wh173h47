from dataclasses import dataclass
from typing import List, Optional
import ipaddress


# Ports that deserve review because they are commonly exposed
# administrative or legacy services.
# Their presence alone is NOT proof of malicious activity.
REVIEW_PORTS = {
    21,    # FTP
    23,    # Telnet
    139,   # NetBIOS
    445,   # SMB
    2323,  # Alternate Telnet
    3389,  # RDP
    5900,  # VNC
}


@dataclass(frozen=True)
class ThreatAssessment:
    level: str
    score: int
    reasons: List[str]


def assess_connection(
    remote_ip: Optional[str],
    remote_port: Optional[int],
    action: str,
    suspicious_burst: bool = False,
) -> ThreatAssessment:

    score = 0
    reasons: List[str] = []

    if action.upper() == "BLOCK":
        score += 100
        reasons.append("Connection matched a BLOCK rule")

    if suspicious_burst:
        score += 60
        reasons.append("Connection pattern matched the burst detector")

    if remote_port in REVIEW_PORTS:
        score += 25
        reasons.append(
            "Destination port is a commonly exposed administrative "
            "or legacy service port"
        )

    if remote_ip:
        try:
            address = ipaddress.ip_address(remote_ip)

            # Local and private addresses are normal in many environments.
            if address.is_loopback or address.is_link_local or address.is_private:
                pass

        except ValueError:
            score += 10
            reasons.append("Remote address could not be parsed as an IP address")

    if score >= 100:
        level = "HIGH"
    elif score >= 60:
        level = "MEDIUM"
    elif score >= 25:
        level = "LOW"
    else:
        level = "INFO"

    return ThreatAssessment(
        level=level,
        score=score,
        reasons=reasons,
    )
