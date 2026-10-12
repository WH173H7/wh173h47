import socket
from typing import Iterable, List, Optional, Dict, Any

import psutil

from .detector import BurstDetector
from .logger import log_event
from .rules import Rule, evaluate


def protocol_name(kind: int) -> str:
    return {
        socket.SOCK_STREAM: "TCP",
        socket.SOCK_DGRAM: "UDP"
    }.get(kind, str(kind))


def iter_connections() -> Iterable[dict]:
    for c in psutil.net_connections(kind="inet"):
        laddr = getattr(c, "laddr", None)
        raddr = getattr(c, "raddr", None)

        remote_ip = getattr(raddr, "ip", None) if raddr else None
        remote_port = getattr(raddr, "port", None) if raddr else None
        local_ip = getattr(laddr, "ip", None) if laddr else None
        local_port = getattr(laddr, "port", None) if laddr else None

        yield {
            "pid": c.pid,
            "status": c.status,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
        }


def connection_fingerprint(conn: Dict[str, Any]) -> str:
    return "|".join(
        str(conn.get(k) or "-")
        for k in (
            "pid",
            "local_ip",
            "local_port",
            "remote_ip",
            "remote_port",
            "status",
        )
    )


def scan_once(
    rules: List[Rule],
    log_path: str,
    detector: Optional[BurstDetector] = None
) -> List[dict]:

    results = []
    detector = detector or BurstDetector()

    for conn in iter_connections():
        action, rule = evaluate(
            rules,
            conn["remote_ip"],
            conn["remote_port"],
            None
        )

        fingerprint = connection_fingerprint(conn)

        suspicious = bool(
            conn["remote_ip"]
            and detector.observe(
                conn["remote_ip"],
                fingerprint
            )
        )

        event = {
            **conn,
            "connection_fingerprint": fingerprint,
            "action": action,
            "rule": rule,
            "suspicious_burst": suspicious,
        }

        results.append(event)

        log_event(
            log_path,
            {
                "event": "connection_observed",
                **event
            }
        )

    return results
