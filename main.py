import argparse
import json
import time
from pathlib import Path

from pyshield.detector import BurstDetector
from pyshield.discovery import DiscoveryError, discover
from pyshield.firewall import plan_block
from pyshield.monitor import scan_once
from pyshield.router import RouterError, fetch_station_info, merge_router_macs
from pyshield.rules import evaluate, load_rules

ROOT = Path(__file__).resolve().parent
RULES = ROOT / "config" / "rules.json"
LOG = ROOT / "logs" / "events.jsonl"


def cmd_rules():
    rules = load_rules(str(RULES))
    print("NAME | ACTION | IP | PORT | PROTOCOL")
    print("-" * 60)
    for r in rules:
        print(f"{r.name} | {r.action} | {r.ip or '-'} | {r.port or '-'} | {r.protocol or '-'}")


def cmd_check(ip, port, protocol):
    action, rule = evaluate(load_rules(str(RULES)), ip, port, protocol)
    print(json.dumps({"remote_ip": ip, "remote_port": port, "protocol": protocol, "decision": action, "rule": rule}, indent=2))


def cmd_monitor(interval, count):
    rules = load_rules(str(RULES))
    detector = BurstDetector()
    for i in range(count):
        events = scan_once(rules, str(LOG), detector)
        remote = [e for e in events if e["remote_ip"]]
        print(f"Scan {i+1}/{count}: {len(events)} connections observed, {len(remote)} with remote endpoints.")
        for e in remote[:10]:
            flag = " SUSPICIOUS-BURST" if e["suspicious_burst"] else ""
            print(f"  {e['local_ip']}:{e['local_port']} -> {e['remote_ip']}:{e['remote_port']}  {e['action']} ({e['rule']}){flag}")
        if i + 1 < count:
            time.sleep(interval)


def cmd_discover(probe=False, router=False):
    try:
        info, devices = discover(probe=probe)
    except DiscoveryError as exc:
        print(f"Discovery error: {exc}")
        return 1

    router_stations = None
    if router:
        if not info.gateway:
            print("Router telemetry: unavailable (no gateway detected)")
        else:
            try:
                router_stations = fetch_station_info(info.gateway)
                devices = merge_router_macs(devices, router_stations)
                print(f"Router telemetry: MF935 station list ({len(router_stations.normalized_macs)} reported)")
            except RouterError as exc:
                print(f"Router telemetry: unavailable ({exc})")

    print("WH173H47 NETWORK DISCOVERY")
    print(f"Interface: {info.interface}")
    print(f"Local IP:  {info.local_ip}")
    print(f"Gateway:   {info.gateway or '-'}")
    print(f"Subnet:    {info.subnet}")
    print("\nDEVICES")
    print("IP              MAC                SOURCE   HOSTNAME")
    print("-" * 72)
    for device in devices:
        print(
            f"{device.ip:<15} "
            f"{(device.mac or '-'):18} "
            f"{device.source:<8} "
            f"{device.hostname or '-'}"
        )
    print(f"\nTotal devices: {len(devices)}")
    if router_stations is not None:
        print(f"Router-reported stations: {len(router_stations.normalized_macs)}")
    return 0


def cmd_demo():
    rules = load_rules(str(RULES))
    samples = [
        ("127.0.0.1", 22, "TCP"),
        ("192.168.1.50", 80, "TCP"),
        ("10.0.0.10", 443, "TCP"),
        ("203.0.113.25", 443, "TCP"),
    ]
    print("SAFE RULE-ENGINE DEMO (no system firewall changes are made)\n")
    for ip, port, proto in samples:
        action, rule = evaluate(rules, ip, port, proto)
        print(f"{ip}:{port}/{proto} -> {action} via {rule}")


def cmd_block_preview(ip):
    plan = plan_block(ip)
    print(json.dumps(plan.__dict__, indent=2))


def main():
    parser = argparse.ArgumentParser(description="PyShield - Network Security and Defensive Monitoring System")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("rules", help="List configured rules")
    p = sub.add_parser("discover", help="Discover devices on the local private network")
    p.add_argument("--probe", action="store_true", help="Ping hosts in the detected subnet before reading ARP")
    p.add_argument("--router", action="store_true", help="Read connected-station metadata from a supported local router")
    p = sub.add_parser("check", help="Evaluate one connection against rules")
    p.add_argument("ip"); p.add_argument("port", type=int); p.add_argument("protocol", nargs="?", default="TCP")
    p = sub.add_parser("monitor", help="Observe local network connections")
    p.add_argument("--interval", type=float, default=3); p.add_argument("--count", type=int, default=3)
    sub.add_parser("demo", help="Run a safe rule-engine demonstration")
    p = sub.add_parser("block-preview", help="Show OS firewall command preview without applying it")
    p.add_argument("ip")
    args = parser.parse_args()
    if args.command == "rules": cmd_rules()
    elif args.command == "discover": return cmd_discover(args.probe, args.router)
    elif args.command == "check": cmd_check(args.ip, args.port, args.protocol)
    elif args.command == "monitor": cmd_monitor(args.interval, args.count)
    elif args.command == "demo": cmd_demo()
    elif args.command == "block-preview": cmd_block_preview(args.ip)


if __name__ == "__main__":
    main()
