import json
from pathlib import Path

from pyshield.rules import evaluate, load_rules


def test_block_rule():
    rules = load_rules(str(Path(__file__).parents[1] / "config" / "rules.json"))
    assert evaluate(rules, "203.0.113.25", 443, "TCP")[0] == "BLOCK"


def test_ssh_log_rule():
    rules = load_rules(str(Path(__file__).parents[1] / "config" / "rules.json"))
    assert evaluate(rules, "192.168.1.5", 22, "TCP")[0] == "LOG"


def test_default_allow():
    rules = load_rules(str(Path(__file__).parents[1] / "config" / "rules.json"))
    assert evaluate(rules, "192.168.1.5", 443, "TCP")[0] == "ALLOW"
