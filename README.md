# PyShield

**Network Security and Defensive Monitoring System**

PyShield is a Python-based defensive security project for controlled training and demonstration. It combines a configurable rule engine, local connection monitoring, event logging, simple repeated-connection detection, and operating-system firewall command previews.

## Safety model

- The default mode is **observe / simulate**.
- The project does **not** modify the host firewall automatically.
- `demo` exercises the rule engine using documentation-only IP space.
- `block-preview` prints a possible OS firewall command without executing it.
- Real enforcement should only be enabled later under an approved, isolated test environment.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py rules
python main.py demo
python main.py check 203.0.113.25 443 TCP
python main.py monitor --count 3 --interval 3
python main.py block-preview 203.0.113.25
```

Logs are written to `logs/events.jsonl`.

## Project modules

- `pyshield/rules.py` — configurable rule matching and decisions.
- `pyshield/monitor.py` — local connection observation using psutil.
- `pyshield/detector.py` — basic repeated-connection detection.
- `pyshield/logger.py` — structured JSONL event logging.
- `pyshield/firewall.py` — platform-aware enforcement previews.
- `main.py` — command-line interface.

## SIWES demonstration flow

1. Show configured rules.
2. Run the safe rule-engine demo.
3. Run a live local monitoring scan.
4. Inspect `logs/events.jsonl`.
5. Explain how enforcement adapters would connect to the host firewall in an approved lab.
6. Document tests and observations.

## Important note for the report

The project should be described as a **Network Security and Defensive Monitoring System** unless and until real OS-level enforcement has been safely implemented and tested. This avoids claiming that the prototype is a full kernel-level firewall when the current version is primarily a monitoring and rule-evaluation system.
