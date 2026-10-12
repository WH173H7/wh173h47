from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Union


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_event(path: Union[str, Path], event: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": utc_now(), **event}
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")
