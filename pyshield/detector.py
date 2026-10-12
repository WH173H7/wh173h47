from collections import defaultdict, deque
from time import monotonic
from typing import Deque, DefaultDict, Dict, Optional


class BurstDetector:
    """Detect bursts of newly observed connections."""

    def __init__(self, threshold=20, window_seconds=10, seen_ttl=30):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.seen_ttl = seen_ttl
        self.events = defaultdict(deque)
        self.seen = {}

    def observe(self, source: str, fingerprint: Optional[str] = None) -> bool:
        now = monotonic()
        key = fingerprint or source

        stale = [
            k for k, ts in self.seen.items()
            if now - ts > self.seen_ttl
        ]

        for k in stale:
            del self.seen[k]

        # Existing connection: do not count it again.
        if key in self.seen:
            self.seen[key] = now
            return False

        # New connection.
        self.seen[key] = now

        q = self.events[source]
        q.append(now)

        while q and now - q[0] > self.window_seconds:
            q.popleft()

        return len(q) >= self.threshold
