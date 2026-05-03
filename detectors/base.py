"""Shared detector infrastructure.

HitTracker is the in-memory sliding-window counter used by every detector
that has a "N hits in M seconds → block" rule.
"""

import time
from collections import defaultdict


class HitTracker:
    """Tracks hit counts per IP within a sliding time window."""

    def __init__(self, time_window=300):
        self.time_window = time_window
        self._hits = defaultdict(list)  # ip -> [timestamp, timestamp, ...]

    def add(self, ip):
        """Record a hit and return current count within window."""
        now = time.time()
        self._hits[ip].append(now)
        cutoff = now - self.time_window
        self._hits[ip] = [t for t in self._hits[ip] if t > cutoff]
        return len(self._hits[ip])

    def get_count(self, ip):
        """Get current hit count within window."""
        now = time.time()
        cutoff = now - self.time_window
        self._hits[ip] = [t for t in self._hits[ip] if t > cutoff]
        return len(self._hits[ip])

    def cleanup(self):
        """Remove stale entries."""
        now = time.time()
        cutoff = now - self.time_window
        stale = [ip for ip, hits in self._hits.items() if not hits or hits[-1] < cutoff]
        for ip in stale:
            del self._hits[ip]
