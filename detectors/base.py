"""Shared detector infrastructure.

HitTracker is the in-memory sliding-window counter used by every detector
that has a "N hits in M seconds → block" rule.
"""

import logging
import time
from collections import defaultdict

# How far back an IP may have last authenticated as a username and still count
# as that account's own client. Generous on purpose: a mailbox Guardian
# disabled cannot produce fresh successes, so the evidence is always stale.
GUARDIAN_DISABLED_CLIENT_LOOKBACK = 30 * 86400


def is_guardian_disabled_client(db, ip, username, service, logger_name):
    """True when this auth failure is Guardian's own remediation echoing back.

    When a mailbox is disabled after a compromise event, Dovecot's
    password_query filters on `AND enabled = 1`, so the account owner's mail
    client turns into a failed-auth generator on every retry. Left alone, the
    brute-force detector then blocks — and escalates — the victim's own IP.
    The remediation manufactures the evidence for the next punishment, which
    is exactly how a false positive became a permanent ban.

    Deliberately narrow. Suppression requires BOTH:
      1. Guardian currently has that mailbox disabled, and
      2. this IP has previously authenticated successfully as that username.

    Requirement 2 matters: without it, knowing the name of a disabled mailbox
    would buy an attacker unlimited free attempts from anywhere.
    """
    if not username:
        return False

    try:
        if not db.is_mailbox_disabled_by_guardian(username):
            return False
        if not db.has_auth_history(ip, username, GUARDIAN_DISABLED_CLIENT_LOOKBACK):
            return False
    except Exception as e:
        logging.getLogger(logger_name).error(
            "Guardian-disabled mailbox check failed for {u}: {e}".format(u=username, e=e)
        )
        return False

    logging.getLogger(logger_name).warning(
        "{ip} failing {svc} auth as {u} — mailbox is disabled BY GUARDIAN and this "
        "IP is a known client of that account. Not blocking (our own remediation "
        "is causing these failures).".format(ip=ip, svc=service.upper(), u=username)
    )
    return True


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


def cleanup_trackers(*owners):
    """Prune every HitTracker held by these objects.

    add() and get_count() trim an IP's timestamp list but never drop the key,
    so without this every IP the daemon has ever seen keeps a dict entry for
    the life of the process. The 5-minute tick in wp-guardian.py that was
    meant to do this had an empty body, so none of the eleven trackers across
    the five detectors was ever swept.

    It matters more since v1.7.16: WebDetector.hits_success records every
    2xx/3xx response, so the web trackers now grow with ordinary visitors
    rather than only with attack traffic.
    """
    for owner in owners:
        if owner is None:
            continue
        for value in vars(owner).values():
            if isinstance(value, HitTracker):
                value.cleanup()
