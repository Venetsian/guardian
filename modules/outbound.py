"""Outbound send correlation (v1.7.15).

The payload-phase half of abuse corroboration. `modules/corroboration.py`
explains why the reconnaissance-phase signals shipped first; this module
supplies the harder proof that arrives later — what the account actually SENT.

Guardian had no outbound visibility at all before this. `MailDetector` parsed
four line shapes, all of them authentication, and discarded Postfix delivery
lines entirely.

THE QUEUE ID IS THE JOIN KEY, and the correlation is mandatory rather than an
optimisation. Postfix logs two lines that matter, seconds apart and interleaved
with everything else on a busy host:

    postfix/smtps/smtpd[65793]: 0F5B86C403F7: client=host[198.51.100.20],
        sasl_method=PLAIN, sasl_username=erin@example.com

    postfix/qmgr[4031830]: 4BAFB6C403F3: from=<sender>, size=80933,
        nrcpt=1 (queue active)

Only the first says who sent it. Only the second says how big it was and how
many recipients it had. And critically, **qmgr logs inbound and outbound mail
identically** — on the reference host most sampled qmgr lines were inbound
bounces and spam. Counting qmgr alone would measure how much mail the server
RECEIVES for an account and report it as sending. So a queue ID is ours going
out only if it was first seen on an authenticated smtpd line.

This also picks up PHP-originated mail: web.maiahost.com relays through the
mail host with a sasl_username, so a compromised website's sending is visible
through exactly the same path.

Python 3.6 compatible.
"""

import re
import time
import logging

from collections import OrderedDict

logger = logging.getLogger('wp-guardian.outbound')


# `smtpd[65793]: 0F5B86C403F7: client=...`
#
# Anchored on `: client=` because that is the only smtpd line carrying the
# sasl_username, and anchoring loosely would pick up queue IDs off cleanup and
# bounce lines that say nothing about who authenticated.
SUBMISSION_QID_RE = re.compile(r'\]:\s*([0-9A-Za-z]{4,24}):\s*client=')

# `qmgr[4031830]: 4BAFB6C403F3: from=<x>, size=80933, nrcpt=1 (queue active)`
#
# qmgr's other line for a message is `<QID>: removed`, which carries no nrcpt
# and therefore cannot match — one row per message, by construction.
QMGR_RE = re.compile(
    r'\]:\s*([0-9A-Za-z]{4,24}):\s*from=<([^>]*)>,\s*size=(\d+),\s*nrcpt=(\d+)'
)

# Postfix's placeholder when no queue file was ever created (rejects, most
# NOQUEUE lines). It is alphanumeric and sits in the queue-ID position, so
# without this it would be treated as one ID shared by every rejected message.
NOT_A_QUEUE_ID = frozenset(['NOQUEUE'])


def parse_submission(line):
    """Queue ID from an authenticated smtpd line, or ''.

    The caller has already established that the line is an auth success and
    holds the username and IP — this only recovers the ID the existing parser
    discarded.
    """
    match = SUBMISSION_QID_RE.search(line)
    if not match:
        return ''
    qid = match.group(1)
    if qid in NOT_A_QUEUE_ID:
        return ''
    return qid


def parse_qmgr(line):
    """(queue_id, size_bytes, nrcpt) from a qmgr active line, or None."""
    match = QMGR_RE.search(line)
    if not match:
        return None
    qid = match.group(1)
    if qid in NOT_A_QUEUE_ID:
        return None
    try:
        return (qid, int(match.group(3)), int(match.group(4)))
    except (TypeError, ValueError):
        return None


class OutboundTracker:
    """Correlates authenticated submissions with their queue records.

    Single-threaded by construction: only the mail tailer thread touches the
    pending map. The database writes go through the shared connection like
    every other detector's.
    """

    def __init__(self, config, db):
        self.db = db

        self.enabled = config.getboolean(
            'compromise_detection', 'outbound_monitoring', fallback=True
        )

        # How long a submission waits for its qmgr line. The two arrive
        # seconds apart normally; a few minutes covers a host under load
        # without letting the map become a memory leak on a misconfigured
        # Postfix that never logs the second line.
        self.queue_ttl = config.getint(
            'compromise_detection', 'outbound_queue_ttl', fallback=300
        )

        # Hard cap regardless of TTL. Bounded memory beats complete data:
        # dropping the oldest pending entries costs a few send records, which
        # fails toward NO SIGNAL.
        self.max_pending = config.getint(
            'compromise_detection', 'outbound_max_pending', fallback=10000
        )

        self._pending = OrderedDict()   # qid -> (username, ip, seen_at)
        self._last_prune = 0.0
        self._last_cap_warning = 0.0

        self.stats = {
            'submissions': 0,   # authenticated smtpd lines with a queue ID
            'recorded': 0,      # matched pairs written to the database
            'unmatched': 0,     # qmgr lines with no pending submission (inbound)
            'expired': 0,       # submissions whose qmgr line never arrived
            'dropped': 0,       # evicted by the size cap — diagnostic, not normal
            'errors': 0,
        }

    # ------------------------------------------------------------------
    # Feeding — called from MailDetector.process_line
    # ------------------------------------------------------------------
    def note_submission(self, queue_id, username, ip, now=None):
        """Remember that this queue ID belongs to an authenticated sender."""
        if not self.enabled or not queue_id or not username:
            return
        now = time.time() if now is None else now
        try:
            self._pending[queue_id] = (username, ip or '', now)
            # Re-inserting an existing key keeps its original position in an
            # OrderedDict, which would defeat the oldest-first eviction below.
            self._pending.move_to_end(queue_id)
            self.stats['submissions'] += 1
            self._prune(now)
        except Exception as e:
            self.stats['errors'] += 1
            logger.debug("note_submission failed: {e}".format(e=e))

    def note_delivery(self, queue_id, size_bytes, nrcpt, now=None):
        """Match a qmgr record to a pending submission and record the send.

        Returns True if a row was written. An unmatched queue ID is inbound
        mail — silently ignored, which is the entire point of the join.
        """
        if not self.enabled or not queue_id:
            return False
        now = time.time() if now is None else now

        entry = self._pending.pop(queue_id, None)
        if entry is None:
            self.stats['unmatched'] += 1
            return False

        username, ip, seen_at = entry

        # Expired between arrival and now. Treat as unmatched rather than
        # recording against a queue ID that may have been reused.
        if self.queue_ttl > 0 and (now - seen_at) > self.queue_ttl:
            self.stats['expired'] += 1
            return False

        try:
            self.db.record_outbound(
                username=username, ip=ip, nrcpt=nrcpt,
                size_bytes=size_bytes, queue_id=queue_id,
                timestamp=int(now),
            )
        except Exception as e:
            # A failed insert costs one send record. It must never propagate:
            # this runs inside the mail tailer, and taking that thread down
            # would stop brute-force blocking too.
            self.stats['errors'] += 1
            logger.error("Failed to record outbound for {u}: {e}".format(
                u=username, e=e))
            return False

        self.stats['recorded'] += 1
        return True

    # ------------------------------------------------------------------
    def _prune(self, now):
        """Drop expired and overflowing pending entries.

        Time-based pruning runs at most once a minute — the map is only
        touched by one thread and a full scan on every submission would be
        wasted work on a busy relay.
        """
        if len(self._pending) > self.max_pending:
            overflow = len(self._pending) - self.max_pending
            for _ in range(overflow):
                try:
                    self._pending.popitem(last=False)
                    self.stats['dropped'] += 1
                except KeyError:
                    break
            # Once at the cap every further submission overflows, so an
            # unthrottled warning here would be one log line per outbound
            # message for as long as the condition lasts.
            if (now - self._last_cap_warning) > 300:
                self._last_cap_warning = now
                logger.warning(
                    "Outbound pending map is at its cap ({n}) — dropping the "
                    "oldest submissions ({d} total). Postfix may not be "
                    "logging qmgr lines for this queue.".format(
                        n=self.max_pending, d=self.stats['dropped'])
                )

        if self.queue_ttl <= 0 or (now - self._last_prune) < 60:
            return
        self._last_prune = now

        cutoff = now - self.queue_ttl
        # Insertion order is time order, so stop at the first live entry.
        while self._pending:
            qid = next(iter(self._pending))
            if self._pending[qid][2] >= cutoff:
                break
            del self._pending[qid]
            self.stats['expired'] += 1

    def pending_count(self):
        return len(self._pending)
