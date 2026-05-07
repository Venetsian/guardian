"""
MTA queue depth — host-health module.

Postfix-only for now. Counts pending messages via `postqueue -p` and
buckets the depth for transition stability. This is unrelated to
outbound-spam detection (DistributedAuthDetector handles that) — the
queue depth is a system-health signal: a growing queue means something
downstream is broken (DNS, network, recipient rejecting in bulk, our
own rate-limit being hit).

Severity ladder:
  *  >= 1000 pending → HIGH (deliverability meaningfully impacted)
  *  >=  100 pending → MEDIUM (default warn threshold)
  *  otherwise        → PASS

Stored value buckets the depth so daily fluctuations don't trip
transitions; only crossing a threshold fires an event.

Applies: mta = postfix.
"""

import logging
import re

from posture_checks.base import Check, CheckResult, Severity, Module
from posture_checks._utils import safe_run

logger = logging.getLogger('wp-guardian.posture.mta_queue')


THRESHOLD_HIGH = 1000
THRESHOLD_MEDIUM = 100


_QUEUE_SUMMARY_RE = re.compile(
    r'(\d+)\s+Kbytes?\s+in\s+(\d+)\s+Requests?',
    re.IGNORECASE,
)


def _postqueue_depth():
    """Return (count, kbytes) from `postqueue -p`. (0, 0) on empty queue.
    None on probe failure (binary missing, command errored)."""
    rc, out = safe_run(['postqueue', '-p'], timeout=10)
    if rc < 0:
        return None
    text = out or ''
    if not text.strip() or 'queue is empty' in text.lower():
        return (0, 0)
    m = _QUEUE_SUMMARY_RE.search(text)
    if m:
        kbytes = int(m.group(1))
        count = int(m.group(2))
        return (count, kbytes)
    # Output was non-empty but lacked the summary line — probably an error
    return None


class MtaQueueCheck(Check):
    check_id = 'mta_queue_depth'
    module = Module.HEALTH
    severity = Severity.MEDIUM
    description = 'Postfix mail queue depth (pending messages)'

    def applies_to(self, profile):
        return profile.get('mta') == 'postfix'

    def run(self, profile, previous=None):
        result = _postqueue_depth()
        if result is None:
            return CheckResult.errored(
                detail="couldn't query postfix queue (`postqueue -p` failed)",
                value={'reason': 'postqueue_failed'},
            )
        count, kbytes = result

        if count >= THRESHOLD_HIGH:
            bucket = 'high'
        elif count >= THRESHOLD_MEDIUM:
            bucket = 'medium'
        else:
            bucket = 'ok'

        value = {
            'bucket': bucket,
            'threshold_medium': THRESHOLD_MEDIUM,
            'threshold_high': THRESHOLD_HIGH,
        }

        if count >= THRESHOLD_HIGH:
            return CheckResult.failing(
                detail="postfix queue: {n} pending ({k} KB)".format(n=count, k=kbytes),
                value=value, severity=Severity.HIGH,
            )
        if count >= THRESHOLD_MEDIUM:
            return CheckResult.warning(
                detail="postfix queue: {n} pending ({k} KB)".format(n=count, k=kbytes),
                value=value, severity=Severity.MEDIUM,
            )
        return CheckResult.passing(
            detail="postfix queue: {n} pending".format(n=count),
            value=value,
        )
