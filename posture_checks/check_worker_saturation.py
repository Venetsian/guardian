"""
Web-server worker saturation — host-health module.

For Apache: fetch /server-status?auto on 127.0.0.1, parse BusyWorkers
and the Scoreboard string (length = MaxRequestWorkers).

OLS coverage is deferred — OLS exposes /reqstats but the shape differs
and isn't always enabled by default. First iteration reports a soft
WARN("not yet implemented") on OLS hosts so --posture-status surfaces
the gap rather than silently skipping.

Severity:
  *  >= 90% utilization → HIGH (status FAIL)
  *  >= 70%             → MEDIUM (status WARN; matches the spec's threshold)
  *  otherwise          → PASS

Stored value uses a coarse bucket so daily traffic wiggle doesn't fire
transitions every run. Single-sample only — sustained-average logic
would need its own sampling table; not in scope for first iteration.
"""

import logging
import urllib.request
import urllib.error

from posture_checks.base import Check, CheckResult, Severity, Module

logger = logging.getLogger('wp-guardian.posture.worker_saturation')


WARN_PCT = 70
FAIL_PCT = 90
DEFAULT_URL = 'http://127.0.0.1/server-status?auto'


def _fetch_apache_status(url=DEFAULT_URL, timeout=5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='replace')
    except (urllib.error.URLError, OSError) as e:
        logger.debug("server-status fetch failed: %s", e)
        return None
    except Exception as e:
        logger.debug("server-status fetch crashed unexpectedly: %s", e)
        return None


def _parse_apache_status(text):
    """Returns dict {'busy', 'max'} or None."""
    busy = None
    scoreboard = ''
    for line in text.splitlines():
        if line.startswith('BusyWorkers:'):
            try:
                busy = int(line.split(':', 1)[1].strip())
            except (ValueError, IndexError):
                pass
        elif line.startswith('Scoreboard:'):
            try:
                scoreboard = line.split(':', 1)[1].strip()
            except IndexError:
                scoreboard = ''
    if busy is None or not scoreboard:
        return None
    return {'busy': busy, 'max': len(scoreboard)}


class WorkerSaturationCheck(Check):
    check_id = 'worker_saturation'
    module = Module.HEALTH
    severity = Severity.MEDIUM
    description = 'Web-server worker saturation (BusyWorkers / MaxRequestWorkers)'

    def applies_to(self, profile):
        return profile.get('web_server') in ('apache', 'ols')

    def run(self, profile, previous=None):
        web = profile.get('web_server')

        if web == 'ols':
            return CheckResult.warning(
                detail="OLS worker saturation not yet implemented",
                value={'web_server': 'ols', 'reason': 'ols_unimplemented'},
                severity=Severity.LOW,
            )

        text = _fetch_apache_status()
        if text is None:
            return CheckResult.errored(
                detail=("couldn't fetch /server-status?auto on 127.0.0.1 "
                        "(is mod_status enabled and bound to localhost?)"),
                value={'reason': 'fetch_failed'},
            )

        parsed = _parse_apache_status(text)
        if parsed is None:
            return CheckResult.errored(
                detail="server-status response missing BusyWorkers / Scoreboard",
                value={'reason': 'parse_failed'},
            )

        busy = parsed['busy']
        max_w = parsed['max']
        if max_w == 0:
            return CheckResult.errored(
                detail="server-status reported zero-length scoreboard",
                value={'reason': 'zero_max'},
            )

        pct = int(round(100.0 * busy / max_w))
        if pct >= FAIL_PCT:
            bucket = 'high'
        elif pct >= WARN_PCT:
            bucket = 'medium'
        else:
            bucket = 'ok'

        value = {'bucket': bucket, 'max_workers': max_w}
        detail = "BusyWorkers={b}/{m} ({p}%)".format(b=busy, m=max_w, p=pct)

        if pct >= FAIL_PCT:
            return CheckResult.failing(detail=detail, value=value, severity=Severity.HIGH)
        if pct >= WARN_PCT:
            return CheckResult.warning(detail=detail, value=value, severity=Severity.MEDIUM)
        return CheckResult.passing(detail=detail, value=value)
