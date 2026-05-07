"""
DB health — host-health module.

Tracks three signals on the local MariaDB / MySQL:
  * connection saturation: Threads_connected / max_connections
  * slow query rate: Slow_queries / Questions  (cumulative since server
    start — see below for why we don't do delta yet)
  * InnoDB buffer pool hit rate: 1 - reads/read_requests

Auth probe order:
  1. /root/.my.cnf            (CyberPanel writes this on install)
  2. /etc/mysql/debian.cnf    (Debian/Ubuntu)
  3. unix_socket auth as root (no creds needed on a modern install)

If none of those work, the check returns ERROR with a clear message;
the operator can drop a [client] block in /root/.my.cnf to enable it.

Severity ladder (worst-of):
  * any 'high' bucket          → HIGH (status FAIL)
  * any 'medium' bucket        → MEDIUM (status WARN)
  * otherwise                  → PASS

Stored value buckets each metric so daily wiggles don't trip transitions.
We deliberately do NOT store cumulative counters in the value dict —
they grow monotonically and would force a transition every run, drowning
the bucket signal in noise. Slow-query rate is therefore cumulative
since server start (a poor proxy that improves with uptime); a real
delta-based slow rate is a follow-up.
"""

import logging
import os

from posture_checks.base import Check, CheckResult, Severity, Module
from posture_checks._utils import safe_run

logger = logging.getLogger('wp-guardian.posture.db_health')


CONN_PCT_HIGH = 90
CONN_PCT_MEDIUM = 70
SLOW_PCT_HIGH = 5.0       # >= 5% of total queries being slow is bad
SLOW_PCT_MEDIUM = 1.0
HIT_RATE_VERY_LOW = 90    # buffer pool hit rate below this is bad
HIT_RATE_LOW = 95


def _mysql_query_one(sql):
    """Run `mysql -N -B -e <sql>` and return first row of values list,
    or None. Tries common auth paths in order."""
    candidates = [
        ['mysql', '--defaults-file=/root/.my.cnf', '-N', '-B', '-e', sql],
        ['mysql', '--defaults-file=/etc/mysql/debian.cnf', '-N', '-B', '-e', sql],
        ['mysql', '-N', '-B', '-e', sql],
    ]
    for cmd in candidates:
        # Skip non-existent --defaults-file paths quickly so we don't
        # waste a process spawn per attempt.
        if cmd[1].startswith('--defaults-file='):
            path = cmd[1].split('=', 1)[1]
            if not os.path.isfile(path):
                continue
        rc, out = safe_run(cmd, timeout=8)
        if rc == 0 and (out or '').strip():
            for line in out.splitlines():
                stripped = line.rstrip('\n').rstrip('\r')
                if stripped:
                    return stripped.split('\t')
    return None


def _query_status_int(name):
    row = _mysql_query_one("SHOW GLOBAL STATUS LIKE '{n}'".format(n=name))
    if row and len(row) >= 2:
        try:
            return int(row[1])
        except ValueError:
            return None
    return None


def _query_variable(name):
    row = _mysql_query_one("SHOW VARIABLES LIKE '{n}'".format(n=name))
    if row and len(row) >= 2:
        try:
            return int(row[1])
        except ValueError:
            return row[1]
    return None


def _conn_bucket(pct):
    if pct >= CONN_PCT_HIGH:
        return 'high'
    if pct >= CONN_PCT_MEDIUM:
        return 'medium'
    return 'ok'


def _slow_bucket(pct):
    if pct >= SLOW_PCT_HIGH:
        return 'high'
    if pct >= SLOW_PCT_MEDIUM:
        return 'medium'
    return 'ok'


def _hit_bucket(rate):
    if rate is None:
        return 'unknown'
    if rate < HIT_RATE_VERY_LOW:
        return 'very_low'
    if rate < HIT_RATE_LOW:
        return 'low'
    return 'ok'


class DbHealthCheck(Check):
    check_id = 'db_health'
    module = Module.HEALTH
    severity = Severity.MEDIUM
    description = ('DB health: connection saturation, slow-query rate, '
                   'InnoDB buffer pool hit rate')

    def applies_to(self, profile):
        return profile.get('db_server') in ('mariadb', 'mysql')

    def run(self, profile, previous=None):
        threads = _query_status_int('Threads_connected')
        if threads is None:
            return CheckResult.errored(
                detail=("couldn't query DB status — auth failed (tried "
                        "/root/.my.cnf, /etc/mysql/debian.cnf, unix_socket). "
                        "Drop a [client] block in /root/.my.cnf to enable."),
                value={'reason': 'auth_failed'},
            )

        max_conn_raw = _query_variable('max_connections')
        max_conn = max_conn_raw if isinstance(max_conn_raw, int) else 0
        slow_queries = _query_status_int('Slow_queries') or 0
        questions = _query_status_int('Questions') or 0
        ip_reads = _query_status_int('Innodb_buffer_pool_reads') or 0
        ip_req = _query_status_int('Innodb_buffer_pool_read_requests') or 0

        conn_pct = int(round(100.0 * threads / max_conn)) if max_conn else 0
        slow_pct = (100.0 * slow_queries / questions) if questions > 0 else 0.0
        hit_rate = None
        if ip_req > 0:
            hit_rate = int(round(100.0 * (1.0 - (float(ip_reads) / ip_req))))

        buckets = {
            'conn': _conn_bucket(conn_pct),
            'slow': _slow_bucket(slow_pct),
            'hit_rate': _hit_bucket(hit_rate),
        }
        value = {'buckets': buckets}

        bits = ["conns={t}/{m} ({p}%)".format(t=threads, m=max_conn, p=conn_pct)]
        if questions > 0:
            bits.append("slow={s}/{q} ({pct:.2f}%)".format(
                s=slow_queries, q=questions, pct=slow_pct))
        if hit_rate is not None:
            bits.append("buffer-pool-hit={h}%".format(h=hit_rate))
        detail = ', '.join(bits)

        any_high = (
            buckets['conn'] == 'high'
            or buckets['slow'] == 'high'
            or buckets['hit_rate'] == 'very_low'
        )
        any_medium = (
            buckets['conn'] == 'medium'
            or buckets['slow'] == 'medium'
            or buckets['hit_rate'] == 'low'
        )

        if any_high:
            return CheckResult.failing(detail=detail, value=value, severity=Severity.HIGH)
        if any_medium:
            return CheckResult.warning(detail=detail, value=value, severity=Severity.MEDIUM)
        return CheckResult.passing(detail=detail, value=value)
