"""Mail schema auto-detection (v1.7.12+).

Derives Guardian's [mail_backend] settings from what Postfix and Dovecot
already declare about themselves, instead of asking the operator to hand-copy
table and column names out of a schema they may not have designed.

Why config files rather than the database: both daemons must be told exactly
how to find mailboxes, and they are told in plain text. Postfix names its map
files, each map file states its query; Dovecot's passdb states its. That is
authoritative — it is literally what the running mail server uses — and it
needs no database credentials to read, so detection works before Guardian's
own least-privilege DB user exists.

It is also stack-agnostic. Postfixadmin, Mailcow, iRedMail and CyberPanel are
all Postfix + Dovecot underneath and all use these same two mechanisms. The
query TEXT differs between them; the place you find it does not.

    postfix+dovecot MySQL   SELECT destination FROM virtual_aliases WHERE source='%s'
    postfixadmin / mailcow  SELECT goto        FROM alias           WHERE address='%s'
    iRedMail                SELECT forwarding  FROM forwardings     WHERE address=%s

Detection never wins silently. Every result carries the file it came from and
a confidence, and callers are expected to show that to the operator before
writing anything.

SECURITY: map files contain the mail server's own database password. This
module reads a WHITELIST of keys and never stores or returns the password
field. A blacklist would leak the first time someone's file had an unusual
key name.

Python 3.6 compatible — no dataclasses, no f-string nesting, no walrus.
"""

import os
import re
import logging
import subprocess

logger = logging.getLogger('wp-guardian.mail_schema')


# Keys we are willing to read out of a Postfix MySQL map file. Anything not
# listed here — crucially `password` — is never even parsed.
CF_SAFE_KEYS = (
    'hosts', 'host', 'dbname', 'user', 'query',
    # Legacy three-key form, still shipped by several distro packages and by
    # older Postfixadmin setups. Easier to parse than a query, and if present
    # it is unambiguous.
    'table', 'select_field', 'where_field', 'additional_conditions',
)

DOVECOT_SQL_PATHS = (
    '/etc/dovecot/dovecot-sql.conf.ext',
    '/etc/dovecot/conf.d/dovecot-sql.conf.ext',
    '/usr/local/etc/dovecot/dovecot-sql.conf.ext',
)

# A query we cannot reduce to one table and one column pair. iRedMail in
# particular composes forwarding lookups from several tables.
_AMBIGUOUS_SQL = re.compile(r'\b(JOIN|UNION)\b', re.I)

_RE_SELECT = re.compile(r'\bSELECT\s+(.+?)\s+FROM\b', re.I | re.S)
_RE_FROM = re.compile(r'\bFROM\s+`?(\w+)`?', re.I)
_RE_WHERE = re.compile(r'\bWHERE\s+`?(\w+)`?\s*=', re.I)
# `AND enabled=1` / `AND active = '1'` — the soft-delete flag most schemas carry.
_RE_ENABLED = re.compile(r"\bAND\s+`?(\w+)`?\s*=\s*'?1'?", re.I)


def _run(cmd):
    """Run a command, return stdout or '' — never raises.

    Python 3.6: no capture_output=, no text=.
    """
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True
        )
        out, _ = proc.communicate(timeout=10)
        if proc.returncode != 0:
            return ''
        return out or ''
    except Exception as e:
        logger.debug("command {c} failed: {e}".format(c=' '.join(cmd), e=e))
        return ''


def _first_select_column(select_list):
    """Reduce a SELECT list to its first bare column name.

    'destination'                    -> destination
    'email as user, password'        -> email
    '`goto`'                         -> goto
    'a.destination'                  -> destination
    Returns '' when the first item is an expression we shouldn't guess at
    (CONCAT(...), a literal, *).
    """
    first = select_list.split(',')[0].strip()
    # Strip a column alias: "email as user" -> "email"
    first = re.split(r'\s+as\s+', first, flags=re.I)[0].strip()
    first = first.strip('`').strip()
    # table-qualified: a.destination -> destination
    if '.' in first:
        first = first.rsplit('.', 1)[1].strip('`')
    if not re.match(r'^\w+$', first):
        return ''
    if first == '*':
        return ''
    # `SELECT 1 FROM virtual_users WHERE ...` is an existence probe, not a
    # column projection — Postfix's mailbox map is usually written this way.
    # \w matches digits, so this has to be rejected explicitly.
    if first.isdigit():
        return ''
    return first


def _parse_sql(query):
    """Extract {table, select_column, where_column, enabled_column} from a query.

    Returns (result_dict, problem_string). A problem means "show the operator
    the raw query and let them decide" — never a partial guess.
    """
    if not query:
        return (None, 'empty query')
    if _AMBIGUOUS_SQL.search(query):
        return (None, 'query joins multiple tables')

    m_from = _RE_FROM.search(query)
    m_sel = _RE_SELECT.search(query)
    m_where = _RE_WHERE.search(query)
    if not (m_from and m_sel and m_where):
        return (None, 'could not locate SELECT/FROM/WHERE')

    select_col = _first_select_column(m_sel.group(1))
    if not select_col:
        return (None, 'SELECT list is an expression, not a plain column')

    m_enabled = _RE_ENABLED.search(query)
    return ({
        'table': m_from.group(1),
        'select_column': select_col,
        'where_column': m_where.group(1),
        'enabled_column': m_enabled.group(1) if m_enabled else '',
    }, '')


def parse_cf_file(path):
    """Parse a Postfix MySQL map file into a dict of whitelisted keys.

    The password field is deliberately not read. Returns {} if unreadable.
    """
    values = {}
    try:
        with open(path, 'r') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                key, _, val = line.partition('=')
                key = key.strip().lower()
                if key in CF_SAFE_KEYS:
                    values[key] = val.strip()
    except IOError as e:
        logger.debug("cannot read {p}: {e}".format(p=path, e=e))
        return {}
    return values


def _schema_from_cf(cf, path):
    """Turn a parsed map file into a schema dict, preferring the explicit
    three-key form over parsing SQL."""
    # Legacy explicit form — unambiguous, no parsing risk.
    if cf.get('table') and cf.get('select_field') and cf.get('where_field'):
        return ({
            'table': cf['table'],
            'select_column': cf['select_field'],
            'where_column': cf['where_field'],
            'enabled_column': '',
            'database': cf.get('dbname', ''),
            'host': cf.get('hosts') or cf.get('host') or '',
            'source_file': path,
            'confidence': 'high',
        }, '')

    parsed, problem = _parse_sql(cf.get('query', ''))
    if not parsed:
        return (None, problem)
    parsed['database'] = cf.get('dbname', '')
    parsed['host'] = cf.get('hosts') or cf.get('host') or ''
    parsed['source_file'] = path
    parsed['confidence'] = 'high'
    return (parsed, '')


def _map_files(postconf_value):
    """Extract usable mysql: map paths from a postconf value.

    Returns (paths, problem). A map that is not MySQL-backed — hash:, ldap:,
    pcre:, regexp: — cannot tell us a schema, and chained maps are ambiguous
    about which one owns the mailboxes.
    """
    value = (postconf_value or '').strip()
    if not value:
        return ([], 'not configured')

    maps = value.split(',')
    mysql_maps = []
    other = []
    for entry in maps:
        entry = entry.strip()
        if not entry:
            continue
        if entry.startswith('mysql:'):
            mysql_maps.append(entry[len('mysql:'):])
        else:
            other.append(entry.split(':')[0])

    if not mysql_maps:
        return ([], 'not MySQL-backed ({o})'.format(o=', '.join(other) or value))
    return (mysql_maps, '')


def detect_postfix():
    """Read Postfix's alias and mailbox maps.

    Returns {'alias': {...}|None, 'mailbox': {...}|None, 'problems': {...}}.
    """
    result = {'alias': None, 'mailbox': None, 'problems': {}}

    out = _run(['postconf', '-h', 'virtual_alias_maps', 'virtual_mailbox_maps'])
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if len(lines) < 2:
        result['problems']['postfix'] = 'postconf unavailable or returned nothing'
        return result

    for kind, raw in (('alias', lines[0]), ('mailbox', lines[1])):
        paths, problem = _map_files(raw)
        if problem:
            result['problems'][kind] = problem
            continue
        if len(paths) > 1:
            result['problems'][kind] = (
                'several maps chained ({n}) — cannot tell which owns the '
                'data'.format(n=len(paths))
            )
            continue
        cf = parse_cf_file(paths[0])
        if not cf:
            result['problems'][kind] = 'cannot read {p} (run as root?)'.format(p=paths[0])
            continue
        schema, problem = _schema_from_cf(cf, paths[0])
        if problem:
            result['problems'][kind] = '{p}: {q}'.format(
                p=problem, q=cf.get('query', '')[:160])
            continue
        result[kind] = schema

    return result


def _dovecot_sql_path():
    for path in DOVECOT_SQL_PATHS:
        if os.path.isfile(path):
            return path
    # Ask Dovecot itself where its passdb args point.
    out = _run(['doveadm', 'config'])
    m = re.search(r'args\s*=\s*(\S*dovecot-sql\S*)', out)
    if m and os.path.isfile(m.group(1)):
        return m.group(1)
    return ''


def detect_dovecot():
    """Read Dovecot's passdb query and mail location.

    Returns {'mailbox': {...}|None, 'maildir_template': str, 'problems': {...}}.
    """
    result = {'mailbox': None, 'maildir_template': '', 'problems': {}}

    # mail_location is the authoritative maildir root, and it is what the
    # sieve corroboration check needs to find ~/.dovecot.sieve.
    out = _run(['doveadm', 'config'])
    m = re.search(r'^mail_location\s*=\s*maildir:(\S+)', out, re.M)
    if m:
        result['maildir_template'] = m.group(1).rstrip('/')
    else:
        result['problems']['maildir'] = 'mail_location not a maildir: path'

    path = _dovecot_sql_path()
    if not path:
        result['problems']['dovecot'] = 'no dovecot-sql.conf.ext found'
        return result

    query = ''
    try:
        with open(path, 'r') as fh:
            for line in fh:
                line = line.strip()
                if line.startswith('#') or '=' not in line:
                    continue
                key, _, val = line.partition('=')
                # password_query only. user_query carries quota/home
                # expressions that are not a mailbox lookup, and we must
                # never touch the `password =` connect string.
                if key.strip().lower() == 'password_query':
                    query = val.strip()
                    break
    except IOError as e:
        result['problems']['dovecot'] = 'cannot read {p}: {e}'.format(p=path, e=e)
        return result

    parsed, problem = _parse_sql(query)
    if not parsed:
        result['problems']['dovecot'] = '{p}: {q}'.format(p=problem, q=query[:160])
        return result

    parsed['source_file'] = path
    parsed['confidence'] = 'high'
    result['mailbox'] = parsed
    return result


def detect():
    """Full detection pass. Returns a report dict; never raises.

    Keys:
      mail_backend   suggested [mail_backend] values (may be partial)
      evidence       where each value came from
      problems       what could not be determined, and why
      detected       True if anything usable was found
    """
    report = {'mail_backend': {}, 'evidence': {}, 'problems': {}, 'detected': False}

    pf = detect_postfix()
    dc = detect_dovecot()
    report['problems'].update(
        dict(('postfix:' + k, v) for k, v in pf['problems'].items())
    )
    report['problems'].update(
        dict(('dovecot:' + k, v) for k, v in dc['problems'].items())
    )

    mb = report['mail_backend']
    ev = report['evidence']

    # --- mailbox table -----------------------------------------------------
    # Dovecot's passdb is the better source: it names the enabled/active
    # column, which is the one Guardian actually writes. Postfix's mailbox map
    # often selects a literal (SELECT 1 FROM ...) and so yields no column.
    mailbox = dc['mailbox'] or pf['mailbox']
    if mailbox:
        mb['table'] = mailbox['table']
        mb['email_column'] = mailbox['where_column']
        if mailbox.get('enabled_column'):
            mb['enabled_column'] = mailbox['enabled_column']
        ev['table'] = mailbox['source_file']
        ev['email_column'] = mailbox['source_file']
        if mailbox.get('enabled_column'):
            ev['enabled_column'] = mailbox['source_file']

    # --- database / host ---------------------------------------------------
    for src in (pf['mailbox'], pf['alias']):
        if src and src.get('database'):
            mb['database'] = src['database']
            ev['database'] = src['source_file']
            if src.get('host'):
                mb['host'] = src['host']
                ev['host'] = src['source_file']
            break

    # --- alias table -------------------------------------------------------
    alias = pf['alias']
    if alias:
        mb['alias_table'] = alias['table']
        mb['alias_source_column'] = alias['where_column']
        mb['alias_destination_column'] = alias['select_column']
        ev['alias_table'] = alias['source_file']
        ev['alias_source_column'] = alias['source_file']
        ev['alias_destination_column'] = alias['source_file']

    # --- maildir root (sieve corroboration check) --------------------------
    # Translated out of Dovecot's %d/%n syntax: ConfigParser runs
    # BasicInterpolation, so a literal % in a config value makes the daemon
    # fail to start. Guardian's own placeholders are brace-delimited.
    if dc['maildir_template']:
        mb['maildir_template'] = (dc['maildir_template']
                                  .replace('%d', '{domain}')
                                  .replace('%n', '{user}')
                                  .replace('%u', '{email}'))
        ev['maildir_template'] = 'doveadm config (mail_location)'

    report['detected'] = bool(mb)
    return report


def verify_against_db(report, connect_fn):
    """Optional second opinion: confirm the detected columns actually exist.

    connect_fn is a zero-arg callable returning a DB-API connection — normally
    MailBackend._connect. Config-file evidence stands on its own when no
    credentials are available; this only ever ADDS confidence or downgrades a
    specific field, and never invents one.

    Returns a dict of {field: 'ok'|'missing'|'unchecked'}.
    """
    checks = {}
    mb = report.get('mail_backend', {})
    pairs = (
        ('table', ('email_column', 'enabled_column')),
        ('alias_table', ('alias_source_column', 'alias_destination_column',
                         'alias_created_column')),
    )
    try:
        conn = connect_fn()
    except Exception as e:
        logger.debug("verify skipped, no DB connection: {e}".format(e=e))
        for tkey, cols in pairs:
            if mb.get(tkey):
                checks[tkey] = 'unchecked'
        return checks

    try:
        cur = conn.cursor()
        try:
            for tkey, cols in pairs:
                table = mb.get(tkey)
                if not table:
                    continue
                # Identifier cannot be parameterised; it came from our own
                # regex which only ever yields \w+, so it is already safe.
                safe = ''.join(c for c in table if c.isalnum() or c == '_')
                try:
                    cur.execute("DESCRIBE `{t}`".format(t=safe))
                    present = set(row[0] for row in cur.fetchall())
                except Exception:
                    checks[tkey] = 'missing'
                    continue
                checks[tkey] = 'ok'
                for ckey in cols:
                    col = mb.get(ckey)
                    if col:
                        checks[ckey] = 'ok' if col in present else 'missing'
        finally:
            cur.close()
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return checks


def find_created_column(report, connect_fn):
    """Look for a timestamp column on the alias table.

    Not derivable from Postfix's config — its query never selects it — but
    it is what lets the forwarding check distinguish a rule planted an hour
    ago from one the client has had for two years. Best-effort: needs DB
    access, and returns '' when unavailable.
    """
    table = report.get('mail_backend', {}).get('alias_table')
    if not table:
        return ''
    safe = ''.join(c for c in table if c.isalnum() or c == '_')
    try:
        conn = connect_fn()
    except Exception:
        return ''
    try:
        cur = conn.cursor()
        try:
            cur.execute("DESCRIBE `{t}`".format(t=safe))
            rows = cur.fetchall()
        finally:
            cur.close()
    except Exception:
        return ''
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # row = (Field, Type, Null, Key, Default, Extra)
    for candidate in ('created_at', 'created', 'created_on', 'add_date', 'ts'):
        for row in rows:
            if row[0].lower() == candidate and _is_timeish(row[1]):
                return row[0]
    for row in rows:
        if _is_timeish(row[1]) and 'creat' in row[0].lower():
            return row[0]
    return ''


def _is_timeish(coltype):
    t = (coltype or '').lower()
    return any(k in t for k in ('datetime', 'timestamp', 'date', 'int'))


def grant_statement(report, db_user='wp_guardian', db_host='localhost'):
    """The exact GRANT the operator needs for the alias check, with real
    names filled in. Returns '' when there is no alias table to grant on."""
    mb = report.get('mail_backend', {})
    table = mb.get('alias_table')
    if not table:
        return ''
    cols = [mb.get('alias_source_column'), mb.get('alias_destination_column')]
    if mb.get('alias_created_column'):
        cols.append(mb['alias_created_column'])
    cols = [c for c in cols if c]
    database = mb.get('database', '<database>')
    return (
        "GRANT SELECT ({cols}) ON {db}.{tbl} TO '{u}'@'{h}';".format(
            cols=', '.join(cols), db=database, tbl=table, u=db_user, h=db_host
        )
    )
