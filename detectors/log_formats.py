"""Web access log format dispatcher.

Auto-detects log format and normalizes the line into a dict for downstream
detectors. Supports:

  - OpenLiteSpeed (OLS): each line wrapped in outer quotes
  - Apache combined / nginx default: no outer quotes
  - LSWS Enterprise: identical to OLS in the common configuration

The parser is deliberately lenient — it accepts the line as long as the
three required fields (IP, request line, status code) can be extracted.
This matches the v1.4 inline parser exactly so the v1.5 refactor produces
zero behavior change.

v1.5 callers should use parse_line(); the returned dict also surfaces
referer / user_agent / size for the upcoming POST-flood detector.
"""

import re


_IP_RE = re.compile(r'^(\d+\.\d+\.\d+\.\d+)')
_REQ_RE = re.compile(r'"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) ([^ ]+) HTTP')
_STATUS_RE = re.compile(r'" (\d{3}) ')
_SIZE_RE = re.compile(r'" \d{3} (\S+)')
_QUOTED_RE = re.compile(r'"([^"]*)"')


def parse_line(line):
    """Parse a single access log line.

    Returns a dict with keys:
        ip, method, path, clean_path, status, size, referer, user_agent, format
    or None if the line can't be parsed.
    """
    if not line:
        return None

    # OLS / LSWS Enterprise wrap each line in outer quotes. Only strip the
    # trailing quote when we recognize the line as OLS — Apache combined and
    # nginx default legitimately end with the user-agent's closing quote.
    fmt = 'combined'
    if line.startswith('"'):
        line = line[1:]
        fmt = 'ols'
        if line.endswith('"'):
            line = line[:-1]

    ip_match = _IP_RE.match(line)
    if not ip_match:
        return None

    req_match = _REQ_RE.search(line)
    if not req_match:
        return None

    status_match = _STATUS_RE.search(line)
    if not status_match:
        return None

    path = req_match.group(2)
    clean_path = re.sub(r'\?.*$', '', path).lower()

    # Optional fields used by POST-flood and future detectors.
    size = ''
    size_match = _SIZE_RE.search(line)
    if size_match:
        size = size_match.group(1)

    # Combined log keeps three quoted strings: the request, the referer, and
    # the user-agent (in that order). Pulling the last two is enough for our
    # purposes; the request quote is already captured by _REQ_RE.
    quoted = _QUOTED_RE.findall(line)
    referer = ''
    user_agent = ''
    if len(quoted) >= 3:
        referer = quoted[-2]
        user_agent = quoted[-1]
    elif len(quoted) == 2:
        # Some shorter formats (or partial logs) — treat the trailing quote as UA.
        user_agent = quoted[-1]

    return {
        'ip': ip_match.group(1),
        'method': req_match.group(1),
        'path': path,
        'clean_path': clean_path,
        'status': status_match.group(1),
        'size': size,
        'referer': referer,
        'user_agent': user_agent,
        'format': fmt,
    }
