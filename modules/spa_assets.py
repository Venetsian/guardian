"""Framework navigation-payload classification.

Single-page-application frameworks fetch route data through URLs no human
ever types and no wordlist ever contains. When the build on disk stops
matching the route manifest inside an already-loaded client bundle — the
normal state of affairs for the seconds after every deploy, and for as long
as a developer leaves a stale tab open — the browser emits one failed payload
request per route it wanted to prefetch, all at once.

Measured on a production Next.js host in this fleet, one developer's browser
during a rebuild:

    peak minute   134 failed requests, 129 of them RSC prefetches,
                  alongside 100 successful ones
    threshold     general_404_threshold = 50 per 300s

So the storm rule fired inside a single minute, six times over four months,
and escalated the developer to a tier-2 (30-day) block once. The client was a
current Edge browser sending a same-origin Referer that had already pulled
766 successful responses from that vhost.

Recognising these lets the 404-storm counter leave them out. The exemption is
deliberately narrow:

  * It never applies to a .php path. Every high-value web rule Guardian has
    — structural, instant, suspicious, tripwire, php_scan — is .php-scoped,
    so a scanner cannot reach any of them by dressing a probe up as a
    prefetch.
  * It suppresses *counting* only. Nothing here can cancel a block another
    rule already decided on.
  * WebDetector's success-ratio guard still applies to whatever is left, so
    appending ?_rsc= to a wordlist buys an attacker nothing: they would still
    have to fetch real content in bulk to look like a browser.
"""

import re

# Query parameters a framework appends to its own fetches. Matched on the
# parameter NAME, so a value that merely contains the string does not count.
_QUERY_PARAMS = (
    '_rsc',        # Next.js App Router — RSC payload and prefetch
    '_data',       # Remix / React Router — loader data
)

# Path prefixes owned by a build tool. Everything underneath is generated,
# content-hashed and re-created on every build.
_PATH_PREFIXES = (
    '/_next/',              # Next.js build output, route data, image optimiser
    '/_nuxt/',              # Nuxt
    '/_astro/',             # Astro
    '/_app/',               # SvelteKit
    '/page-data/',          # Gatsby
    '/@vite/',              # Vite dev server
    '/@id/',
    '/@fs/',
    '/node_modules/.vite/',
)

# Generated payload filenames, matched against the end of the path.
_FILE_PATTERNS = (
    re.compile(r'/__next\.[^/]*\.txt$'),   # Next.js 15 client segment cache
    re.compile(r'/__data\.json$'),         # SvelteKit
    re.compile(r'/_payload\.json$'),       # Nuxt
    re.compile(r'/app-data\.json$'),       # Gatsby
    re.compile(r'\.map$'),                 # source maps
)


def _is_route_shaped(clean_path):
    """True when the path could be a router route rather than a filename.

    Directory-style or extension-less. `/carrier/signup/` and
    `/pricing-for-shippers` qualify; `/backup.zip` and `/.env` do not.
    """
    for segment in clean_path.split('/'):
        if segment.startswith('.'):
            return False
    if clean_path.endswith('/'):
        return True
    return '.' not in clean_path.rsplit('/', 1)[-1]


def is_framework_payload(path, clean_path, extra_prefixes=()):
    """True when this request is a build tool's own navigation payload.

    Takes the same pair every caller in detectors/ already holds: `path`
    keeps the query string, `clean_path` is lowercased with the query
    stripped.
    """
    # Refusing .php here is the whole reason this classifier is safe to
    # consult before a threshold counter. Do not relax it.
    if clean_path.endswith('.php'):
        return False

    if '?' in path:
        query = path.split('?', 1)[1].lower()
        for part in query.split('&'):
            if part.split('=', 1)[0] in _QUERY_PARAMS:
                # The marker alone is not enough. A router only ever appends
                # it to a route it is navigating to, and a route is
                # extension-less. Requiring that shape means /.env?_rsc=1 and
                # /backup.zip?_rsc=1 stay ordinary enumeration instead of
                # becoming exempt the moment an attacker learns the parameter
                # name.
                if _is_route_shaped(clean_path):
                    return True
                break

    for prefix in _PATH_PREFIXES:
        if clean_path.startswith(prefix):
            return True

    for prefix in extra_prefixes:
        if prefix and clean_path.startswith(prefix):
            return True

    for pattern in _FILE_PATTERNS:
        if pattern.search(clean_path):
            return True

    return False
