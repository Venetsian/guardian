"""Abuse corroboration for compromise events (v1.7.12+).

Geography selects candidates; abuse evidence authorises enforcement.

`DistributedAuthDetector` answers "is this account authenticating from an
implausible spread of networks". That is a real question, but its answer alone
disabled two travelling clients' mailboxes in ten days, because a multi-homed
user roaming between carrier pools looks exactly like a distributed credential
abuse. This module answers the separate question: "is there any sign the
account is actually being MISUSED".

Signals are deliberately phase-matched to how a real takeover unfolds.
Credentials are harvested, the attacker logs in, reads mail, plants
persistence — and only monetises days or weeks later. A corroboration model
that only knew about outbound spam would go blind for exactly the window in
which intervention is cheap, and would speak up only once the damage was
already underway. So the checks here look for the RECONNAISSANCE-phase
artefacts:

    auth_failure_burst   credential stuffing leaves a pile of failures
                         immediately before the success that matters
    sieve_injection      a mailbox filter planted via ManageSieve — reachable
                         with nothing but the stolen IMAP password
    alias_injection      a forwarding row planted in the mail database, the
                         same persistence step performed through a panel

Outbound volume and recipient fan-out are the payload-phase signals and are
strictly better proof, but they arrive too late to be the only ones. They land
separately once the maillog delivery parser exists.

Every check fails toward NO SIGNAL. An exception, a missing GRANT, an
unreadable directory — none of them may ever manufacture evidence that takes a
client's mailbox offline.

Python 3.6 compatible.
"""

import os
import time
import logging

from detectors.base import HitTracker

logger = logging.getLogger('wp-guardian.corroboration')


class AbuseCorroborator:
    def __init__(self, config, db, mail_backend=None):
        self.db = db
        self.mail_backend = mail_backend

        self.enabled = config.getboolean(
            'compromise_detection', 'corroboration_enabled', fallback=True
        )

        # How far back a persistence artefact still counts. Deliberately much
        # wider than the detector's 1h window: the whole point is that the
        # sieve rule was planted during a dwell phase that may predate the
        # geographic trigger by days.
        self.lookback_seconds = config.getint(
            'compromise_detection', 'corroboration_lookback_hours', fallback=168
        ) * 3600

        self.failure_threshold = config.getint(
            'compromise_detection', 'corroboration_failure_threshold', fallback=20
        )
        failure_window = config.getint(
            'compromise_detection', 'corroboration_failure_window', fallback=3600
        )

        # Failures are counted per USERNAME here, in memory. The existing
        # per-IP HitTracker in MailDetector answers a different question and
        # cannot be reused: credential stuffing arrives from many IPs by
        # design, so a per-IP counter never sees the burst.
        #
        # In memory rather than a table on purpose. The window is an hour, the
        # write volume during an attack is enormous, and losing the counter to
        # a restart costs one corroborating signal — which fails toward "don't
        # disable". A table would trade a real write-amplification problem for
        # a benefit nobody would notice.
        self._failures = HitTracker(failure_window)

        # /var/vmail/{domain}/{user} — deliberately NOT Dovecot's own %d/%n
        # syntax. ConfigParser runs BasicInterpolation, so a literal % in any
        # config value raises at load time and the daemon never starts.
        # mail_schema translates Dovecot's form to this one when it detects.
        self.maildir_template = config.get(
            'mail_backend', 'maildir_template', fallback=''
        ).strip()

    # ------------------------------------------------------------------
    # Feeding
    # ------------------------------------------------------------------
    def record_auth_failure(self, username):
        """Called by the mail/roundcube detectors on every failed auth."""
        if not self.enabled or not username:
            return
        try:
            self._failures.add(self._normalize(username))
        except Exception as e:
            logger.debug("failure tracking error: {e}".format(e=e))

    @staticmethod
    def _normalize(username):
        """Fold the local-part form onto the full address.

        Brute-forcers try both — the observed pattern is `grace@example.org`
        immediately followed by `helen`. Counting those separately halves the
        burst and can drop it under the threshold.
        """
        return (username or '').strip().lower()

    # ------------------------------------------------------------------
    # Evaluating
    # ------------------------------------------------------------------
    def evaluate(self, username):
        """Return a list of human-readable abuse signals for this account.

        An empty list means distributed logins with no evidence of misuse,
        which describes a travelling or multi-homed user rather than a
        compromise.
        """
        if not self.enabled or not username:
            return []

        signals = []
        for check in (self._check_failure_burst,
                      self._check_sieve_injection,
                      self._check_alias_injection):
            try:
                found = check(username)
                if found:
                    signals.append(found)
            except Exception as e:
                # Never let a broken check authorise enforcement.
                logger.error("Corroboration check {c} failed for {u}: {e}".format(
                    c=check.__name__, u=username, e=e))
        return signals

    def _check_failure_burst(self, username):
        base = self._normalize(username)
        count = self._failures.get_count(base)
        local = base.split('@')[0]
        if local != base:
            count += self._failures.get_count(local)
        if count >= self.failure_threshold:
            return "auth-failure burst ({n} failures before success)".format(n=count)
        return ''

    def _check_sieve_injection(self, username):
        """A mailbox filter that appeared inside the lookback window.

        ManageSieve accepts the user's ordinary IMAP password, so this is the
        cheapest persistence an attacker with stolen credentials can plant —
        no panel access required. Roundcube's managesieve plugin writes the
        same files, so one check covers both routes.
        """
        home = self._maildir_for(username)
        if not home:
            return ''

        cutoff = time.time() - self.lookback_seconds
        newest = 0.0
        for candidate in (os.path.join(home, '.dovecot.sieve'),
                          os.path.join(home, 'sieve')):
            try:
                st = os.stat(candidate)
            except OSError:
                continue
            newest = max(newest, st.st_mtime)

        if newest and newest >= cutoff:
            age_h = int((time.time() - newest) / 3600)
            return "sieve rule created/modified {h}h ago".format(h=age_h)
        return ''

    def _maildir_for(self, username):
        """Expand the maildir template for one address.

        Placeholders: {domain} {user} {email}
        """
        if not self.maildir_template or '@' not in (username or ''):
            return ''
        local, _, domain = username.partition('@')
        # Reject anything that could climb out of the mail root. These come
        # from log lines, so they are attacker-influenced input.
        for part in (local, domain):
            if not part or '/' in part or os.sep in part \
                    or part.startswith('.') or '..' in part:
                return ''
        return (self.maildir_template
                .replace('{domain}', domain)
                .replace('{user}', local)
                .replace('{email}', username))

    def _check_alias_injection(self, username):
        """A forwarding row pointing this mailbox somewhere else."""
        if not (self.mail_backend and
                getattr(self.mail_backend, 'alias_check_available', False)):
            return ''

        since = int(time.time() - self.lookback_seconds)
        rows = self.mail_backend.recent_aliases(username, since_ts=since)

        # None means the check could not run — missing GRANT, DB down. That is
        # absence of evidence, not evidence of absence, and must not be read
        # as "no forwarding rules exist".
        if rows is None:
            return ''
        if not rows:
            return ''

        # Without a created column we cannot date the rule, so presence alone
        # is all we have. Report it as weaker so the log makes clear why.
        dated = any(r.get('created_at') is not None for r in rows)
        destinations = ', '.join(
            str(r['destination'])[:60] for r in rows[:3] if r.get('destination')
        )
        if dated:
            return "forwarding rule created in window -> {d}".format(d=destinations)
        return "forwarding rule present (undated) -> {d}".format(d=destinations)
