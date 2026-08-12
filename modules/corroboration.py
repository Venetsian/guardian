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

v1.7.15 adds the payload-phase pair, which is strictly better proof but arrives
later in the takeover:

    outbound_volume      the account sending far above its own normal rate
    outbound_fanout      one message addressed to an implausible number of
                         recipients

Those two differ from each other in when they become usable. Volume needs the
account's own history, so it is deliberately INERT for the first few weeks
after installation — with an empty table every account looks anomalous, and
this is not a place to guess. Fan-out is absolute and needs no baseline, so it
is the one outbound signal that works on day one, and it covers exactly the
window in which the volume baseline is still accruing.

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

        # --- Outbound, payload phase (v1.7.15) -------------------------
        # Window for "recent sending". Wider than the detector's 1h because
        # the burst and the geographic anomaly need not be simultaneous — an
        # attacker may start sending an hour before their next login trips the
        # country count, or the other way round.
        self.outbound_window_seconds = config.getint(
            'compromise_detection', 'outbound_window_hours', fallback=6
        ) * 3600

        self.outbound_baseline_seconds = config.getint(
            'compromise_detection', 'outbound_baseline_days', fallback=30
        ) * 86400

        # The volume check stays silent until the table holds this much
        # history — measured across ALL accounts, not this one. That is what
        # distinguishes "this mailbox is genuinely silent" from "Guardian was
        # installed on Tuesday", and without it every account would read as
        # anomalous for the first weeks.
        self.outbound_min_observation_days = config.getint(
            'compromise_detection', 'outbound_min_observation_days', fallback=14
        )

        self.outbound_volume_multiplier = config.getfloat(
            'compromise_detection', 'outbound_volume_multiplier', fallback=10.0
        )

        # Absolute floor, in messages within the window. Load-bearing: a
        # multiplier against a near-zero baseline is a division by almost
        # nothing, and would fire on an account going from one message a week
        # to three.
        self.outbound_volume_floor = config.getint(
            'compromise_detection', 'outbound_volume_floor', fallback=100
        )

        # Recipients on a single message. No baseline, so this one can fire on
        # the day of installation — it is the signal that covers the volume
        # baseline's inert period.
        #
        # 250 rather than the 50 originally chosen. Replaying 4.5 weeks of a
        # production maillog (5,413 messages, 63 senders) found a starkly
        # bimodal distribution: everything at or below 9 recipients except one
        # legitimate newsletter at 133. 50 would have fired on that, and on the
        # single worst account to be wrong about — the host's only bulk sender
        # is also its most geographically scattered mailbox, so the fan-out
        # risk and the geographic trigger are concentrated on one client rather
        # than being independent.
        #
        # Set to 0 to disable this check entirely. That is the right choice on
        # a host whose users send bulk mail from their own mailboxes, since the
        # volume check below is immune to it — volume counts MESSAGES, and a
        # newsletter is one message however many recipients it carries.
        self.outbound_fanout_threshold = config.getint(
            'compromise_detection', 'outbound_fanout_threshold', fallback=250
        )

        retention_days = config.getint(
            'database', 'outbound_retention_days', fallback=30
        )
        if retention_days * 86400 < self.outbound_baseline_seconds:
            logger.warning(
                "[database] outbound_retention_days={r} is shorter than "
                "[compromise_detection] outbound_baseline_days={b} — the "
                "volume baseline will silently see only {r} days of "
                "history".format(r=retention_days,
                                 b=self.outbound_baseline_seconds // 86400)
            )

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
                      self._check_alias_injection,
                      self._check_outbound_volume,
                      self._check_outbound_fanout):
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

    # ------------------------------------------------------------------
    # Payload phase (v1.7.15)
    # ------------------------------------------------------------------
    def _check_outbound_volume(self, username):
        """Sending far above this account's own established rate.

        Compared against the account itself rather than a server-wide figure,
        because mailboxes differ by orders of magnitude — a booking address
        that sends 400 a day and a director's address that sends four are both
        normal, and no single number describes them.

        Deliberately inert until the table holds outbound_min_observation_days
        of history. Guardian cannot tell a quiet mailbox from an empty table,
        and the safe reading of that ambiguity is "no signal".
        """
        if not self.db or self.outbound_window_seconds <= 0:
            return ''

        observed_days = self.db.outbound_observation_days()
        if observed_days < self.outbound_min_observation_days:
            logger.debug(
                "Outbound volume check inert: {o:.1f} of {n} days of history "
                "accrued".format(o=observed_days, n=self.outbound_min_observation_days)
            )
            return ''

        stats = self.db.outbound_window_stats(username, self.outbound_window_seconds)
        messages = stats['messages']

        # The floor is checked before the ratio on purpose. Every FP this
        # check could plausibly produce comes from a small absolute number
        # magnified by a tiny baseline.
        if messages < self.outbound_volume_floor:
            return ''

        baseline = self.db.outbound_baseline(
            username,
            self.outbound_baseline_seconds,
            exclude_recent_seconds=self.outbound_window_seconds,
        )
        # None means the windows were degenerate — no comparison to make.
        if not baseline:
            return ''

        window_hours = self.outbound_window_seconds / 3600.0
        recent_rate = messages / window_hours if window_hours > 0 else 0.0

        if not baseline['messages']:
            # Silent for the whole baseline window. The observation gate above
            # already established the silence is real history, so a hundred
            # messages in six hours from a standing start is the signal, not
            # an artefact of an empty table.
            return ("outbound burst from an account with no send history in "
                    "{d} days ({m} messages in {h:.0f}h)".format(
                        d=int(self.outbound_baseline_seconds / 86400),
                        m=messages, h=window_hours))

        if recent_rate < baseline['per_hour'] * self.outbound_volume_multiplier:
            return ''

        return ("outbound volume {r:.0f}/h against a baseline of {b:.1f}/h "
                "({m} messages in {h:.0f}h)".format(
                    r=recent_rate, b=baseline['per_hour'],
                    m=messages, h=window_hours))

    def _check_outbound_fanout(self, username):
        """One message addressed to an implausible number of recipients.

        The only outbound signal that needs no history, so it is armed from
        the moment the feature is installed and covers the weeks in which the
        volume baseline is still accruing. A mailbox blasting a list is doing
        something its owner can describe in one sentence — and the account is
        only being examined at all because the geographic detector already
        selected it.
        """
        if not self.db or self.outbound_fanout_threshold <= 0:
            return ''

        stats = self.db.outbound_window_stats(username, self.outbound_window_seconds)
        max_nrcpt = stats['max_nrcpt']
        if max_nrcpt >= self.outbound_fanout_threshold:
            return ("recipient fan-out: a single message to {n} recipients "
                    "(threshold {t})".format(
                        n=max_nrcpt, t=self.outbound_fanout_threshold))
        return ''
