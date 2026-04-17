"""
WP-Guardian Telegram Verbosity Router (v1.4.1+)

Decides whether a given block event should be sent to Telegram
immediately, buffered into the hourly digest, or dropped silently.

Resolution order (first hit wins):
    1. Always-immediate overrides (hardcoded — cannot be muted)
    2. Tier-3 blocks (any rule firing at tier 3 → immediate)
    3. Runtime overrides from state/telegram_verbosity.json (/verbosity cmd)
    4. Config [telegram.rules] section
    5. Hardcoded per-rule defaults
    6. Global [telegram] alert_mode fallback (verbose/digest/quiet)

Levels:
    immediate — send now
    digest    — queue for the hourly digest
    silent    — no Telegram alert (block still executes and is logged)
"""

import json
import logging
import os
import threading

logger = logging.getLogger('wp-guardian.verbosity')


VALID_LEVELS = ('immediate', 'digest', 'silent')

# Rules that can never be muted — operational signals where silence is dangerous.
ALWAYS_IMMEDIATE_RULES = frozenset({
    'compromise',      # account takeover
    'cidr',            # /24 aggregation fired
    'block_failed',    # firewall backend broken
})

# Per-rule defaults. Tuned so noisy web-scanner traffic stays quiet out of the
# box while auth/takeover signals stay loud.
DEFAULTS = {
    # Web — high-signal
    'wp_login':        'immediate',
    'xmlrpc':          'immediate',
    'tripwire':        'immediate',
    'instant':         'immediate',
    'structural':      'immediate',
    'suspicious':      'immediate',
    'login_isolation': 'immediate',

    # Web — noisy, low-signal (muted by default; operator can opt in)
    'php_scan':        'silent',
    'general_404':     'silent',
    'author_enum':     'silent',

    # Mail
    'smtp_fail':       'immediate',
    'imap_fail':       'immediate',
    'pop3_fail':       'immediate',
    'roundcube':       'immediate',

    # SSH
    'ssh_fail':        'immediate',
    'ssh_invalid':     'immediate',

    # Meta
    'trusted_skip':    'immediate',
    'compromise':      'immediate',
    'cidr':            'immediate',
    'block_failed':    'immediate',
    'block':           'immediate',  # catch-all fallback
}

# Map legacy [telegram] alert_mode → effective level for rules that aren't
# covered by DEFAULTS or [telegram.rules]. Existing v1.4 operators upgrading
# keep the spirit of their chosen mode.
ALERT_MODE_FALLBACK = {
    'verbose': 'immediate',
    'digest':  'digest',
    'quiet':   'silent',
}


class VerbosityRouter:
    def __init__(self, config, base_dir):
        self.base_dir = base_dir
        self.state_path = os.path.join(base_dir, 'state', 'telegram_verbosity.json')
        self._lock = threading.Lock()

        self.alert_mode = config.get(
            'telegram', 'alert_mode', fallback='verbose'
        ).strip().lower()
        if self.alert_mode not in ALERT_MODE_FALLBACK:
            logger.warning("Invalid alert_mode '{m}', falling back to 'verbose'".format(m=self.alert_mode))
            self.alert_mode = 'verbose'

        # Load [telegram.rules] from config
        self._config_rules = {}
        if config.has_section('telegram.rules'):
            for key, value in config.items('telegram.rules'):
                level = (value or '').strip().lower()
                if level in VALID_LEVELS:
                    self._config_rules[key.strip().lower()] = level
                else:
                    logger.warning(
                        "Invalid level '{v}' for rule '{k}' in [telegram.rules]; skipping".format(
                            v=value, k=key
                        )
                    )

        # Load runtime overrides from JSON (if present)
        self._runtime_overrides = self._load_state()

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------
    def route(self, rule, tier=0, severity='medium'):
        """Return the effective level for this event."""
        rule = (rule or 'block').strip().lower()

        # 1. Always-on operational signals
        if rule in ALWAYS_IMMEDIATE_RULES:
            return 'immediate'

        # 2. Any tier-3 block bypasses muting
        if tier >= 3:
            return 'immediate'

        # 3. Runtime overrides (from /verbosity chat command)
        with self._lock:
            if rule in self._runtime_overrides:
                return self._runtime_overrides[rule]

        # 4. Config [telegram.rules]
        if rule in self._config_rules:
            return self._config_rules[rule]

        # 5. Hardcoded defaults
        if rule in DEFAULTS:
            return DEFAULTS[rule]

        # 6. alert_mode fallback for unknown rules
        return ALERT_MODE_FALLBACK.get(self.alert_mode, 'immediate')

    # ------------------------------------------------------------------
    # Runtime overrides API (used by /verbosity Telegram command)
    # ------------------------------------------------------------------
    def set_override(self, rule, level):
        """Set a runtime override. Persisted to state JSON.
        Returns (ok, message) — ok=False if rule/level is invalid or muted-rule."""
        rule = (rule or '').strip().lower()
        level = (level or '').strip().lower()

        if level not in VALID_LEVELS:
            return False, "Invalid level '{l}'. Valid: immediate, digest, silent".format(l=level)
        if not rule:
            return False, "Rule name required"
        if rule in ALWAYS_IMMEDIATE_RULES and level != 'immediate':
            return False, (
                "Rule '{r}' is always-immediate by design (operational signal, "
                "cannot be muted)".format(r=rule)
            )

        with self._lock:
            self._runtime_overrides[rule] = level
            self._save_state_locked()
        logger.info("Verbosity override: {r} → {l}".format(r=rule, l=level))
        return True, "Set {r} → {l}".format(r=rule, l=level)

    def clear_override(self, rule):
        """Remove a single runtime override. Returns (ok, message)."""
        rule = (rule or '').strip().lower()
        with self._lock:
            if rule not in self._runtime_overrides:
                return False, "No runtime override for '{r}'".format(r=rule)
            del self._runtime_overrides[rule]
            self._save_state_locked()
        logger.info("Verbosity override cleared: {r}".format(r=rule))
        return True, "Cleared override for {r}".format(r=rule)

    def reset_all(self):
        """Wipe all runtime overrides — fall back to config + defaults."""
        with self._lock:
            self._runtime_overrides = {}
            self._save_state_locked()
        logger.info("All verbosity overrides reset")
        return True, "All runtime overrides cleared. Using config defaults."

    def current_map(self):
        """Return the full effective rule→level map plus the source for each.

        Used by /verbosity (no args) to show operator what's in effect.
        """
        rows = []
        all_rules = set(DEFAULTS.keys()) | set(self._config_rules.keys())
        with self._lock:
            all_rules |= set(self._runtime_overrides.keys())
            runtime_snapshot = dict(self._runtime_overrides)
        for rule in sorted(all_rules):
            if rule in runtime_snapshot:
                level = runtime_snapshot[rule]
                source = 'runtime'
            elif rule in self._config_rules:
                level = self._config_rules[rule]
                source = 'config'
            else:
                level = DEFAULTS.get(rule, ALERT_MODE_FALLBACK.get(self.alert_mode, 'immediate'))
                source = 'default'
            if rule in ALWAYS_IMMEDIATE_RULES:
                source = 'locked'
                level = 'immediate'
            rows.append((rule, level, source))
        return rows

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load_state(self):
        if not os.path.exists(self.state_path):
            return {}
        try:
            with open(self.state_path, 'r') as f:
                data = json.load(f)
            # Filter invalid entries out rather than fail-closed
            cleaned = {}
            for k, v in (data or {}).items():
                k = str(k).strip().lower()
                v = str(v).strip().lower()
                if v in VALID_LEVELS:
                    cleaned[k] = v
            return cleaned
        except Exception as e:
            logger.warning("Could not read {p}: {e}".format(p=self.state_path, e=e))
            return {}

    def _save_state_locked(self):
        """Persist overrides. Caller must hold self._lock."""
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            tmp = self.state_path + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(self._runtime_overrides, f, indent=2, sort_keys=True)
            os.replace(tmp, self.state_path)
        except Exception as e:
            logger.error("Could not write {p}: {e}".format(p=self.state_path, e=e))
