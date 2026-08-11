"""
WP-Guardian Mail Backend Module (v1.4+)

Thin wrapper around the mail server's MariaDB to enable/disable
individual mailboxes. Completely separate from Guardian's own SQLite DB.

Supports multiple mail server types via RECIPES:
  - cyberpanel          CyberPanel (password_reset strategy)
  - postfixadmin        Postfixadmin (toggle_enabled strategy)
  - mailcow             Mailcow (toggle_enabled strategy)
  - iredmail            iRedMail (toggle_enabled strategy)
  - custom              Manual config (toggle_enabled strategy)

Two disable strategies:
  - toggle_enabled:  SET enabled=0 / enabled=1 (classic approach)
  - password_reset:  Scramble password to lock account, store original
                     hash in Guardian's DB so it can be restored.

The operator must create a least-privilege SQL user ahead of time.
Required privileges differ by strategy:

  toggle_enabled:
    GRANT SELECT (email, enabled), UPDATE (enabled)
      ON mailserver.virtual_users TO 'wp_guardian'@'localhost';

  password_reset:
    GRANT SELECT (email, password), UPDATE (password)
      ON cyberpanel.e_users TO 'wp_guardian'@'localhost';

Substitute your own database/table/column names — the ones above are the
defaults for two common layouts, not a fixed requirement. Whatever you set in
[mail_backend] is what needs granting.

OPTIONAL — forwarding-injection check (read-only):

  Guardian can read your alias/forwarding table to detect a mailbox rule
  planted on a compromised account. Mailbox-rule injection is the standard
  BEC follow-on and it happens during the reconnaissance phase, days before
  any spam is sent, so it is worth far more as evidence than outbound volume
  alone. Requires SELECT on the alias table:

    GRANT SELECT (<source_col>, <destination_col>, <created_col>)
      ON <database>.<alias_table> TO 'wp_guardian'@'localhost';

  The table name is NOT standardised across mail stacks. Verify against your
  own schema (`SHOW TABLES`, `DESCRIBE`) before granting. Layouts seen in the
  wild:

    postfix+dovecot MySQL   virtual_aliases (source, destination, created_at)
    postfixadmin / mailcow  alias           (address, goto)
    iRedMail                forwardings     (address, forwarding)

  Guardian NEVER needs UPDATE or DELETE on this table. It reads forwarding
  rules to spot tampering; it does not modify mail routing. Do not grant
  write access here even if your DB user already has it elsewhere.

  The check is entirely optional: leave it unconfigured and Guardian skips it.
  A missing grant degrades to a logged warning, never an error.
"""

import crypt
import logging
import os
import string

logger = logging.getLogger('wp-guardian.mail_backend')


# ---------------------------------------------------------------------------
# Recipe registry
# ---------------------------------------------------------------------------
RECIPES = {
    'cyberpanel': {
        'label': 'CyberPanel',
        'database': 'cyberpanel',
        'table': 'e_users',
        'email_column': 'email',
        'disable_strategy': 'password_reset',
        'password_column': 'password',
    },
    'postfixadmin': {
        'label': 'Postfixadmin',
        'database': 'postfixadmin',
        'table': 'mailbox',
        'email_column': 'username',
        'disable_strategy': 'toggle_enabled',
        'enabled_column': 'active',
    },
    'mailcow': {
        'label': 'Mailcow',
        'database': 'mailcow',
        'table': 'mailbox',
        'email_column': 'username',
        'disable_strategy': 'toggle_enabled',
        'enabled_column': 'active',
    },
    'iredmail': {
        'label': 'iRedMail',
        'database': 'vmail',
        'table': 'mailbox',
        'email_column': 'username',
        'disable_strategy': 'toggle_enabled',
        'enabled_column': 'active',
    },
    'custom': {
        'label': 'Custom (specify all columns)',
        'database': 'mailserver',
        'table': 'virtual_users',
        'email_column': 'email',
        'disable_strategy': 'toggle_enabled',
        'enabled_column': 'enabled',
    },
}


def get_recipes():
    """Return the recipe registry (for wizards/installers)."""
    return RECIPES


# ---------------------------------------------------------------------------
# Password hashing helper
# ---------------------------------------------------------------------------
def _generate_locked_hash():
    """Generate a SHA-512 crypt hash of a random password.

    Uses os.urandom + crypt.crypt (stdlib, Python 3.6 compatible).
    The result is a valid {CRYPT} hash that Dovecot/Postfix accept but
    that no one knows the plaintext for — effectively locking the account.
    """
    # Generate a random 32-char password
    charset = string.ascii_letters + string.digits + string.punctuation
    random_bytes = os.urandom(32)
    random_pw = ''.join(charset[b % len(charset)] for b in random_bytes)

    # Generate a random 16-char salt for SHA-512
    salt_bytes = os.urandom(16)
    salt_chars = string.ascii_letters + string.digits + './'
    salt = ''.join(salt_chars[b % len(salt_chars)] for b in salt_bytes)

    # crypt.crypt with $6$ prefix = SHA-512
    hashed = crypt.crypt(random_pw, '$6${s}$'.format(s=salt))
    return hashed


# ---------------------------------------------------------------------------
# MailBackend
# ---------------------------------------------------------------------------
class MailBackend:
    def __init__(self, config, guardian_db=None):
        """Initialize the mail backend.

        Args:
            config: ConfigParser instance with [mail_backend] section
            guardian_db: GuardianDB instance for storing/retrieving password
                         hashes when using password_reset strategy. Required
                         for password_reset, ignored for toggle_enabled.
        """
        self.type = config.get('mail_backend', 'type', fallback='none').strip().lower()
        self.enabled = False
        self.init_error = None  # stores the reason if init fails
        self._pymysql = None
        self._guardian_db = guardian_db

        if self.type == 'none' or self.type == '':
            logger.debug("Mail backend disabled (type=none)")
            return

        # Backward compatibility: mariadb_virtual_users → custom
        if self.type == 'mariadb_virtual_users':
            logger.info(
                "mail_backend type 'mariadb_virtual_users' is deprecated. "
                "Use 'custom' instead (same behavior). "
                "See wp-guardian.conf.example for recipe options."
            )
            self.type = 'custom'

        # Load recipe or reject unknown type
        if self.type in RECIPES:
            recipe = RECIPES[self.type]
        else:
            msg = "Unsupported mail_backend type: {t}. Available: {r}".format(
                t=self.type, r=', '.join(sorted(RECIPES.keys())))
            logger.error(msg)
            self.init_error = msg
            return

        # Resolve config: recipe defaults, then explicit config overrides
        self.disable_strategy = recipe.get('disable_strategy', 'toggle_enabled')

        try:
            import pymysql  # lazy import — only needed when enabled
            self._pymysql = pymysql
        except ImportError:
            msg = ("mail_backend type={t} requires PyMySQL. "
                   "Install: pip3 install PyMySQL").format(t=self.type)
            logger.error(msg)
            self.init_error = msg
            return

        self.host = self._config_or_recipe(config, 'host', recipe, '127.0.0.1')
        self.port = config.getint('mail_backend', 'port', fallback=3306)
        self.database = self._config_or_recipe(config, 'database', recipe, 'mailserver')
        self.user = self._config_or_recipe(config, 'user', recipe, 'wp_guardian')
        self.password = config.get('mail_backend', 'password', fallback='')
        self.table = self._sanitize_ident(
            self._config_or_recipe(config, 'table', recipe, 'virtual_users')
        )
        self.email_col = self._sanitize_ident(
            self._config_or_recipe(config, 'email_column', recipe, 'email')
        )

        # Strategy-specific columns
        if self.disable_strategy == 'toggle_enabled':
            self.enabled_col = self._sanitize_ident(
                self._config_or_recipe(config, 'enabled_column', recipe, 'enabled')
            )
            self.password_col = None
        elif self.disable_strategy == 'password_reset':
            self.enabled_col = None
            self.password_col = self._sanitize_ident(
                self._config_or_recipe(config, 'password_column', recipe, 'password')
            )
            if not self._guardian_db:
                msg = ("password_reset strategy requires guardian_db for storing "
                       "original password hashes. This is a bug — report it.")
                logger.error(msg)
                self.init_error = msg
                return
        else:
            logger.error("Unknown disable_strategy: {s}".format(s=self.disable_strategy))
            return

        # --- optional: alias / forwarding table (read-only) ---------------
        # Used by the compromise corroboration check to spot a forwarding rule
        # planted on a hijacked mailbox. Entirely opt-in: no alias_table
        # configured means the check is skipped, not that it failed.
        self.alias_table = ''
        self.alias_source_col = ''
        self.alias_dest_col = ''
        self.alias_created_col = ''
        self._alias_warned = False
        alias_table = config.get('mail_backend', 'alias_table', fallback='').strip()
        if alias_table:
            try:
                self.alias_table = self._sanitize_ident(alias_table)
                self.alias_source_col = self._sanitize_ident(
                    config.get('mail_backend', 'alias_source_column',
                               fallback='source'))
                self.alias_dest_col = self._sanitize_ident(
                    config.get('mail_backend', 'alias_destination_column',
                               fallback='destination'))
                created = config.get('mail_backend', 'alias_created_column',
                                     fallback='').strip()
                self.alias_created_col = self._sanitize_ident(created) if created else ''
            except ValueError as e:
                logger.error(
                    "Invalid alias column config, forwarding check disabled: {e}".format(e=e)
                )
                self.alias_table = ''

        try:
            self._test_connection()
        except Exception as e:
            msg = "MailBackend connection failed: {e}".format(e=e)
            logger.error(msg)
            logger.error(
                "Compromise mailbox-disable action will be unavailable. "
                "Guardian will still block source IPs and send alerts."
            )
            self.init_error = msg
            return

        self.enabled = True
        logger.info("MailBackend [{t}] connected to {db}.{tbl} (strategy={s})".format(
            t=self.type, db=self.database, tbl=self.table, s=self.disable_strategy
        ))

    @staticmethod
    def _config_or_recipe(config, key, recipe, default):
        """Return explicit config value if set and non-empty, else recipe default."""
        val = config.get('mail_backend', key, fallback='').strip()
        if val:
            return val
        return recipe.get(key, default)

    @staticmethod
    def _sanitize_ident(name):
        """Strip anything that isn't safe for an unquoted identifier."""
        safe = ''.join(ch for ch in (name or '') if ch.isalnum() or ch == '_')
        if not safe:
            raise ValueError("empty/invalid identifier: {n}".format(n=name))
        return safe

    def _connect(self):
        return self._pymysql.connect(
            host=self.host,
            port=self.port,
            user=self.user,
            password=self.password,
            database=self.database,
            autocommit=False,
            connect_timeout=5,
            charset='utf8mb4',
        )

    def _test_connection(self):
        conn = self._connect()
        try:
            cur = conn.cursor()
            try:
                cur.execute("SELECT COUNT(*) FROM {tbl} LIMIT 1".format(tbl=self.table))
                cur.fetchone()
            finally:
                cur.close()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Disable / Enable
    # ------------------------------------------------------------------

    def disable_mailbox(self, email):
        """Disable a mailbox. Returns True if a row changed."""
        if not self.enabled:
            raise RuntimeError("MailBackend is not enabled")

        if self.disable_strategy == 'password_reset':
            return self._disable_via_password_reset(email)
        else:
            return self._disable_via_toggle(email)

    def enable_mailbox(self, email):
        """Re-enable a mailbox. Returns True if a row changed."""
        if not self.enabled:
            raise RuntimeError("MailBackend is not enabled")

        if self.disable_strategy == 'password_reset':
            return self._enable_via_password_restore(email)
        else:
            return self._enable_via_toggle(email)

    def is_enabled(self, email):
        """Return True/False/None (None = email not found)."""
        if not self.enabled:
            return None

        if self.disable_strategy == 'password_reset':
            return self._is_enabled_password_check(email)
        else:
            return self._is_enabled_toggle_check(email)

    # ------------------------------------------------------------------
    # Alias / forwarding inspection (read-only, optional)
    # ------------------------------------------------------------------

    @property
    def alias_check_available(self):
        return bool(self.enabled and self.alias_table)

    def recent_aliases(self, email, since_ts=None):
        """Forwarding rules pointing away from this mailbox.

        Returns a list of {'destination': str, 'created_at': int|None}, or
        **None** when the check could not run (not configured, missing GRANT,
        DB unreachable). None and [] mean opposite things to the caller: []
        is evidence of absence, None is absence of evidence, and a corroboration
        check must never treat the second as the first.

        `since_ts` filters on the created column when one is configured. Without
        it every existing rule looks freshly planted, so when no created column
        exists the filter is dropped and the caller is told via created_at=None.
        """
        if not self.alias_check_available:
            return None

        cols = [self.alias_dest_col]
        if self.alias_created_col:
            cols.append(self.alias_created_col)

        sql = "SELECT {c} FROM {t} WHERE {s} = %s".format(
            c=', '.join('`{x}`'.format(x=c) for c in cols),
            t=self.alias_table, s=self.alias_source_col
        )
        params = [email]
        if self.alias_created_col and since_ts is not None:
            sql += " AND `{c}` >= FROM_UNIXTIME(%s)".format(c=self.alias_created_col)
            params.append(int(since_ts))

        try:
            conn = self._connect()
        except Exception as e:
            self._warn_alias_once("cannot connect: {e}".format(e=e))
            return None

        try:
            cur = conn.cursor()
            try:
                cur.execute(sql, tuple(params))
                rows = cur.fetchall()
            finally:
                cur.close()
        except Exception as e:
            # Almost always a missing GRANT on the alias table. Warn once —
            # the corroboration path runs on every compromise event and a
            # per-event error would drown the log.
            self._warn_alias_once(str(e))
            return None
        finally:
            try:
                conn.close()
            except Exception:
                pass

        out = []
        for row in rows:
            created = None
            if self.alias_created_col and len(row) > 1 and row[1] is not None:
                created = row[1]
            out.append({'destination': row[0], 'created_at': created})
        return out

    def _warn_alias_once(self, detail):
        if self._alias_warned:
            logger.debug("alias check unavailable: {d}".format(d=detail))
            return
        self._alias_warned = True
        logger.warning(
            "Forwarding-injection check unavailable on {db}.{tbl}: {d} — "
            "the mailbox GRANT does not cover this table. Add: "
            "GRANT SELECT ON {db}.{tbl} TO '<guardian user>'@'localhost'. "
            "Compromise detection continues without this signal.".format(
                db=self.database, tbl=self.alias_table, d=detail
            )
        )

    # ------------------------------------------------------------------
    # toggle_enabled strategy (Postfixadmin, Mailcow, iRedMail, custom)
    # ------------------------------------------------------------------

    def _disable_via_toggle(self, email):
        conn = self._connect()
        try:
            cur = conn.cursor()
            try:
                sql = (
                    "UPDATE {tbl} SET {en} = 0 "
                    "WHERE {em} = %s AND {en} = 1"
                ).format(tbl=self.table, en=self.enabled_col, em=self.email_col)
                cur.execute(sql, (email,))
                rows = cur.rowcount
                conn.commit()
                return rows > 0
            finally:
                cur.close()
        finally:
            conn.close()

    def _enable_via_toggle(self, email):
        conn = self._connect()
        try:
            cur = conn.cursor()
            try:
                sql = (
                    "UPDATE {tbl} SET {en} = 1 "
                    "WHERE {em} = %s AND {en} = 0"
                ).format(tbl=self.table, en=self.enabled_col, em=self.email_col)
                cur.execute(sql, (email,))
                rows = cur.rowcount
                conn.commit()
                return rows > 0
            finally:
                cur.close()
        finally:
            conn.close()

    def _is_enabled_toggle_check(self, email):
        conn = self._connect()
        try:
            cur = conn.cursor()
            try:
                sql = (
                    "SELECT {en} FROM {tbl} WHERE {em} = %s"
                ).format(tbl=self.table, en=self.enabled_col, em=self.email_col)
                cur.execute(sql, (email,))
                row = cur.fetchone()
                if row is None:
                    return None
                return bool(row[0])
            finally:
                cur.close()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # password_reset strategy (CyberPanel)
    # ------------------------------------------------------------------

    def _disable_via_password_reset(self, email):
        """Scramble password to lock account. Store original hash for restore."""
        conn = self._connect()
        try:
            cur = conn.cursor()
            try:
                # 1. Read current password hash
                sql = "SELECT {pw} FROM {tbl} WHERE {em} = %s".format(
                    pw=self.password_col, tbl=self.table, em=self.email_col
                )
                cur.execute(sql, (email,))
                row = cur.fetchone()
                if row is None:
                    logger.warning("Mailbox not found: {e}".format(e=email))
                    return False
                original_hash = row[0]

                # 2. Generate a locked replacement hash
                locked_hash = _generate_locked_hash()

                # 3. Update the mail DB
                sql = "UPDATE {tbl} SET {pw} = %s WHERE {em} = %s".format(
                    tbl=self.table, pw=self.password_col, em=self.email_col
                )
                cur.execute(sql, (locked_hash, email))
                rows = cur.rowcount
                conn.commit()

                if rows > 0:
                    # 4. Store original hash in Guardian's DB for later restore
                    self._guardian_db.insert_mailbox_action(
                        username=email,
                        action='password_reset_disable',
                        actor='mail_backend',
                        reason='password scrambled for lockout',
                        original_password_hash=original_hash,
                    )
                    logger.info("Mailbox locked via password reset: {e}".format(e=email))

                return rows > 0
            finally:
                cur.close()
        finally:
            conn.close()

    def _enable_via_password_restore(self, email):
        """Restore original password hash from Guardian's DB."""
        # Find the most recent password_reset_disable action with a stored hash
        original_hash = self._guardian_db.get_original_password_hash(email)
        if not original_hash:
            logger.error(
                "Cannot restore mailbox {e}: no original password hash found. "
                "The user will need to reset their password manually.".format(e=email)
            )
            return False

        conn = self._connect()
        try:
            cur = conn.cursor()
            try:
                sql = "UPDATE {tbl} SET {pw} = %s WHERE {em} = %s".format(
                    tbl=self.table, pw=self.password_col, em=self.email_col
                )
                cur.execute(sql, (original_hash, email))
                rows = cur.rowcount
                conn.commit()

                if rows > 0:
                    # Record the restore action
                    self._guardian_db.insert_mailbox_action(
                        username=email,
                        action='password_restore_enable',
                        actor='mail_backend',
                        reason='original password restored',
                    )
                    logger.info("Mailbox restored via password restore: {e}".format(e=email))

                return rows > 0
            finally:
                cur.close()
        finally:
            conn.close()

    def _is_enabled_password_check(self, email):
        """Check if the mailbox exists. For password_reset strategy,
        check Guardian's DB for an unrestored disable action."""
        # First check if the email exists at all
        conn = self._connect()
        try:
            cur = conn.cursor()
            try:
                sql = "SELECT 1 FROM {tbl} WHERE {em} = %s".format(
                    tbl=self.table, em=self.email_col
                )
                cur.execute(sql, (email,))
                if cur.fetchone() is None:
                    return None  # email not found
            finally:
                cur.close()
        finally:
            conn.close()

        # Check if there's an unrestored disable action
        original_hash = self._guardian_db.get_original_password_hash(email)
        if original_hash:
            return False  # disabled (has unreversed password reset)
        return True  # enabled (no pending password reset)
