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
            logger.error("Unsupported mail_backend type: {t}. "
                         "Available: {r}".format(
                             t=self.type,
                             r=', '.join(sorted(RECIPES.keys()))))
            return

        # Resolve config: recipe defaults, then explicit config overrides
        self.disable_strategy = recipe.get('disable_strategy', 'toggle_enabled')

        try:
            import pymysql  # lazy import — only needed when enabled
            self._pymysql = pymysql
        except ImportError:
            logger.error(
                "mail_backend enabled but 'PyMySQL' not installed. "
                "Run: pip install PyMySQL"
            )
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
                logger.error(
                    "password_reset strategy requires guardian_db for storing "
                    "original password hashes. Pass guardian_db to MailBackend()."
                )
                return
        else:
            logger.error("Unknown disable_strategy: {s}".format(s=self.disable_strategy))
            return

        try:
            self._test_connection()
        except Exception as e:
            logger.error("MailBackend startup test failed: {e}".format(e=e))
            logger.error(
                "Compromise mailbox-disable action will be unavailable. "
                "Guardian will still block source IPs and send alerts."
            )
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
