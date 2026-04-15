"""
WP-Guardian Mail Backend Module (v1.4+)

Thin wrapper around the mail server's MariaDB to enable/disable
individual mailboxes. Completely separate from Guardian's own SQLite DB.

v1.4 ships only the generic `mariadb_virtual_users` type, which fits
Postfixadmin/Mailcow-style schemas where there's a table with an
email column and an integer enabled column. Column names are
configurable.

The operator must create a least-privilege SQL user ahead of time:

    CREATE USER 'wp_guardian'@'localhost' IDENTIFIED BY '...';
    GRANT SELECT (email, enabled), UPDATE (enabled)
      ON mailserver.virtual_users TO 'wp_guardian'@'localhost';
    FLUSH PRIVILEGES;
"""

import logging

logger = logging.getLogger('wp-guardian.mail_backend')


class MailBackend:
    def __init__(self, config):
        self.type = config.get('mail_backend', 'type', fallback='none').strip().lower()
        self.enabled = False
        self._pymysql = None

        if self.type == 'none' or self.type == '':
            logger.debug("Mail backend disabled (type=none)")
            return

        if self.type != 'mariadb_virtual_users':
            logger.error("Unsupported mail_backend type: {t}".format(t=self.type))
            return

        try:
            import pymysql  # lazy import — only needed when enabled
            self._pymysql = pymysql
        except ImportError:
            logger.error(
                "mail_backend enabled but 'PyMySQL' not installed. "
                "Run: pip install PyMySQL"
            )
            return

        self.host = config.get('mail_backend', 'host', fallback='127.0.0.1')
        self.port = config.getint('mail_backend', 'port', fallback=3306)
        self.database = config.get('mail_backend', 'database', fallback='mailserver')
        self.user = config.get('mail_backend', 'user', fallback='wp_guardian')
        self.password = config.get('mail_backend', 'password', fallback='')
        self.table = self._sanitize_ident(
            config.get('mail_backend', 'table', fallback='virtual_users')
        )
        self.email_col = self._sanitize_ident(
            config.get('mail_backend', 'email_column', fallback='email')
        )
        self.enabled_col = self._sanitize_ident(
            config.get('mail_backend', 'enabled_column', fallback='enabled')
        )

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
        logger.info("MailBackend connected to {db}.{tbl}".format(
            db=self.database, tbl=self.table
        ))

    @staticmethod
    def _sanitize_ident(name):
        """Strip anything that isn't safe for an unquoted identifier.
        The table and column names come from config, not user input, but
        this is still cheap defence-in-depth — prevents a typo-in-config
        from smuggling SQL into the statement.
        """
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

    def disable_mailbox(self, email):
        """Set enabled=0 on a mailbox row. Returns True if a row changed."""
        if not self.enabled:
            raise RuntimeError("MailBackend is not enabled")

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

    def enable_mailbox(self, email):
        """Set enabled=1 on a mailbox row. Returns True if a row changed."""
        if not self.enabled:
            raise RuntimeError("MailBackend is not enabled")

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

    def is_enabled(self, email):
        """Return True/False/None (None = email not found)."""
        if not self.enabled:
            return None

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
