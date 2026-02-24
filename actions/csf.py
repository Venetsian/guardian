"""
WP-Guardian CSF Module
Fallback blocker using ConfigServer Firewall.
Used when MikroTik SSH is unavailable.
"""

import subprocess
import logging
import time

logger = logging.getLogger('wp-guardian.csf')


class CSFBlocker:
    def __init__(self, config):
        self.enabled = config.getboolean('csf', 'enabled', fallback=True)

        if self.enabled:
            self._check_csf()

    def _check_csf(self):
        """Verify CSF is installed and accessible."""
        try:
            result = subprocess.run(['csf', '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True, timeout=5)
            if result.returncode == 0:
                logger.info(f"CSF available: {result.stdout.strip()}")
            else:
                logger.warning("CSF command failed — disabling CSF fallback")
                self.enabled = False
        except FileNotFoundError:
            logger.warning("CSF not found — disabling CSF fallback")
            self.enabled = False
        except Exception as e:
            logger.warning(f"CSF check error: {e} — disabling CSF fallback")
            self.enabled = False

    def block(self, ip, reason, service='web'):
        """Block an IP via CSF."""
        if not self.enabled:
            return False

        timestamp = time.strftime('%Y-%m-%d %H:%M')
        comment = f"WPG-{service}: {reason} [{timestamp}]"

        try:
            result = subprocess.run(
                ['csf', '-d', ip, comment],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=10
            )

            if result.returncode == 0:
                logger.info(f"CSF BLOCKED {ip} reason={reason}")
                return True
            else:
                # CSF returns non-zero if IP is already blocked — that's fine
                if 'already exists' in result.stderr.lower() or 'already exists' in result.stdout.lower():
                    logger.debug(f"CSF: {ip} already blocked")
                    return True
                logger.error(f"CSF block failed for {ip}: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"CSF timeout blocking {ip}")
            return False
        except Exception as e:
            logger.error(f"CSF exception blocking {ip}: {e}")
            return False

    def unblock(self, ip):
        """Remove an IP from CSF deny list."""
        if not self.enabled:
            return False

        try:
            result = subprocess.run(
                ['csf', '-dr', ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=10
            )

            if result.returncode == 0:
                logger.info(f"CSF UNBLOCKED {ip}")
                return True
            else:
                logger.error(f"CSF unblock failed for {ip}: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"CSF exception unblocking {ip}: {e}")
            return False
