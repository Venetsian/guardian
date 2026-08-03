"""
WP-Guardian Configuration Module
Loads and parses the INI config file.
"""

import configparser
import os
import re
import logging

logger = logging.getLogger('wp-guardian.config')

DEFAULT_CONFIG_PATH = '/opt/wp-guardian/wp-guardian.conf'


def parse_duration(value):
    """Convert duration string (e.g., '24h', '7d', '30d') to seconds."""
    if isinstance(value, (int, float)):
        return int(value)

    value = str(value).strip().lower()
    match = re.match(r'^(\d+)\s*(s|m|h|d|w)$', value)

    if not match:
        raise ValueError(f"Invalid duration format: {value} (use e.g., 24h, 7d, 30d)")

    amount = int(match.group(1))
    unit = match.group(2)

    multipliers = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
    return amount * multipliers[unit]


def parse_asn_list(raw):
    """Parse a comma/newline separated list of integer ASNs into a set.

    Shared by DistributedAuthDetector (detection-side filtering) and
    Blocker (enforcement-side exemption) so both read the same
    [compromise_detection] trusted_asns value the same way.

    Ignores blank entries, '#' comments (whole-line or inline) and
    non-positive values. Invalid tokens are warned about, not fatal.
    """
    asns = set()
    if not raw:
        return asns

    for token in str(raw).replace('\n', ',').split(','):
        token = token.strip()
        if not token or token.startswith('#'):
            continue
        if '#' in token:
            token = token[:token.index('#')].strip()
        if not token:
            continue
        try:
            value = int(token)
        except ValueError:
            logger.warning(f"Invalid trusted_asns entry '{token}' — must be an integer ASN")
            continue
        if value > 0:
            asns.add(value)

    return asns


def parse_service_list(raw):
    """Parse a comma/newline separated list of service names into a set.

    Lowercased and stripped. Used for [compromise_detection]
    trusted_asn_services.
    """
    services = set()
    if not raw:
        return services

    for token in str(raw).replace('\n', ',').split(','):
        token = token.strip()
        if not token or token.startswith('#'):
            continue
        if '#' in token:
            token = token[:token.index('#')].strip()
        if token:
            services.add(token.lower())

    return services


def load_config(config_path=None):
    """Load configuration from INI file."""
    # Try multiple locations: explicit path, script dir, default
    if config_path:
        path = config_path
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.dirname(script_dir)  # Parent of modules/
        candidates = [
            os.path.join(project_dir, 'wp-guardian.conf'),
            DEFAULT_CONFIG_PATH,
        ]
        path = DEFAULT_CONFIG_PATH
        for candidate in candidates:
            if os.path.exists(candidate):
                path = candidate
                break

    config = configparser.ConfigParser()

    if os.path.exists(path):
        config.read(path)
        logger.info(f"Configuration loaded from {path}")

        # Security check: warn if config is readable by group/others
        try:
            stat_info = os.stat(path)
            mode = stat_info.st_mode
            if mode & 0o077:
                logger.warning(
                    f"Config file {path} is readable by group/others. "
                    f"It may contain API tokens. Run: chmod 600 {path}"
                )
        except OSError:
            pass
    else:
        logger.warning(f"Config file not found: {path} — using defaults")

    return config


def load_whitelist_file(filepath):
    """Load IPs from whitelist file."""
    ips = set()

    if not os.path.exists(filepath):
        logger.warning(f"Whitelist file not found: {filepath}")
        return ips

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                # Strip inline comments (e.g., "1.2.3.4 # my office")
                if '#' in line:
                    line = line[:line.index('#')].strip()
                if line:
                    ips.add(line)

    logger.info(f"Loaded {len(ips)} entries from whitelist file")
    return ips


def load_tripwire_file(filepath):
    """Load tripwire paths from file."""
    paths = set()

    if not os.path.exists(filepath):
        logger.warning(f"Tripwire file not found: {filepath}")
        return paths

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                # Strip inline comments
                if '#' in line:
                    line = line[:line.index('#')].strip()
                if line:
                    paths.add(line.lower())

    logger.info(f"Loaded {len(paths)} tripwire paths from file")
    return paths
