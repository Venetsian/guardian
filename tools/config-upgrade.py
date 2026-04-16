#!/usr/bin/env python3
"""
WP-Guardian Config Upgrade Tool

Compares wp-guardian.conf against wp-guardian.conf.example, shows what's new,
and optionally runs an interactive wizard to configure new options.

Usage:
    python3 tools/config-upgrade.py                # Interactive wizard
    python3 tools/config-upgrade.py --auto         # Add defaults silently
    python3 tools/config-upgrade.py --diff-only    # Show diff, don't change anything

Python 3.6 compatible.
"""
from __future__ import print_function

import argparse
import os
import re
import shutil
import sys
import getpass

# Python 3.6: configparser is available
try:
    import configparser
except ImportError:
    import ConfigParser as configparser


# ---------------------------------------------------------------------------
# Colors (ANSI)
# ---------------------------------------------------------------------------
BOLD = '\033[1m'
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
NC = '\033[0m'


def print_header():
    print('')
    print('{b}============================================{n}'.format(b=BOLD, n=NC))
    print('{b}  WP-Guardian Config Upgrade{n}'.format(b=BOLD, n=NC))
    print('{b}============================================{n}'.format(b=BOLD, n=NC))
    print('')


def print_step(msg):
    print('{c}[*]{n} {m}'.format(c=CYAN, n=NC, m=msg))


def print_ok(msg):
    print('{g}[+]{n} {m}'.format(g=GREEN, n=NC, m=msg))


def print_warn(msg):
    print('{y}[!]{n} {m}'.format(y=YELLOW, n=NC, m=msg))


def print_err(msg):
    print('{r}[-]{n} {m}'.format(r=RED, n=NC, m=msg))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def ask(prompt, default=''):
    """Prompt user for input with a default value."""
    if default:
        full = '{p} [{d}]: '.format(p=prompt, d=default)
    else:
        full = '{p}: '.format(p=prompt)
    try:
        answer = input(full).strip()
    except (EOFError, KeyboardInterrupt):
        print('')
        return default
    return answer if answer else default


def ask_yn(prompt, default='n'):
    """Yes/no prompt. Returns True for yes."""
    if default.lower() == 'y':
        full = '{p} [Y/n]: '.format(p=prompt)
    else:
        full = '{p} [y/N]: '.format(p=prompt)
    try:
        answer = input(full).strip()
    except (EOFError, KeyboardInterrupt):
        print('')
        answer = default
    answer = answer or default
    return answer.lower().startswith('y')


def ask_password(prompt):
    """Prompt for a password without echoing."""
    try:
        pw = getpass.getpass(prompt + ': ')
    except (EOFError, KeyboardInterrupt):
        print('')
        pw = ''
    return pw


# ---------------------------------------------------------------------------
# Config parsing (preserving comments)
# ---------------------------------------------------------------------------
class CommentPreservingConfig(object):
    """
    Parse INI files while preserving comments and structure.

    configparser strips comments. We need to:
    1. Use configparser to get section/key data for comparison
    2. Work with raw file lines for merging
    """

    def __init__(self, path):
        self.path = path
        self.parser = configparser.ConfigParser(allow_no_value=True)
        self.parser.optionxform = str  # preserve case
        if os.path.exists(path):
            self.parser.read(path)
        self.lines = []
        if os.path.exists(path):
            with open(path, 'r') as f:
                self.lines = f.readlines()

    def sections(self):
        return self.parser.sections()

    def has_section(self, section):
        return self.parser.has_section(section)

    def has_option(self, section, key):
        return self.parser.has_option(section, key)

    def get(self, section, key, fallback=None):
        try:
            return self.parser.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback

    def options(self, section):
        try:
            return self.parser.options(section)
        except configparser.NoSectionError:
            return []


def extract_section_block(lines, section_name):
    """
    Extract the raw text block for a section from a file's lines,
    including leading comments that belong to it.

    Returns the block as a string, or '' if not found.
    """
    in_section = False
    block_lines = []
    comment_buffer = []

    for line in lines:
        stripped = line.strip()

        # Detect section headers
        if stripped.startswith('[') and ']' in stripped:
            header = stripped.split(']')[0].lstrip('[').strip()
            if header == section_name:
                # Include accumulated comments before this header
                block_lines.extend(comment_buffer)
                block_lines.append(line)
                in_section = True
                comment_buffer = []
                continue
            elif in_section:
                # We've hit the next section — stop
                break
            else:
                comment_buffer = []
                continue

        if in_section:
            block_lines.append(line)
        else:
            # Accumulate comments/blanks before sections
            if stripped == '' or stripped.startswith('#'):
                comment_buffer.append(line)
            else:
                comment_buffer = []

    return ''.join(block_lines)


def extract_key_lines(lines, section_name, key_name):
    """
    Extract the comment + key=value lines for a specific key within a section.
    Returns the block as a string.
    """
    in_section = False
    comment_buffer = []
    result = []

    for line in lines:
        stripped = line.strip()

        if stripped.startswith('[') and ']' in stripped:
            header = stripped.split(']')[0].lstrip('[').strip()
            if header == section_name:
                in_section = True
                comment_buffer = []
                continue
            elif in_section:
                break
            continue

        if not in_section:
            continue

        # Inside our section
        if stripped == '' or stripped.startswith('#'):
            comment_buffer.append(line)
        else:
            # This is a key = value line
            eq_pos = stripped.find('=')
            if eq_pos > 0:
                file_key = stripped[:eq_pos].strip()
                if file_key == key_name:
                    result.extend(comment_buffer)
                    result.append(line)
                    comment_buffer = []
                    return ''.join(result)
            comment_buffer = []

    return ''


# ---------------------------------------------------------------------------
# Changelog "What's New" extractor
# ---------------------------------------------------------------------------
def extract_whats_new(base_dir):
    """Extract the latest version entry from CHANGELOG.md."""
    changelog = os.path.join(base_dir, 'CHANGELOG.md')
    if not os.path.exists(changelog):
        return None, None

    with open(changelog, 'r') as f:
        content = f.read()

    # Find the first ## v... heading
    match = re.search(r'^## (v\S+.*?)$', content, re.MULTILINE)
    if not match:
        return None, None

    version_line = match.group(1)
    start = match.end()

    # Find the next ## v... heading (or end of file)
    next_match = re.search(r'^## v', content[start:], re.MULTILINE)
    if next_match:
        body = content[start:start + next_match.start()].strip()
    else:
        body = content[start:].strip()

    return version_line, body


def show_whats_new(base_dir):
    """Display what's new in a compact banner."""
    version_line, body = extract_whats_new(base_dir)
    if not version_line:
        return

    print('')
    print('{b}  What\'s New: {v}{n}'.format(b=BOLD, v=version_line, n=NC))
    print('  ' + '-' * 50)

    # Extract headline (first non-empty line after version)
    if body:
        first_line = body.split('\n')[0].strip()
        if first_line:
            print('  {}'.format(first_line))

    # Extract "New config" section if present
    config_match = re.search(r'### New config\s*\n(.*?)(?=\n###|\Z)', body,
                             re.DOTALL)
    if config_match:
        print('')
        print('  {b}New config sections:{n}'.format(b=BOLD, n=NC))
        for line in config_match.group(1).strip().split('\n'):
            line = line.strip()
            if line.startswith('-'):
                print('    {}'.format(line))

    print('')


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------
# Backend-specific sections — only relevant if that backend is active
BACKEND_SECTIONS = {
    'mikrotik': 'mikrotik',
    'csf': 'csf',
    'firewalld': 'firewalld',
    'nftables': 'nftables',
    'pfsense': 'pfsense',
    'opnsense': 'pfsense',  # opnsense uses [pfsense] section
}

# All backend section names
ALL_BACKEND_SECTIONS = set(BACKEND_SECTIONS.values())


def find_missing(example_conf, live_conf):
    """
    Compare example vs live config.
    Returns:
        missing_sections: list of section names entirely missing
        missing_keys: dict of {section: [key, ...]} for partially missing
    """
    missing_sections = []
    missing_keys = {}

    # Determine which backend is configured
    active_backend = live_conf.get('firewall', 'backend', fallback='csf')
    active_backend_section = BACKEND_SECTIONS.get(active_backend, active_backend)

    for section in example_conf.sections():
        # Skip backend sections that don't match the active backend
        if section in ALL_BACKEND_SECTIONS and section != active_backend_section:
            continue

        if not live_conf.has_section(section):
            missing_sections.append(section)
            continue

        # Section exists — check for missing keys
        for key in example_conf.options(section):
            if not live_conf.has_option(section, key):
                if section not in missing_keys:
                    missing_keys[section] = []
                missing_keys[section].append(key)

    return missing_sections, missing_keys


def print_diff(missing_sections, missing_keys):
    """Print a human-readable diff summary."""
    if not missing_sections and not missing_keys:
        print_ok('Config is up to date — no missing options.')
        return False

    print_warn('Missing config options found:')
    print('')

    if missing_sections:
        print('  {b}New sections:{n}'.format(b=BOLD, n=NC))
        for s in missing_sections:
            print('    [{s}]'.format(s=s))
        print('')

    if missing_keys:
        print('  {b}New keys in existing sections:{n}'.format(b=BOLD, n=NC))
        for section, keys in sorted(missing_keys.items()):
            for key in keys:
                print('    [{s}] {k}'.format(s=section, k=key))
        print('')

    total = len(missing_sections) + sum(len(v) for v in missing_keys.values())
    print('  Total: {n} new option(s)'.format(n=total))
    print('')
    return True


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------
# Sections with special interactive handling (matching install.sh style)
WIZARD_HANDLERS = {}


def wizard_handler(section_name):
    """Decorator to register a special wizard handler for a section."""
    def decorator(func):
        WIZARD_HANDLERS[section_name] = func
        return func
    return decorator


@wizard_handler('geoip')
def wizard_geoip(example_conf, live_conf, base_dir):
    """GeoIP enrichment wizard."""
    print('')
    print('{b}  GeoIP Enrichment (v1.4+){n}'.format(b=BOLD, n=NC))
    print('  Tags every auth event with country, city, and ASN.')
    print('  Required for the compromise-detection feature.')
    print('  You\'ll need MaxMind GeoLite2 database files (free registration).')
    print('')

    values = {}
    if ask_yn('  Enable GeoIP enrichment?', 'n'):
        values['enabled'] = 'true'
        print('')
        print('  Place the following files under /opt/wp-guardian/state/geoip/:')
        print('    - GeoLite2-City.mmdb')
        print('    - GeoLite2-ASN.mmdb')
        print('')
        print('  Get them from https://www.maxmind.com/en/geolite2/signup')
        print('')

        install_dir = os.path.dirname(base_dir)
        city_path = os.path.join(base_dir, 'state', 'geoip', 'GeoLite2-City.mmdb')
        asn_path = os.path.join(base_dir, 'state', 'geoip', 'GeoLite2-ASN.mmdb')

        if os.path.exists(city_path):
            print_ok('GeoLite2-City.mmdb found')
        else:
            print_warn('GeoLite2-City.mmdb not yet present')

        if os.path.exists(asn_path):
            print_ok('GeoLite2-ASN.mmdb found')
        else:
            print_warn('GeoLite2-ASN.mmdb not yet present')
    else:
        values['enabled'] = 'false'

    # Fill remaining keys with example defaults
    for key in example_conf.options('geoip'):
        if key not in values:
            values[key] = example_conf.get('geoip', key)

    return values


@wizard_handler('compromise_detection')
def wizard_compromise(example_conf, live_conf, base_dir):
    """Compromise detection wizard."""
    print('')
    print('{b}  Compromise Detection (v1.4+){n}'.format(b=BOLD, n=NC))
    print('  Flags accounts authenticating from many distinct countries/ASNs/IPs')
    print('  in a short window — the classic credential-abuse botnet signature.')
    print('')

    values = {}
    geoip_enabled = live_conf.get('geoip', 'enabled', fallback='false')
    if ask_yn('  Enable compromise detection?', 'n'):
        values['enabled'] = 'true'
        if geoip_enabled.lower() != 'true':
            print_warn('GeoIP is NOT enabled — country/ASN rules will never trigger.')
            print_warn('Only the distinct-IPs rule will work without GeoIP.')

        print('')
        print('  Compromise action determines what happens on detection:')
        print('    1) alert_only       — record event + Telegram alert only')
        print('    2) block_ips        — alert + block all attacker IPs')
        print('    3) disable_mailbox  — alert + disable mailbox in mail backend')
        print('    4) full             — alert + block IPs + disable mailbox (default)')
        choice = ask('  Choice', '4')
        action_map = {'1': 'alert_only', '2': 'block_ips',
                      '3': 'disable_mailbox', '4': 'full'}
        values['action'] = action_map.get(choice, 'full')
    else:
        values['enabled'] = 'false'

    for key in example_conf.options('compromise_detection'):
        if key not in values:
            values[key] = example_conf.get('compromise_detection', key)

    return values


@wizard_handler('mail_backend')
def wizard_mail_backend(example_conf, live_conf, base_dir):
    """Mail backend wizard (with password handling via configparser)."""
    print('')
    print('{b}  Mail Backend Integration (v1.4+){n}'.format(b=BOLD, n=NC))
    print('  Lets Guardian auto-disable a compromised mailbox by updating the')
    print('  mail server\'s MariaDB virtual_users table.')
    print('')

    values = {}
    if ask_yn('  Configure mail backend integration?', 'n'):
        values['type'] = 'mariadb_virtual_users'
        values['host'] = ask('    MariaDB host', '127.0.0.1')
        values['port'] = ask('    MariaDB port', '3306')
        values['database'] = ask('    Database name', 'mailserver')
        values['user'] = ask('    MariaDB user', 'wp_guardian')
        values['password'] = ask_password('    MariaDB password')
        values['table'] = ask('    Mailbox table', 'virtual_users')

        print('')
        print_step('Before Guardian can disable mailboxes, run this on your mail server:')
        print('')
        print("    CREATE USER '{u}'@'localhost' IDENTIFIED BY '<your password>';".format(
            u=values['user']))
        print("    GRANT SELECT (email, enabled), UPDATE (enabled)")
        print("      ON {db}.{tbl} TO '{u}'@'localhost';".format(
            db=values['database'], tbl=values['table'], u=values['user']))
        print("    FLUSH PRIVILEGES;")
        print('')
    else:
        values['type'] = 'none'

    for key in example_conf.options('mail_backend'):
        if key not in values:
            values[key] = example_conf.get('mail_backend', key)

    return values


@wizard_handler('profile')
def wizard_profile(example_conf, live_conf, base_dir):
    """Profile mode wizard."""
    print('')
    print('{b}  Threshold Profile (v1.4+){n}'.format(b=BOLD, n=NC))
    print('    1) steady    — tight thresholds for normal operations (default)')
    print('    2) migration — loose thresholds for post-cutover migration periods')

    choice = ask('  Choice', '1')
    mode = 'migration' if choice == '2' else 'steady'

    return {'mode': mode}


def wizard_generic_keys(example_conf, section, keys):
    """
    Generic wizard for missing keys in existing sections.
    Shows the comment from the example file and asks for a value.
    """
    values = {}

    print('')
    print('{b}  New options in [{s}]:{n}'.format(b=BOLD, s=section, n=NC))

    for key in keys:
        default = example_conf.get(section, key) or ''
        # Extract the comment for this key from the example
        comment = extract_key_lines(example_conf.lines, section, key)
        if comment:
            # Print just the comment lines
            for line in comment.strip().split('\n'):
                stripped = line.strip()
                if stripped.startswith('#'):
                    print('  {}'.format(stripped))

        values[key] = ask('    {k}'.format(k=key), default)

    return values


def wizard_telegram_alert_mode(example_conf, live_conf, base_dir):
    """Special handler for new telegram keys."""
    values = {}

    # Check which telegram keys are missing
    new_keys = []
    for key in example_conf.options('telegram'):
        if not live_conf.has_option('telegram', key):
            new_keys.append(key)

    if 'alert_mode' in new_keys:
        print('')
        print('{b}  Telegram Alert Mode (v1.4+){n}'.format(b=BOLD, n=NC))
        print('    1) verbose — every block alerts immediately (recommended for first week)')
        print('    2) digest  — tier-1/tier-2 blocks are buffered into an hourly summary')
        print('    3) quiet   — only compromise + BLOCK FAILED alert immediately')
        choice = ask('  Choice', '1')
        mode_map = {'1': 'verbose', '2': 'digest', '3': 'quiet'}
        values['alert_mode'] = mode_map.get(choice, 'verbose')
        new_keys.remove('alert_mode')

    # Handle remaining keys generically
    for key in new_keys:
        default = example_conf.get('telegram', key) or ''
        values[key] = ask('    {k}'.format(k=key), default)

    return values


# ---------------------------------------------------------------------------
# Config writer
# ---------------------------------------------------------------------------
def write_merged_config(example_conf, live_conf, live_path,
                        missing_sections, missing_keys, wizard_values):
    """
    Merge new sections/keys into the live config file.
    Preserves existing content. Appends new sections with full comments
    from the example file. Inserts missing keys at the end of their section.

    wizard_values: dict of {section: {key: value}}
    """
    # Back up before writing
    backup_path = live_path + '.pre-upgrade.bak'
    shutil.copy2(live_path, backup_path)
    print_ok('Backed up config to {}'.format(os.path.basename(backup_path)))

    # Read current content
    with open(live_path, 'r') as f:
        content = f.read()

    lines = content.split('\n')

    # Step 1: Insert missing keys into existing sections
    for section, keys in sorted(missing_keys.items()):
        section_values = wizard_values.get(section, {})
        insert_block = ''
        for key in keys:
            # Get comment + key from example
            key_block = extract_key_lines(example_conf.lines, section, key)
            if key_block:
                # Replace the value with the wizard value if we have one
                value = section_values.get(key, example_conf.get(section, key) or '')
                # Replace the key=value line in the block
                new_block = re.sub(
                    r'^({k}\s*=\s*).*$'.format(k=re.escape(key)),
                    r'\g<1>{v}'.format(v=value),
                    key_block,
                    count=1,
                    flags=re.MULTILINE
                )
                insert_block += new_block
                if not new_block.endswith('\n'):
                    insert_block += '\n'
            else:
                value = section_values.get(key, example_conf.get(section, key) or '')
                insert_block += '{k} = {v}\n'.format(k=key, v=value)

        if insert_block:
            # Find the end of this section (line before next [section] or EOF)
            in_section = False
            insert_idx = len(lines)
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith('[') and ']' in stripped:
                    header = stripped.split(']')[0].lstrip('[').strip()
                    if header == section:
                        in_section = True
                        continue
                    elif in_section:
                        # Insert before this next section header
                        # Back up past blank lines
                        insert_idx = i
                        while insert_idx > 0 and lines[insert_idx - 1].strip() == '':
                            insert_idx -= 1
                        break
                elif in_section:
                    continue

            # If we're in the last section, insert at end
            if in_section and insert_idx == len(lines):
                # Back up past trailing blank lines
                while insert_idx > 0 and lines[insert_idx - 1].strip() == '':
                    insert_idx -= 1

            insert_lines = insert_block.rstrip('\n').split('\n')
            # Add a blank line before new keys if the section isn't empty
            if insert_idx > 0 and lines[insert_idx - 1].strip() != '':
                insert_lines.insert(0, '')
            lines[insert_idx:insert_idx] = insert_lines

    # Step 2: Append missing sections at end of file
    for section in missing_sections:
        section_values = wizard_values.get(section, {})
        section_block = extract_section_block(example_conf.lines, section)

        if section_block:
            # Replace values with wizard values
            for key, value in section_values.items():
                section_block = re.sub(
                    r'^({k}\s*=\s*).*$'.format(k=re.escape(key)),
                    r'\g<1>{v}'.format(v=value),
                    section_block,
                    count=1,
                    flags=re.MULTILINE
                )

            # Ensure separation
            if lines and lines[-1].strip() != '':
                lines.append('')
            lines.extend(section_block.rstrip('\n').split('\n'))
        else:
            # Fallback: generate from parsed data
            if lines and lines[-1].strip() != '':
                lines.append('')
            lines.append('[{s}]'.format(s=section))
            for key in example_conf.options(section):
                value = section_values.get(key, example_conf.get(section, key) or '')
                lines.append('{k} = {v}'.format(k=key, v=value))

    # Step 3: Handle mail_backend password safely via configparser
    if 'mail_backend' in wizard_values and wizard_values['mail_backend'].get('password'):
        # Write the file first without the password
        output = '\n'.join(lines)
        if not output.endswith('\n'):
            output += '\n'
        with open(live_path, 'w') as f:
            f.write(output)

        # Now use configparser to set the password safely
        parser = configparser.ConfigParser(allow_no_value=True)
        parser.optionxform = str
        parser.read(live_path)
        if parser.has_section('mail_backend'):
            parser.set('mail_backend', 'password',
                        wizard_values['mail_backend']['password'])
            with open(live_path, 'w') as f:
                parser.write(f)
        return

    # Write final output
    output = '\n'.join(lines)
    if not output.endswith('\n'):
        output += '\n'
    with open(live_path, 'w') as f:
        f.write(output)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='WP-Guardian Config Upgrade Tool')
    parser.add_argument('--auto', action='store_true',
                        help='Add missing options with example defaults (no questions)')
    parser.add_argument('--diff-only', action='store_true',
                        help='Show missing options without changing anything')
    parser.add_argument('--config', default=None,
                        help='Path to live config (default: auto-detect)')
    parser.add_argument('--example', default=None,
                        help='Path to example config (default: auto-detect)')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress what\'s-new banner')

    args = parser.parse_args()

    # Determine base directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)  # tools/ -> project root

    # Find config files
    live_path = args.config or os.path.join(base_dir, 'wp-guardian.conf')
    example_path = args.example or os.path.join(base_dir, 'wp-guardian.conf.example')

    if not os.path.exists(example_path):
        print_err('Example config not found: {}'.format(example_path))
        sys.exit(1)

    if not os.path.exists(live_path):
        print_err('Live config not found: {}'.format(live_path))
        print_err('Run install.sh first, or copy wp-guardian.conf.example to wp-guardian.conf')
        sys.exit(1)

    # Parse configs
    example_conf = CommentPreservingConfig(example_path)
    live_conf = CommentPreservingConfig(live_path)

    # Show header
    if not args.quiet:
        print_header()

    # Show what's new
    if not args.quiet and not args.diff_only:
        show_whats_new(base_dir)

    # Compute diff
    missing_sections, missing_keys = find_missing(example_conf, live_conf)

    # Display diff
    has_changes = print_diff(missing_sections, missing_keys)

    if not has_changes:
        return 0

    if args.diff_only:
        # Exit with code 1 to signal "changes available" to update.sh
        return 1

    # Collect values
    wizard_values = {}

    if args.auto:
        # Auto mode: use example defaults
        print_step('Adding missing options with default values...')
        for section in missing_sections:
            wizard_values[section] = {}
            for key in example_conf.options(section):
                wizard_values[section][key] = example_conf.get(section, key) or ''
        for section, keys in missing_keys.items():
            wizard_values[section] = {}
            for key in keys:
                wizard_values[section][key] = example_conf.get(section, key) or ''
    else:
        # Interactive wizard
        print_step('Running config upgrade wizard...')
        print('  (Press Enter to accept defaults)')
        print('')

        # Handle missing sections with special wizards
        for section in missing_sections:
            if section in WIZARD_HANDLERS:
                wizard_values[section] = WIZARD_HANDLERS[section](
                    example_conf, live_conf, base_dir)
            else:
                # Generic: show section comment block, ask for each key
                wizard_values[section] = wizard_generic_keys(
                    example_conf, section, example_conf.options(section))

        # Handle missing keys in existing sections
        for section, keys in sorted(missing_keys.items()):
            if section == 'telegram' and 'alert_mode' in keys:
                wizard_values[section] = wizard_telegram_alert_mode(
                    example_conf, live_conf, base_dir)
            else:
                wizard_values[section] = wizard_generic_keys(
                    example_conf, section, keys)

    # Write merged config
    write_merged_config(example_conf, live_conf, live_path,
                        missing_sections, missing_keys, wizard_values)

    print('')
    print_ok('Config updated successfully!')
    print_ok('Backup saved to: {}'.format(live_path + '.pre-upgrade.bak'))

    if not args.auto:
        print('')
        print_step('Review the updated config:')
        print('    cat {}'.format(live_path))

    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
