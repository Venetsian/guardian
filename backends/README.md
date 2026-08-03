# WP-Guardian — Adding a Firewall Backend

WP-Guardian uses a pluggable firewall backend system. This guide explains how to add support for a new firewall or router.

## Architecture

All backends live in the `backends/` directory and inherit from `FirewallBackend` in `base.py`. The active backend is selected via `[firewall] backend = ...` in `wp-guardian.conf`.

```
backends/
├── base.py           # Abstract base class (shared CIDR helpers)
├── factory.py        # Backend registry and instantiation
├── csf.py            # ConfigServer Firewall
├── firewalld.py      # firewalld (RHEL/AlmaLinux/CyberPanel 2.4+)
├── nftables.py       # nftables direct (modern Linux)
├── mikrotik.py       # MikroTik RouterOS via SSH
├── pfsense.py        # pfSense / OPNsense via REST API
└── README.md         # This file
```

## Supported Backends

| Backend | Type | How it blocks | Best for |
|---------|------|---------------|----------|
| `csf` | Software | iptables rules via CSF | Servers with CSF installed |
| `firewalld` | Software | firewall-cmd rich rules | CyberPanel, RHEL/AlmaLinux |
| `nftables` | Software | nft sets + drop chain | Modern Linux without frontends |
| `mikrotik` | Hardware | Address lists via SSH | MikroTik routers at network edge |
| `pfsense` | Hardware | Aliases via REST API | pfSense firewalls at network edge |
| `opnsense` | Hardware | Aliases via REST API | OPNsense firewalls at network edge |

## Creating a New Backend

### 1. Create the file

Create `backends/yourbackend.py`:

```python
"""
WP-Guardian YourFirewall Backend
Brief description of how it works.
"""

import logging
from backends.base import FirewallBackend

logger = logging.getLogger('wp-guardian.yourbackend')


class YourBackend(FirewallBackend):
    """Firewall backend for YourFirewall."""

    supports_cidr = True          # Set False if no CIDR support
    supports_friendly_list = True  # Set False if no allow-list

    def __init__(self, config):
        # Read config from [yourbackend] section
        self.some_setting = config.get('yourbackend', 'setting', fallback='default')

        if not self.test_connection():
            raise RuntimeError("Cannot connect to YourFirewall")

    def block(self, ip, tier, reason, service='web'):
        """Block an IP. Return True on success."""
        # tier 1 = 24h, tier 2 = 30d, tier 3 = permanent
        # Must be idempotent (return True if already blocked)
        pass

    def unblock(self, ip):
        """Remove from all block lists. Return True on success."""
        pass

    def test_connection(self):
        """Verify backend is working. Return True if ready."""
        pass

    # Optional: override these if supported
    def is_blocked(self, ip):
        return False

    def block_cidr(self, subnet, reason, service='web', duration='30d'):
        return False

    def is_cidr_blocked(self, subnet):
        return False

    def is_friendly(self, ip):
        return False

    def is_friendly_subnet(self, subnet):
        return False

    def ensure_firewall_rules(self):
        pass

    def get_block_counts(self):
        return {}
```

### 2. Register in factory.py

Add your backend to `backends/factory.py`:

```python
elif backend_type == 'yourbackend':
    from backends.yourbackend import YourBackend
    logger.info("Initializing YourFirewall backend")
    return YourBackend(config)
```

### 3. Add config section

Add a section to `wp-guardian.conf`:

```ini
[firewall]
backend = yourbackend

[yourbackend]
# Your backend-specific settings
setting = value
```

### 4. Test

```bash
# Test connectivity
python3 wp-guardian.py --test-backend

# Dry run (no actual blocking)
python3 wp-guardian.py --dry-run

# Check status
python3 wp-guardian.py --status
```

## Required Methods

| Method | Required | Description |
|--------|----------|-------------|
| `block(ip, tier, reason, service)` | Yes | Block an IP. Must be idempotent. |
| `unblock(ip)` | Yes | Remove from all block lists. |
| `test_connection()` | Yes | Verify backend is working. |
| `is_blocked(ip)` | No | Check if IP is currently blocked. |
| `block_cidr(subnet, ...)` | No | Block a CIDR range (set `supports_cidr = True`). |
| `is_cidr_blocked(subnet)` | No | Check if CIDR is blocked. |
| `is_friendly(ip)` | No | Check if IP is in never-block list. |
| `is_friendly_subnet(subnet)` | No | Check if subnet contains friendly IPs. |
| `ensure_firewall_rules()` | No | One-time setup on daemon start. |
| `get_block_counts()` | No | Return dict with tier counts. |

## Tier System

The blocker determines the tier; your backend just needs to apply the right duration:

| Tier | Duration | Meaning |
|------|----------|---------|
| 1 | 24 hours | First offense |
| 2 | 30 days | Repeat offender |
| 3 | Permanent | Persistent threat |

Read durations from config `[escalation]` section:
```python
tier1_dur = config.get('escalation', 'tier1_duration', fallback='24h')
tier2_dur = config.get('escalation', 'tier2_duration', fallback='30d')
```

### Who enforces the duration — `expires_own_entries` (v1.7.9+)

There are two valid ways to honor a tier duration, and your backend must
declare which one it uses:

```python
expires_own_entries = True   # the firewall drops the entry on its own TTL
expires_own_entries = False  # entries persist until unblock() removes them
```

| Backend | Value | Mechanism |
|---------|-------|-----------|
| mikrotik | `True` | `timeout=24h` / `30d` on the address-list entry |
| nftables | `True` | per-element `timeout` in the set |
| csf | `True` | `csf -td <ip> <seconds>` temporary deny |
| firewalld | `False` | ipset entries carry no TTL |
| pfsense | `False` | flat alias, tier ignored |

`Blocker.reap_expired_blocks()` reads this flag on the hourly sweep:

- **`True`** — skip `unblock()` and only clear the stale tier in `ip_history`.
  The firewall already forgot the IP, so the call would be a guaranteed no-op.
  On MikroTik that no-op costs three SSH round-trips per IP.
- **`False`** — call `unblock()`, and only clear the tier if it returns True,
  so a backend outage can't silently drop blocks from the database.

**The tier reset happens either way, and it is the part that matters.** Without
it, `block()` short-circuits on "already blocked at tier N" and a returning
attacker is never re-pushed — even on a self-expiring backend that dropped the
entry hours ago.

Default is `False`. A wrong `True` leaves entries blocked at the firewall that
the database no longer tracks — the worst failure direction — so only set it if
`block()` genuinely attaches an expiry for **both** tier 1 and tier 2. Tier 3 is
permanent and the reaper never touches it.

## Python 3.6 Compatibility

WP-Guardian targets Python 3.6.8. Do NOT use:
- `capture_output=True` in subprocess (use `stdout=subprocess.PIPE, stderr=subprocess.PIPE`)
- `text=True` in subprocess (use `universal_newlines=True`)
- Dataclasses (3.7+)
- Walrus operator `:=` (3.8+)
- f-string `=` debugging (3.8+)

## Base Class Helpers

The `FirewallBackend` base class provides shared methods you can use:

```python
# Check if IP is in a set of IPs/CIDRs
self._check_friendly(ip, friendly_set)      # Returns True/False
self._check_friendly_subnet(subnet, friendly_set)  # Returns True/False
self._ip_in_cidr(ip, cidr_string)           # Static method, basic CIDR match
```

## Ideas for Future Backends

- **iptables** — Classic Linux firewall (via `iptables` command)
- **UFW** — Uncomplicated Firewall (Ubuntu/Debian)
- **Ubiquiti EdgeRouter** — SSH-based, similar to MikroTik approach
- **Fortinet FortiGate** — Via REST API
- **Cisco ASA** — Via SSH
- **SonicWall** — Via REST API
- **Sophos XG** — Via REST API
