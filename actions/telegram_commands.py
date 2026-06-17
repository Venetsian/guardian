"""
WP-Guardian Telegram Command Handler
Polls for incoming Telegram messages and executes commands.
Uses getUpdates long-polling — no webhooks, no open ports.
"""

import logging
import os
import time
import re
import threading

logger = logging.getLogger('wp-guardian.telegram-cmd')

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class TelegramCommander:
    """
    Polls Telegram for incoming commands and responds.
    Runs as a daemon thread alongside the log tailers.

    Security: ONLY messages from the configured chat_id are processed.
    All other messages are silently ignored.
    """

    def __init__(self, config, db, blocker, whitelist, tripwires=None, base_dir=None,
                 mail_backend=None, compromise_action=None, verbosity_router=None,
                 cms_registry=None, firewall=None, post_flood_detector=None,
                 version='unknown'):
        self.enabled = config.getboolean('telegram', 'commands_enabled', fallback=False)
        self.bot_token = config.get('telegram', 'bot_token', fallback='')
        self.chat_id = config.get('telegram', 'chat_id', fallback='')
        self.poll_timeout = config.getint('telegram', 'commands_poll_timeout', fallback=30)

        self.config = config
        self.db = db
        self.blocker = blocker
        self.whitelist = whitelist
        self.tripwires = tripwires  # Shared set reference from Guardian
        self.base_dir = base_dir or '/opt/wp-guardian'
        self.mail_backend = mail_backend  # may be None/disabled
        self.compromise_action = compromise_action  # may be None
        self.verbosity_router = verbosity_router  # may be None
        self.cms_registry = cms_registry              # v1.5+
        self.firewall = firewall                      # v1.5+ — for /serverinfo
        self.post_flood_detector = post_flood_detector  # v1.5+
        self.version = version
        self.tailers = []                             # populated via set_tailers()

        self.running = False
        self._thread = None
        self._offset = 0  # Tracks last processed update_id

        # IP validation pattern
        self._ip_pattern = re.compile(
            r'^(\d{1,3}\.){3}\d{1,3}$'
        )

        # Duration parsing pattern (e.g., "24h", "7d", "1h")
        self._duration_pattern = re.compile(
            r'^(\d+)([hdm])$', re.IGNORECASE
        )

        if self.enabled:
            if not HAS_REQUESTS:
                logger.error("Telegram commands enabled but 'requests' module not installed")
                self.enabled = False
            elif not self.bot_token or not self.chat_id:
                logger.error("Telegram commands enabled but bot_token or chat_id not configured")
                self.enabled = False
            else:
                logger.info("Telegram command handler enabled")

    def start(self):
        """Start the polling thread."""
        if not self.enabled:
            logger.debug("Telegram commands disabled, not starting")
            return

        self.running = True
        self._thread = threading.Thread(target=self._poll_loop, name='telegram-cmd')
        self._thread.daemon = True
        self._thread.start()
        logger.info("Telegram command polling started")

    def set_tailers(self, tailers):
        """Hand the live LogTailer list to the command handler.

        Tailers are created in Guardian.start() AFTER TelegramCommander is
        instantiated, so /logs needs them attached at that point.
        """
        self.tailers = list(tailers)

    def stop(self):
        """Stop the polling thread."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=self.poll_timeout + 5)
            logger.info("Telegram command polling stopped")

    # ------------------------------------------------------------------
    # Polling loop
    # ------------------------------------------------------------------
    def _poll_loop(self):
        """Main polling loop — runs in daemon thread."""
        # Small initial delay to let the daemon finish startup
        time.sleep(2)

        while self.running:
            try:
                updates = self._get_updates()
                if updates:
                    for update in updates:
                        self._process_update(update)
            except Exception as e:
                logger.error(f"Telegram poll error: {e}")
                # Back off on errors to avoid hammering
                time.sleep(10)

    def _get_updates(self):
        """Call Telegram getUpdates with long polling."""
        try:
            url = "https://api.telegram.org/bot{token}/getUpdates".format(
                token=self.bot_token
            )
            params = {
                'timeout': self.poll_timeout,
                'allowed_updates': '["message"]',
            }
            if self._offset > 0:
                params['offset'] = self._offset

            response = requests.get(
                url, params=params,
                timeout=self.poll_timeout + 10  # HTTP timeout > long-poll timeout
            )

            if response.status_code != 200:
                logger.error(f"Telegram getUpdates HTTP {response.status_code}")
                time.sleep(5)
                return []

            data = response.json()
            if not data.get('ok'):
                logger.error(f"Telegram getUpdates API error: {data}")
                time.sleep(5)
                return []

            return data.get('result', [])

        except requests.Timeout:
            # Normal for long polling — no updates available
            return []
        except requests.ConnectionError:
            logger.warning("Telegram connection error, retrying in 30s")
            time.sleep(30)
            return []
        except Exception as e:
            logger.error(f"Telegram getUpdates error: {e}")
            time.sleep(5)
            return []

    # ------------------------------------------------------------------
    # Update processing
    # ------------------------------------------------------------------
    def _process_update(self, update):
        """Process a single Telegram update."""
        update_id = update.get('update_id', 0)

        # Always advance offset to acknowledge this update
        if update_id >= self._offset:
            self._offset = update_id + 1

        message = update.get('message')
        if not message:
            return

        # SECURITY: Only process messages from our configured chat_id
        msg_chat_id = str(message.get('chat', {}).get('id', ''))
        if msg_chat_id != str(self.chat_id):
            logger.warning(f"Telegram command from unauthorized chat_id: {msg_chat_id}")
            return

        text = message.get('text', '').strip()
        if not text:
            return

        logger.info(f"Telegram command received: {text}")

        # Parse and dispatch command
        # Strip bot username from commands (e.g., /status@MyBot -> /status)
        if '@' in text.split()[0]:
            parts = text.split(None, 1)
            parts[0] = parts[0].split('@')[0]
            text = ' '.join(parts)

        if text.startswith('/'):
            self._dispatch_command(text, msg_chat_id)
        else:
            # Treat plain text as a command too (without the /)
            self._dispatch_command('/' + text, msg_chat_id)

    def _dispatch_command(self, text, chat_id):
        """Parse command and call the appropriate handler."""
        parts = text.split()
        command = parts[0].lower()
        args = parts[1:]

        handlers = {
            '/status': self._cmd_status,
            '/unblock': self._cmd_unblock,
            '/block': self._cmd_block,
            '/whitelist': self._cmd_whitelist,
            '/history': self._cmd_history,
            '/tripwires': self._cmd_tripwires,
            '/remove': self._cmd_remove,
            '/help': self._cmd_help,
            # v1.4
            '/authmap': self._cmd_authmap,
            '/suspects': self._cmd_suspects,
            '/disable': self._cmd_disable,
            '/enable': self._cmd_enable,
            '/compromises': self._cmd_compromises,
            '/resolve': self._cmd_resolve,
            # v1.4.1
            '/verbosity': self._cmd_verbosity,
            # v1.5 — remote troubleshooting
            '/sites': self._cmd_sites,
            '/site': self._cmd_site,
            '/cmsrefresh': self._cmd_cmsrefresh,
            '/logs': self._cmd_logs,
            '/serverinfo': self._cmd_serverinfo,
        }

        handler = handlers.get(command)
        if handler:
            try:
                handler(args)
            except Exception as e:
                logger.error(f"Command handler error for '{text}': {e}")
                self._reply("Command failed: {err}".format(err=str(e)))
        else:
            self._reply(
                "Unknown command: {cmd}\n"
                "Type /help for available commands.".format(cmd=command)
            )

    # ------------------------------------------------------------------
    # Command handlers
    # ------------------------------------------------------------------
    def _cmd_status(self, args):
        """Handle /status command."""
        stats = self.db.get_stats()

        msg = (
            "<b>WP-Guardian Status</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "Blocks today: {blocks_today}\n"
            "Active Tier 1 (24h): {tier1}\n"
            "Active Tier 2 (30d): {tier2}\n"
            "Active Tier 3 (perm): {tier3}\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "Total IPs tracked: {total_ips}\n"
            "Auth sessions today: {auth}\n"
            "Whitelist entries: {wl}\n"
            "Active tripwires: {tw}"
        ).format(
            blocks_today=stats.get('total_blocks_today', 0),
            tier1=stats.get('active_tier1', 0),
            tier2=stats.get('active_tier2', 0),
            tier3=stats.get('active_tier3', 0),
            total_ips=stats.get('total_ips_tracked', 0),
            auth=stats.get('auth_sessions_today', 0),
            wl=stats.get('whitelist_count', 0),
            tw=stats.get('tripwire_count', 0),
        )
        self._reply(msg)

    def _cmd_unblock(self, args):
        """Handle /unblock <ip> command."""
        if not args:
            self._reply("Usage: /unblock &lt;ip&gt;\nExample: /unblock 192.0.2.50")
            return

        ip = args[0]
        if not self._validate_ip(ip):
            self._reply("Invalid IP address: {ip}".format(ip=ip))
            return

        # Check if IP is actually blocked
        ip_data = self.db.get_ip(ip)
        if not ip_data or ip_data['current_tier'] == 0:
            self._reply("IP <code>{ip}</code> is not currently blocked.".format(ip=ip))
            return

        tier = ip_data['current_tier']

        try:
            self.blocker.unblock(ip)
            self._reply(
                "Unblocked <code>{ip}</code> (was tier {tier}).".format(
                    ip=ip, tier=tier
                )
            )
        except Exception as e:
            self._reply(
                "Failed to unblock <code>{ip}</code>: {err}".format(
                    ip=ip, err=str(e)
                )
            )

    def _cmd_block(self, args):
        """Handle /block <ip|cidr> [duration] — manual operator block."""
        if not args:
            self._reply(
                "Usage: /block &lt;ip|cidr&gt; [duration]\n"
                "\n"
                "Examples:\n"
                "/block 192.0.2.50 — permanent\n"
                "/block 192.0.2.50 24h — for 24 hours\n"
                "/block 192.0.2.0/24 — block the whole /24 (permanent)\n"
                "/block 192.0.2.0/24 30d — for 30 days\n"
                "\n"
                "Duration: 24h / 7d / 30d / perm (default: permanent).\n"
                "Reverse with /unblock &lt;ip&gt;."
            )
            return

        target = args[0]
        duration = args[1] if len(args) > 1 else None
        ok, msg = self.blocker.block_manual(
            target, duration=duration,
            actor='telegram:{cid}'.format(cid=self.chat_id),
        )
        self._reply(("✅ " if ok else "⚠️ ") + msg)

    def _cmd_whitelist(self, args):
        """Handle /whitelist [add|remove|list] commands."""
        if not args:
            self._reply(
                "Usage:\n"
                "/whitelist &lt;ip&gt; — add permanently\n"
                "/whitelist &lt;ip&gt; &lt;duration&gt; — add temporarily (e.g., 24h, 7d)\n"
                "/whitelist remove &lt;ip&gt;\n"
                "/whitelist list"
            )
            return

        subcommand = args[0].lower()

        # /whitelist list
        if subcommand == 'list':
            entries = self.whitelist.list_all()
            if not entries:
                self._reply("Whitelist is empty.")
                return

            lines = ["<b>Whitelist Entries</b>\n━━━━━━━━━━━━━━━━━━━━━"]
            for entry in entries:
                ip = entry.get('ip', '?')
                source = entry.get('source', entry.get('type', '?'))
                reason = entry.get('reason', '')
                expires = entry.get('expires_at')

                line = "<code>{ip}</code> ({source})".format(ip=ip, source=source)
                if reason:
                    line += " — " + reason
                if expires:
                    remaining = expires - int(time.time())
                    if remaining > 0:
                        hours = remaining // 3600
                        if hours > 24:
                            line += " [expires in {d}d]".format(d=hours // 24)
                        else:
                            line += " [expires in {h}h]".format(h=hours)
                lines.append(line)

            self._reply('\n'.join(lines))
            return

        # /whitelist remove <ip>
        if subcommand == 'remove':
            if len(args) < 2:
                self._reply("Usage: /whitelist remove &lt;ip&gt;")
                return

            ip = args[1]
            if not self._validate_ip(ip):
                self._reply("Invalid IP address: {ip}".format(ip=ip))
                return

            self.whitelist.remove(ip)
            self._reply("Removed <code>{ip}</code> from whitelist.".format(ip=ip))
            return

        # /whitelist <ip> [duration] — add
        ip = args[0]
        if not self._validate_ip(ip):
            self._reply("Invalid IP address: {ip}".format(ip=ip))
            return

        duration_seconds = None
        duration_label = "permanent"

        if len(args) >= 2:
            duration_seconds = self._parse_duration(args[1])
            if duration_seconds is None:
                self._reply(
                    "Invalid duration: {d}\n"
                    "Examples: 1h, 24h, 7d, 30d".format(d=args[1])
                )
                return
            duration_label = args[1]

        wl_type = 'permanent' if duration_seconds is None else 'temporary'

        # Also unblock if currently blocked
        ip_data = self.db.get_ip(ip)
        was_blocked = False
        if ip_data and ip_data['current_tier'] > 0:
            try:
                self.blocker.unblock(ip)
                was_blocked = True
            except Exception as e:
                logger.warning(f"Failed to unblock {ip} during whitelist: {e}")

        self.whitelist.add(
            ip, wl_type=wl_type, duration_seconds=duration_seconds,
            reason='Added via Telegram', added_by='telegram'
        )

        msg = "Whitelisted <code>{ip}</code> ({duration}).".format(
            ip=ip, duration=duration_label
        )
        if was_blocked:
            msg += "\nAlso unblocked (was tier {tier}).".format(
                tier=ip_data['current_tier']
            )
        self._reply(msg)

    def _cmd_history(self, args):
        """Handle /history <ip> command."""
        if not args:
            self._reply("Usage: /history &lt;ip&gt;")
            return

        ip = args[0]
        if not self._validate_ip(ip):
            self._reply("Invalid IP address: {ip}".format(ip=ip))
            return

        ip_data = self.db.get_ip(ip)
        if not ip_data:
            self._reply("No data for <code>{ip}</code>.".format(ip=ip))
            return

        # Format timestamps
        first_seen = time.strftime('%Y-%m-%d %H:%M', time.localtime(ip_data['first_seen']))
        last_seen = time.strftime('%Y-%m-%d %H:%M', time.localtime(ip_data['last_seen']))

        tier_labels = {0: 'Not blocked', 1: 'Tier 1 (24h)', 2: 'Tier 2 (30d)', 3: 'Tier 3 (perm)'}
        current_tier = ip_data['current_tier']

        msg = (
            "<b>IP History: </b><code>{ip}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "Status: {status}\n"
            "Total hits: {hits}\n"
            "Block count: {blocks}\n"
            "First seen: {first}\n"
            "Last seen: {last}"
        ).format(
            ip=ip,
            status=tier_labels.get(current_tier, 'Tier {t}'.format(t=current_tier)),
            hits=ip_data['total_hits'],
            blocks=ip_data['block_count'],
            first=first_seen,
            last=last_seen,
        )

        country = ip_data['geoip_country']
        city = ip_data['geoip_city']
        if country:
            location = "{city}, {country}".format(city=city, country=country) if city else country
            msg += "\nLocation: {loc}".format(loc=location)

        if ip_data['last_block_reason']:
            msg += "\nLast reason: {reason}".format(reason=ip_data['last_block_reason'])

        # Recent block log entries (last 5)
        blocks = self.db.get_block_history(ip)
        if blocks:
            msg += "\n\n<b>Recent blocks:</b>"
            for block in blocks[:5]:
                ts = time.strftime('%m-%d %H:%M', time.localtime(block['timestamp']))
                msg += "\n  {ts} T{tier} {svc}: {reason}".format(
                    ts=ts,
                    tier=block['tier'],
                    svc=block['service'],
                    reason=block['reason'][:40],
                )

        self._reply(msg)

    def _cmd_tripwires(self, args):
        """Handle /tripwires [search] command."""
        total = self.db.count_tripwires()

        if not args:
            # No search term — show summary + top 10
            top = self.db.search_tripwires(pattern=None, limit=10)
            lines = [
                "<b>Active Tripwires</b> ({total} total)".format(total=total),
                "━━━━━━━━━━━━━━━━━━━━━",
                "<b>Top 10 by hits:</b>"
            ]
            for t in top:
                lines.append("<code>{path}</code> ({hits} hits)".format(
                    path=t['path'], hits=t['hit_count']
                ))
            lines.append("")
            lines.append("Search: /tripwires &lt;term&gt;")
            self._reply('\n'.join(lines))
            return

        # Search by pattern
        search = ' '.join(args).strip()
        results = self.db.search_tripwires(pattern=search, limit=30)

        if not results:
            self._reply(
                "No tripwires matching \"{search}\" (of {total} total).".format(
                    search=search, total=total
                )
            )
            return

        lines = [
            "<b>Tripwires matching \"{search}\"</b> ({count}/{total})".format(
                search=search, count=len(results), total=total
            ),
            "━━━━━━━━━━━━━━━━━━━━━"
        ]
        for t in results:
            lines.append("<code>{path}</code> ({hits} hits)".format(
                path=t['path'], hits=t['hit_count']
            ))

        if len(results) == 30:
            lines.append("\n(showing first 30 results)")

        self._reply('\n'.join(lines))

    def _cmd_remove(self, args):
        """Handle /remove <path> — remove a tripwire from DB, memory, and file."""
        if not args:
            self._reply(
                "Usage: /remove &lt;path&gt;\n"
                "Example: /remove /old-plugin.php\n\n"
                "Removes a tripwire from database, memory, and tripwires.txt."
            )
            return

        path = ' '.join(args).strip().lower()

        # Validate: must look like a PHP path
        if not path.endswith('.php'):
            self._reply("Invalid path: tripwires are PHP files only (must end with .php)")
            return

        if not path.startswith('/'):
            path = '/' + path

        # Remove from database
        removed_from_db = self.db.remove_tripwire(path)

        # Remove from tripwires.txt file
        removed_from_file = False
        tripwire_file = os.path.join(self.base_dir, 'tripwires.txt')
        try:
            if os.path.exists(tripwire_file):
                with open(tripwire_file, 'r') as f:
                    lines = f.readlines()
                new_lines = [line for line in lines if line.strip().lower() != path]
                if len(new_lines) < len(lines):
                    with open(tripwire_file, 'w') as f:
                        f.writelines(new_lines)
                    removed_from_file = True
        except Exception as e:
            logger.error(f"Failed to update tripwires.txt: {e}")

        # Remove from in-memory set
        removed_from_memory = False
        if self.tripwires is not None and path in self.tripwires:
            self.tripwires.discard(path)
            removed_from_memory = True

        if removed_from_db or removed_from_file or removed_from_memory:
            sources = []
            if removed_from_db:
                sources.append("database")
            if removed_from_file:
                sources.append("tripwires.txt")
            if removed_from_memory:
                sources.append("memory")
            self._reply(
                "Removed tripwire <code>{path}</code>\n"
                "From: {sources}".format(path=path, sources=', '.join(sources))
            )
        else:
            self._reply(
                "Tripwire not found: <code>{path}</code>\n"
                "Use /tripwires &lt;search&gt; to find tripwires.".format(path=path)
            )

    # ------------------------------------------------------------------
    # v1.4 — compromise detection commands
    # ------------------------------------------------------------------
    def _cmd_authmap(self, args):
        """/authmap <user> [days]"""
        if not args:
            self._reply("Usage: /authmap &lt;user&gt; [days]")
            return
        username = args[0]
        days = 7
        if len(args) >= 2:
            try:
                days = int(args[1])
            except ValueError:
                pass

        rows = self.db.auth_map_for_user(username, days=days)
        summary = self.db.auth_map_summary(username, days=days)
        if not rows:
            self._reply(
                "No successful auths for <code>{u}</code> in the last {d} days.".format(
                    u=username, d=days
                )
            )
            return

        lines = [
            "<b>Auth map: {u}</b> (last {d}d)".format(u=username, d=days),
            "━━━━━━━━━━━━━━━━━━━━━",
            "Total auths: {t}".format(t=summary['total_auths']),
            "Distinct IPs: {n}".format(n=summary['distinct_ips']),
            "Distinct countries: {n}".format(n=summary['distinct_countries']),
            "Distinct ASNs: {n}".format(n=summary['distinct_asns']),
            "",
            "<b>Top sources:</b>",
        ]
        for row in rows[:10]:
            last_ts = time.strftime('%m-%d %H:%M', time.localtime(row['last_seen']))
            loc = row['country'] or '?'
            if row['city']:
                loc = "{ct}/{cy}".format(ct=row['country'], cy=row['city'])
            lines.append("<code>{ip}</code> {loc} ASN{asn} ({c}x, {t})".format(
                ip=row['ip'], loc=loc, asn=row['asn'] or '-', c=row['count'], t=last_ts
            ))
        if len(rows) > 10:
            lines.append("...({n} more, use --auth-map for full list)".format(n=len(rows) - 10))

        if self.db.has_open_compromise(username):
            lines.append("")
            lines.append("⚠ OPEN compromise event for this user")

        self._reply('\n'.join(lines))

    def _cmd_suspects(self, args):
        """/suspects [days] [minips]"""
        days = 7
        min_ips = 10
        if len(args) >= 1:
            try:
                days = int(args[0])
            except ValueError:
                pass
        if len(args) >= 2:
            try:
                min_ips = int(args[1])
            except ValueError:
                pass

        rows = self.db.suspect_accounts(days=days, min_distinct_ips=min_ips)
        if not rows:
            self._reply(
                "No accounts with {m}+ distinct source IPs in the last {d} days.".format(
                    m=min_ips, d=days
                )
            )
            return

        lines = [
            "<b>Suspect accounts</b> (last {d}d, {m}+ IPs)".format(d=days, m=min_ips),
            "━━━━━━━━━━━━━━━━━━━━━",
        ]
        for row in rows[:10]:
            status = 'COMPROMISED' if self.db.has_open_compromise(row['username']) else ''
            lines.append(
                "<code>{u}</code> — {ips} IPs, {c}c, {a}a {st}".format(
                    u=row['username'], ips=row['distinct_ips'],
                    c=row['distinct_countries'], a=row['distinct_asns'],
                    st=('⚠ ' + status) if status else ''
                )
            )
        if len(rows) > 10:
            lines.append("...({n} more, use --auth-suspects for full list)".format(n=len(rows) - 10))

        self._reply('\n'.join(lines))

    def _cmd_disable(self, args):
        """/disable <user> [reason]"""
        if not args:
            self._reply("Usage: /disable &lt;user&gt; [reason]")
            return
        if not self.mail_backend or not getattr(self.mail_backend, 'enabled', False):
            self._reply("Mail backend not configured. Cannot disable mailboxes.")
            return

        username = args[0]
        reason = ' '.join(args[1:]).strip() or 'manual Telegram disable'
        try:
            changed = self.mail_backend.disable_mailbox(username)
            self.db.insert_mailbox_action(
                username=username, action='disable',
                actor='telegram:{cid}'.format(cid=self.chat_id),
                reason=reason, success=True,
            )
            if changed:
                self._reply("Disabled mailbox: <code>{u}</code>".format(u=username))
            else:
                self._reply(
                    "Mailbox already disabled or not found: <code>{u}</code>".format(u=username)
                )
        except Exception as e:
            self.db.insert_mailbox_action(
                username=username, action='disable',
                actor='telegram:{cid}'.format(cid=self.chat_id),
                reason=reason, success=False, error_message=str(e),
            )
            self._reply("Failed to disable {u}: {e}".format(u=username, e=str(e)[:200]))

    def _cmd_enable(self, args):
        """/enable <user>"""
        if not args:
            self._reply("Usage: /enable &lt;user&gt;")
            return
        if not self.mail_backend or not getattr(self.mail_backend, 'enabled', False):
            self._reply("Mail backend not configured. Cannot enable mailboxes.")
            return

        username = args[0]
        try:
            changed = self.mail_backend.enable_mailbox(username)
            self.db.insert_mailbox_action(
                username=username, action='enable',
                actor='telegram:{cid}'.format(cid=self.chat_id),
                reason='manual Telegram enable', success=True,
            )
            if changed:
                self._reply("Enabled mailbox: <code>{u}</code>".format(u=username))
            else:
                self._reply(
                    "Mailbox already enabled or not found: <code>{u}</code>".format(u=username)
                )
        except Exception as e:
            self.db.insert_mailbox_action(
                username=username, action='enable',
                actor='telegram:{cid}'.format(cid=self.chat_id),
                reason='manual Telegram enable', success=False, error_message=str(e),
            )
            self._reply("Failed to enable {u}: {e}".format(u=username, e=str(e)[:200]))

    def _cmd_compromises(self, args):
        """/compromises [open]"""
        open_only = bool(args) and args[0].lower() == 'open'
        rows = self.db.list_compromise_events(open_only=open_only, limit=20)
        if not rows:
            self._reply("No compromise events." if not open_only else "No open compromise events.")
            return

        header = "<b>Open compromise events</b>" if open_only else "<b>Compromise events</b>"
        lines = [header, "━━━━━━━━━━━━━━━━━━━━━"]
        for r in rows:
            when = time.strftime('%m-%d %H:%M', time.localtime(r['detected_at']))
            status = 'OPEN' if not r['resolved_at'] else 'resolved'
            lines.append(
                "[{i}] {w} <code>{u}</code> trig={r} act={a} ({s})".format(
                    i=r['id'], w=when, u=r['username'],
                    r=r['trigger_rule'], a=r['action_taken'], s=status
                )
            )
        self._reply('\n'.join(lines))

    def _cmd_resolve(self, args):
        """/resolve <event_id> [note]"""
        if not args:
            self._reply("Usage: /resolve &lt;event_id&gt;")
            return
        try:
            event_id = int(args[0])
        except ValueError:
            self._reply("Invalid event id: {x}".format(x=args[0]))
            return
        event = self.db.get_compromise_event(event_id)
        if not event:
            self._reply("No compromise event with id {i}".format(i=event_id))
            return
        if event['resolved_at']:
            self._reply("Event {i} is already resolved.".format(i=event_id))
            return
        note = ' '.join(args[1:]).strip()
        self.db.resolve_compromise_event(
            event_id,
            resolved_by='telegram:{cid}'.format(cid=self.chat_id),
            note=note,
        )
        self._reply("Resolved compromise event {i} (<code>{u}</code>)".format(
            i=event_id, u=event['username']
        ))

    # ------------------------------------------------------------------
    # v1.4.1 — Telegram verbosity routing
    # ------------------------------------------------------------------
    def _cmd_verbosity(self, args):
        """/verbosity                   — show current rule → level table
        /verbosity <rule> <level>     — set runtime override (immediate|digest|silent)
        /verbosity clear <rule>       — remove one override, fall back to config
        /verbosity reset              — wipe all runtime overrides
        """
        if not self.verbosity_router:
            self._reply("Verbosity router not available.")
            return

        if not args:
            rows = self.verbosity_router.current_map()
            if not rows:
                self._reply("No rules configured.")
                return
            icons = {'immediate': '🔔', 'digest': '📦', 'silent': '🔕'}
            lines = [
                "<b>Telegram verbosity</b>",
                "━━━━━━━━━━━━━━━━━━━━━",
                "<i>🔔 immediate   📦 digest   🔕 silent   🔒 locked</i>",
                "",
            ]
            for rule, level, source in rows:
                lock = ' 🔒' if source == 'locked' else ''
                tag = '' if source == 'default' else f" <i>({source})</i>"
                lines.append(
                    "{ic} <code>{r}</code> → {l}{tag}{lock}".format(
                        ic=icons.get(level, '?'), r=rule, l=level, tag=tag, lock=lock
                    )
                )
            lines.append("")
            lines.append("<i>Change: /verbosity &lt;rule&gt; &lt;level&gt;</i>")
            lines.append("<i>Reset: /verbosity reset</i>")
            self._reply('\n'.join(lines))
            return

        sub = args[0].lower()

        if sub == 'reset':
            ok, msg = self.verbosity_router.reset_all()
            self._reply(msg)
            return

        if sub == 'clear':
            if len(args) < 2:
                self._reply("Usage: /verbosity clear &lt;rule&gt;")
                return
            ok, msg = self.verbosity_router.clear_override(args[1])
            self._reply(msg)
            return

        # /verbosity <rule> <level>
        if len(args) < 2:
            self._reply(
                "Usage:\n"
                "/verbosity — show current settings\n"
                "/verbosity &lt;rule&gt; &lt;level&gt; — set (immediate|digest|silent)\n"
                "/verbosity clear &lt;rule&gt; — remove one override\n"
                "/verbosity reset — wipe all overrides"
            )
            return

        rule = args[0]
        level = args[1]
        ok, msg = self.verbosity_router.set_override(rule, level)
        self._reply(msg)

    # ------------------------------------------------------------------
    # v1.5 — Remote troubleshooting commands
    # ------------------------------------------------------------------
    def _cmd_sites(self, args):
        """Handle /sites — show CMS registry summary or filter by CMS.

        /sites               — summary + first 30 sites
        /sites <cms>         — only sites of that CMS (e.g. /sites joomla)
        """
        if self.cms_registry is None:
            self._reply("CMS registry is not loaded.")
            return

        sites = self.cms_registry.all()
        if not sites:
            self._reply(
                "CMS registry is empty.\n"
                "If the daemon just started, /cmsrefresh forces a rebuild."
            )
            return

        # Tally by CMS
        tally = {}
        for entry in sites.values():
            tally[entry['cms']] = tally.get(entry['cms'], 0) + 1
        tally_lines = ['  {cms}: {n}'.format(cms=k, n=v)
                       for k, v in sorted(tally.items(), key=lambda x: (-x[1], x[0]))]

        # Filter
        cms_filter = args[0].lower() if args else None
        if cms_filter:
            filtered = {s: e for s, e in sites.items() if e['cms'] == cms_filter}
            if not filtered:
                self._reply(
                    "<b>CMS Registry</b> ({total} sites)\n"
                    "━━━━━━━━━━━━━━━━━━━━━\n"
                    "No sites match cms={cms}.\n"
                    "Known: {known}".format(
                        total=len(sites), cms=cms_filter,
                        known=', '.join(sorted(tally.keys()))
                    )
                )
                return
            display = filtered
            header_extra = " (cms={cms})".format(cms=cms_filter)
        else:
            display = sites
            header_extra = ''

        # Format site list, capped to keep Telegram reply short
        max_lines = 30
        site_lines = []
        for site_name in sorted(display.keys())[:max_lines]:
            entry = display[site_name]
            tag = entry['cms']
            if entry.get('overridden'):
                tag += '*'
            site_lines.append('  {site} [{tag}]'.format(site=site_name, tag=tag))

        truncated_note = ''
        if len(display) > max_lines:
            truncated_note = '\n  ... and {n} more'.format(n=len(display) - max_lines)

        msg = (
            "<b>CMS Registry</b>{extra} ({total} sites)\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "{tally}\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "{sites}{trunc}\n"
            "\n"
            "<i>* = overridden via vhosts.conf</i>\n"
            "/site &lt;name&gt; for details · /cmsrefresh to rebuild"
        ).format(
            extra=header_extra,
            total=len(sites),
            tally='\n'.join(tally_lines),
            sites='\n'.join(site_lines) if site_lines else '  (none)',
            trunc=truncated_note,
        )
        self._reply(msg)

    def _cmd_site(self, args):
        """Handle /site <name> — full registry entry for one site."""
        if self.cms_registry is None:
            self._reply("CMS registry is not loaded.")
            return
        if not args:
            self._reply("Usage: /site &lt;site_name&gt;")
            return

        site_name = args[0]
        entry = self.cms_registry.get(site_name)

        # cms_registry.get() always returns a dict; an unknown site has
        # detected_at=0 and empty fields.
        if entry.get('detected_at', 0) == 0 and not entry.get('docroot'):
            self._reply(
                "Site <code>{site}</code> is not in the registry.\n"
                "Use /sites to list known sites, or /cmsrefresh to rebuild.".format(
                    site=site_name
                )
            )
            return

        admin_paths = entry.get('admin_paths') or []
        admin_block = '\n'.join('  ' + p for p in admin_paths) if admin_paths else '  (none)'

        try:
            ts = time.strftime('%Y-%m-%d %H:%M:%S',
                               time.localtime(entry.get('detected_at', 0)))
        except Exception:
            ts = '?'

        msg = (
            "<b>{site}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "CMS: <b>{cms}</b>{ov}\n"
            "Docroot: <code>{docroot}</code>\n"
            "Admin paths:\n"
            "{paths}\n"
            "Detected: {ts}"
        ).format(
            site=site_name,
            cms=entry['cms'],
            ov=' (overridden via vhosts.conf)' if entry.get('overridden') else ' (auto-detected)',
            docroot=entry.get('docroot') or '(unknown)',
            paths=admin_block,
            ts=ts,
        )
        self._reply(msg)

    def _cmd_cmsrefresh(self, args):
        """Handle /cmsrefresh — force a CMS registry rebuild."""
        if self.cms_registry is None:
            self._reply("CMS registry is not loaded.")
            return
        if not getattr(self.cms_registry, 'enabled', False):
            self._reply(
                "CMS registry is disabled in config.\n"
                "Set [cms_detection] enabled = true to use this feature."
            )
            return

        try:
            self.cms_registry.refresh()
        except Exception as e:
            self._reply("CMS refresh failed: {e}".format(e=e))
            return

        sites = self.cms_registry.all()
        tally = {}
        for entry in sites.values():
            tally[entry['cms']] = tally.get(entry['cms'], 0) + 1
        tally_str = ', '.join('{c}={n}'.format(c=k, n=v)
                              for k, v in sorted(tally.items(), key=lambda x: (-x[1], x[0])))
        self._reply(
            "<b>CMS registry refreshed</b>\n"
            "{n} sites: {tally}".format(n=len(sites), tally=tally_str or '(none)')
        )

    def _cmd_logs(self, args):
        """Handle /logs — show what's being tailed and inferred web-server type."""
        if not self.tailers:
            self._reply(
                "No log tailers are running yet.\n"
                "(Either the daemon is still starting, or set_tailers() was not called.)"
            )
            return

        # Group tailers by name
        web_logs = []
        other_lines = []
        for t in self.tailers:
            files = list(getattr(t, 'log_files', []) or [])
            name = getattr(t, 'name', 'tailer')
            if name == 'web':
                web_logs.extend(files)
            else:
                if files:
                    other_lines.append('  {n}: <code>{f}</code>'.format(
                        n=name, f=files[0]
                    ))

        # Infer web-server type from path patterns. We don't have a
        # configured "web_server_type" field — this is a best-effort
        # inference for the operator.
        srv_type = self._infer_web_server(web_logs)

        # Show first 5 web log paths to keep the reply short.
        sample_max = 5
        web_sample = ['  <code>{p}</code>'.format(p=p) for p in web_logs[:sample_max]]
        if len(web_logs) > sample_max:
            web_sample.append('  ... and {n} more'.format(n=len(web_logs) - sample_max))
        if not web_sample:
            web_sample = ['  (none configured)']

        # Auto-discover state
        auto = self.config.getboolean('log_analysis', 'auto_discover', fallback=False)
        auto_str = 'enabled' if auto else 'disabled'
        if auto:
            auto_str += ' (' + self.config.get('log_analysis', 'discover_interval', fallback='24h') + ')'

        # Logfiles list path
        logfiles_path = self.config.get(
            'general', 'logfiles_list',
            fallback=self.base_dir + '/logfiles.txt'
        )

        msg = (
            "<b>WP-Guardian Logs</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "<b>Web</b> ({n} files, server: {srv})\n"
            "{web}\n"
            "\n"
            "<b>Other tailers</b>\n"
            "{other}\n"
            "\n"
            "Logfiles list: <code>{lf}</code>\n"
            "Auto-discover: {auto}"
        ).format(
            n=len(web_logs), srv=srv_type,
            web='\n'.join(web_sample),
            other='\n'.join(other_lines) if other_lines else '  (none)',
            lf=logfiles_path,
            auto=auto_str,
        )
        self._reply(msg)

    def _cmd_serverinfo(self, args):
        """Handle /serverinfo — version, schema, firewall, profile."""
        try:
            schema = self.db.get_schema_version()
        except Exception:
            schema = '?'

        backend_name = type(self.firewall).__name__ if self.firewall else 'none (dry-run)'
        profile = self.config.get('profile', 'mode', fallback='steady')
        dry_run = self.config.getboolean('general', 'dry_run', fallback=False)
        alert_mode = self.config.get('telegram', 'alert_mode', fallback='verbose')
        commands_enabled = self.config.getboolean('telegram', 'commands_enabled', fallback=False)
        cms_enabled = self.config.getboolean('cms_detection', 'enabled', fallback=True)
        post_flood_on = bool(self.post_flood_detector and getattr(self.post_flood_detector, 'enabled', False))
        ssh_root_thr = self.config.getint('thresholds', 'ssh_root_fail_threshold', fallback=0)

        msg = (
            "<b>WP-Guardian Server Info</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "Version: <b>{ver}</b>\n"
            "Schema:  v{schema}\n"
            "Firewall: {fw}\n"
            "Profile: {prof}\n"
            "Dry-run: {dry}\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "<b>v1.5 features</b>\n"
            "CMS auto-detect: {cms}\n"
            "POST-flood: {pf}\n"
            "ssh_root threshold: {sshr}\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "<b>Telegram</b>\n"
            "Commands: {cmds}\n"
            "Alert mode: {am}"
        ).format(
            ver=self.version,
            schema=schema,
            fw=backend_name,
            prof=profile,
            dry='yes' if dry_run else 'no',
            cms='enabled' if cms_enabled else 'disabled',
            pf='enabled' if post_flood_on else 'disabled',
            sshr=ssh_root_thr if ssh_root_thr > 0 else 'disabled',
            cmds='enabled' if commands_enabled else 'disabled',
            am=alert_mode,
        )
        self._reply(msg)

    def _infer_web_server(self, web_logs):
        """Best-effort web-server type inference from configured log paths."""
        if not web_logs:
            return 'unknown'
        markers = {
            'OpenLiteSpeed (CyberPanel)': ['/home/'],
            'OpenLiteSpeed (server-wide)': ['/usr/local/lsws/'],
            'Apache': ['/var/log/httpd/', '/var/log/apache2/'],
            'nginx': ['/var/log/nginx/'],
        }
        for srv, prefixes in markers.items():
            if any(any(p.startswith(pref) for pref in prefixes) for p in web_logs):
                return srv
        return 'unknown'

    def _cmd_help(self, args):
        """Handle /help command."""
        msg = (
            "<b>WP-Guardian Commands</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "/status — current block counts and stats\n"
            "/block &lt;ip|cidr&gt; [duration] — manually block (default: permanent)\n"
            "/unblock &lt;ip&gt; — remove block and reset tier\n"
            "/whitelist &lt;ip&gt; [duration] — add to whitelist\n"
            "/whitelist remove &lt;ip&gt; — remove from whitelist\n"
            "/whitelist list — show all entries\n"
            "/history &lt;ip&gt; — full IP history\n"
            "/tripwires [search] — list/search tripwires\n"
            "/remove &lt;path&gt; — remove a tripwire\n"
            "\n"
            "<b>Compromise detection (v1.4+)</b>\n"
            "/authmap &lt;user&gt; [days] — per-IP auth map\n"
            "/suspects [days] [minips] — suspect accounts\n"
            "/disable &lt;user&gt; [reason] — disable mailbox\n"
            "/enable &lt;user&gt; — re-enable mailbox\n"
            "/compromises [open] — list compromise events\n"
            "/resolve &lt;event_id&gt; [note] — mark event resolved\n"
            "\n"
            "<b>Alert routing (v1.4.1+)</b>\n"
            "/verbosity — show rule → level\n"
            "/verbosity &lt;rule&gt; &lt;level&gt; — set (immediate/digest/silent)\n"
            "/verbosity clear &lt;rule&gt; — remove one override\n"
            "/verbosity reset — wipe all overrides\n"
            "\n"
            "<b>Remote troubleshooting (v1.5+)</b>\n"
            "/sites [cms] — list detected sites (filter by cms)\n"
            "/site &lt;name&gt; — details for one site\n"
            "/cmsrefresh — rebuild the CMS registry now\n"
            "/logs — log files being tailed + web-server type\n"
            "/serverinfo — version, firewall, feature flags\n"
            "\n"
            "/help — this message"
        )
        self._reply(msg)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _reply(self, text):
        """Send a reply message to the configured chat."""
        try:
            url = "https://api.telegram.org/bot{token}/sendMessage".format(
                token=self.bot_token
            )
            payload = {
                'chat_id': self.chat_id,
                'text': text,
                'parse_mode': 'HTML',
                'disable_web_page_preview': True,
            }
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code != 200:
                logger.error(f"Telegram reply failed: {response.status_code} {response.text}")
        except Exception as e:
            logger.error(f"Telegram reply error: {e}")

    def _validate_ip(self, ip):
        """Validate an IPv4 address."""
        if not self._ip_pattern.match(ip):
            return False
        # Check each octet is 0-255
        parts = ip.split('.')
        for part in parts:
            if int(part) > 255:
                return False
        return True

    def _parse_duration(self, text):
        """Parse a duration string like '24h', '7d', '30m' into seconds. Returns None on failure."""
        match = self._duration_pattern.match(text)
        if not match:
            return None

        value = int(match.group(1))
        unit = match.group(2).lower()

        multipliers = {
            'm': 60,
            'h': 3600,
            'd': 86400,
        }
        return value * multipliers.get(unit, 0)
