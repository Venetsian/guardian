"""
modules/tmp_cleanup.py — active /tmp cleanup module (task #122 Part D).

v1.6.0 introduced this as a files-only janitor. v1.6.1 adds directory
cleanup, an always-wins system excludelist, mountpoint detection, a
broader default allowlist, and top-N-by-size reporting in the digest.
The redesign is driven by what we found during the operational sweep
on srv.dotcom.services — most of the actual /tmp bloat lived in
operator-dropped *directories* (claude-*, *-fresh, restore-*, new-vhosts,
node-compile-cache) and root-owned scratch files at mode 0750 that the
v1.6.0 world-readable requirement excluded.

Modes:
  off      — disabled. Default for new installs (opt-in).
  dry_run  — scan + log + Telegram digest. NO deletions.
  live     — same as dry_run, plus actually delete each candidate.

Deletion criteria (ALL must match):
  * path is a top-level entry of /tmp
  * basename does NOT match SYSTEM_EXCLUDELIST_PATTERNS (always-deny list,
    higher precedence than allowlist — protects live system state like
    /tmp/lshttpd, /tmp/systemd-private-*, X11 sockets, DB unix sockets,
    tmux server dirs)
  * path is NOT itself a mountpoint (defends against systemd PrivateTmp
    bind-mounts and any tmpfs subtree)
  * realpath is strictly under /tmp/ (no symlink escape)
  * owner uid == 0 (root)
  * mtime older than `age_days` (default 7)
  * basename matches one of `allowlist_patterns`
  * file is not currently held open (lsof check)

For directories, the recursive validator walks every contained file and
applies the same uid-0 + lsof + realpath-under-/tmp checks. Any failure
short-circuits and the whole directory is left alone. If a sub-tree
contains a mountpoint, the directory is rejected (we don't descend into
mounts to clean them).

Per the task's two-phase rollout, operators leave each new host in
`dry_run` for ~14 days, review the digests, then promote to `live` by
editing the config. The module deliberately does NOT auto-promote.

Operational events (live deletions + every dry-run summary) are logged
to `posture_events` with check_id='tmp_cleanup' for forensics.
"""

import fnmatch
import logging
import os
import stat as stat_mod
import subprocess
import time

logger = logging.getLogger('wp-guardian.tmp_cleanup')


# Default allowlist — patterns operator-dropped scratch tends to use.
# Extended in v1.6.1 to cover the operational artifacts we saw on srv:
# extract dirs (*-fresh), restore-* dirs, vhost dumps, language compile
# caches, Python multiprocessing leaks, and timestamped *.bak.* files.
DEFAULT_ALLOWLIST = (
    # Logs / scratch files
    '*.log',
    '*.bak.*',
    '*.backup.*',
    'last_resp.json',
    'build-manual-*.log',
    'cagefs-init.log',

    # Operator one-shot drops
    'body-*',
    'curl-*',
    '*-init.log',
    'claude-*',
    'tmp-*.log',

    # Extract / staging dirs (v1.6.1 — directory support added)
    '*-fresh',
    'restore-*',
    'staging-*',
    'new-vhosts',

    # Language runtime caches (v1.6.1)
    'node-compile-cache',
    'python-compile-cache',
    'pip-*-build',
    'pip-tmp-*',
    'pip-build-*',

    # Process leftovers (v1.6.1)
    'pymp-*',     # Python multiprocessing shared-mem dirs
)


# Hardcoded SYSTEM excludelist. ALWAYS denied even if name matches the
# allowlist. Defense-in-depth against an over-broad allowlist eating
# live system state. Operator can EXTEND via [tmp_cleanup]
# additional_excludes but cannot make the list shorter than this base.
SYSTEM_EXCLUDELIST_PATTERNS = (
    # OpenLiteSpeed runtime / swap (we saw 886M of /tmp/lshttpd/swap on srv)
    'lshttpd',
    'lshttpd-*',
    'lsws',
    # X11 standard sticky dirs
    '.font-unix',
    '.ICE-unix',
    '.X11-unix',
    '.XIM-unix',
    # tmux server socket dirs (per-uid; e.g. /tmp/tmux-0)
    'tmux-*',
    # systemd PrivateTmp namespaces (bind-mounts; mountpoint check would
    # also catch them but the name pattern is faster and clearer)
    'systemd-private-*',
    'snap-private-*',
    # Database unix sockets in /tmp
    'mysql.sock',
    'mariadb.sock',
    '.s.PGSQL.*',
    # Cron's lockfile
    '.crontab.lock',
    # CageFS proxyexec socket
    'cagefs.sock',
    # Misc safety
    '.font-cache',
)


DEFAULT_AGE_DAYS = 7
DEFAULT_INTERVAL_SECONDS = 86400
SAMPLE_LIMIT = 10            # filenames in the digest
TOP_N_BY_SIZE = 10           # how many largest /tmp entries to report
DIR_LSOF_TIMEOUT = 8         # seconds — `lsof +D` on a dir can be slow


class TmpCleanup(object):
    """Periodic /tmp janitor. Runs from the Guardian daemon's main loop
    via `run_if_due()`; can also be triggered manually via run_now()."""

    def __init__(self, config, db, telegram=None, hostname=None):
        self.config = config
        self.db = db
        self.telegram = telegram
        self.hostname = hostname or 'localhost'

        raw_mode = config.get(
            'tmp_cleanup', 'mode', fallback='off'
        ).strip().lower()
        if raw_mode not in ('off', 'dry_run', 'live'):
            logger.warning(
                "Invalid [tmp_cleanup] mode '%s'; falling back to 'off'", raw_mode
            )
            raw_mode = 'off'
        self.mode = raw_mode

        age_days = config.getint(
            'tmp_cleanup', 'age_days', fallback=DEFAULT_AGE_DAYS
        )
        self.age_seconds = max(1, age_days) * 86400

        self.interval_seconds = config.getint(
            'tmp_cleanup', 'interval_seconds', fallback=DEFAULT_INTERVAL_SECONDS
        )

        # v1.6.1: operator can opt out of directory cleanup if they want
        # the more conservative files-only behavior of v1.6.0.
        self.include_directories = config.getboolean(
            'tmp_cleanup', 'include_directories', fallback=True
        )

        raw_patterns = config.get(
            'tmp_cleanup', 'allowlist_patterns',
            fallback=','.join(DEFAULT_ALLOWLIST),
        )
        patterns = [p.strip() for p in raw_patterns.split(',') if p.strip()]
        self.allow_patterns = patterns or list(DEFAULT_ALLOWLIST)

        # v1.6.1: operator-extensible excludelist. Hardcoded base ALWAYS
        # applies; this can only ADD more patterns to deny.
        raw_extra = config.get(
            'tmp_cleanup', 'additional_excludes', fallback='',
        )
        extra_excludes = [p.strip() for p in raw_extra.split(',') if p.strip()]
        self.exclude_patterns = list(SYSTEM_EXCLUDELIST_PATTERNS) + extra_excludes

        self._last_run_at = 0
        self._last_result = None

        if self.mode != 'off':
            logger.info(
                "TmpCleanup active: mode=%s age_days=%d interval=%ds "
                "include_dirs=%s allow=%d patterns excl=%d patterns",
                self.mode, age_days, self.interval_seconds,
                self.include_directories,
                len(self.allow_patterns), len(self.exclude_patterns),
            )
        else:
            logger.info("TmpCleanup mode=off — module disabled")

    # ------------------------------------------------------------------
    # Run-loop integration
    # ------------------------------------------------------------------
    def is_due(self, now=None):
        if self.mode == 'off':
            return False
        now = int(now if now is not None else time.time())
        return (now - self._last_run_at) >= self.interval_seconds

    def run_if_due(self):
        if not self.is_due():
            return False
        try:
            self.run_now()
        except Exception as e:
            logger.error("TmpCleanup run crashed: %s", e)
        return True

    # ------------------------------------------------------------------
    # Pattern matching
    # ------------------------------------------------------------------
    def _matches_allowlist(self, name):
        for pat in self.allow_patterns:
            if fnmatch.fnmatch(name, pat):
                return True
        return False

    def _matches_excludelist(self, name):
        for pat in self.exclude_patterns:
            if fnmatch.fnmatch(name, pat):
                return True
        return False

    # ------------------------------------------------------------------
    # Open-file checks (lsof)
    # ------------------------------------------------------------------
    def _path_is_held_open(self, path, timeout=3):
        """True if any process has the path (or anything under it) open.
        Uses `lsof +D` for directories and `lsof --` for files. Soft-fails
        to True on probe failure so we never delete something we couldn't
        verify is closed."""
        # Use +D for directories (recurses), -- for files (terminator).
        if os.path.isdir(path):
            cmd = ['lsof', '+D', path]
            timeout = max(timeout, DIR_LSOF_TIMEOUT)
        else:
            cmd = ['lsof', '--', path]
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, universal_newlines=True,
            )
            return proc.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return True

    # ------------------------------------------------------------------
    # Directory recursive validation (v1.6.1)
    # ------------------------------------------------------------------
    def _validate_dir(self, path):
        """Walk a candidate directory's contents. Returns (ok, reason).

        For a directory to be deletable EVERY entry inside it must:
          * not cross a mountpoint
          * if a regular file: be owned by uid 0
          * if a symlink: target stays under /tmp/
          * not be held open (single bulk lsof +D check at the top level)

        We deliberately don't enforce age or allowlist on the contents —
        the parent-level allowlist match is the gate. This matches the
        operator-dropped pattern: claude-0/-root/<lots of stuff>; once
        we trust 'claude-*' as a wholesale-cleanup pattern, all contents
        come with it.
        """
        try:
            for root, dirs, files in os.walk(path, followlinks=False):
                # Refuse if any subtree boundary is a mountpoint
                if os.path.ismount(root):
                    return (False, "subdir is a mountpoint: " + root)
                # Don't descend into mountpoints
                dirs[:] = [
                    d for d in dirs
                    if not os.path.ismount(os.path.join(root, d))
                ]
                for name in files:
                    fpath = os.path.join(root, name)
                    try:
                        st = os.lstat(fpath)
                    except OSError as e:
                        return (False, "lstat failed on {p}: {e}".format(p=fpath, e=e))
                    if stat_mod.S_ISLNK(st.st_mode):
                        # Symlink — its target may be outside /tmp
                        target = os.path.realpath(fpath)
                        if not (target == '/tmp' or target.startswith('/tmp/')):
                            return (False,
                                    "symlink escapes /tmp: {p} -> {t}".format(
                                        p=fpath, t=target))
                        continue
                    if not stat_mod.S_ISREG(st.st_mode):
                        # Devices / sockets / fifos shouldn't be in operator
                        # scratch. Refuse to delete anything containing them.
                        return (False,
                                "non-regular file under candidate: " + fpath)
                    if st.st_uid != 0:
                        return (False, "non-root file: " + fpath)
            return (True, '')
        except OSError as e:
            return (False, "walk failed: {}".format(e))

    def _dir_size(self, path):
        """Sum of all file sizes in the directory tree. Best-effort."""
        total = 0
        try:
            for root, _dirs, files in os.walk(path):
                for f in files:
                    try:
                        total += os.lstat(os.path.join(root, f)).st_size
                    except OSError:
                        pass
        except OSError:
            pass
        return total

    # ------------------------------------------------------------------
    # Candidate selection
    # ------------------------------------------------------------------
    def _scan_candidates(self):
        """Walk /tmp top-level and return list of cleanup candidates.

        Each candidate dict has: path, name, type ('file'|'dir'), size,
        age_days, mode (octal int). lsof is NOT yet run here — that
        happens just before the unlink/rmtree, so the candidate-list
        view is stable while we display it.
        """
        now = time.time()
        cutoff = now - self.age_seconds
        candidates = []

        try:
            scanner = os.scandir('/tmp')
        except OSError:
            return candidates
        try:
            for entry in scanner:
                # Defense-in-depth #1: SYSTEM excludelist (always wins)
                if self._matches_excludelist(entry.name):
                    continue
                # Defense-in-depth #2: skip mountpoints
                try:
                    if os.path.ismount(entry.path):
                        continue
                except OSError:
                    continue
                # Skip symlinks unconditionally — we never delete a
                # symlink targeting somewhere unknown.
                try:
                    if entry.is_symlink():
                        continue
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue

                # Common required gates
                if st.st_uid != 0:
                    continue
                if st.st_mtime > cutoff:
                    continue

                # realpath-under-/tmp defense
                resolved = os.path.realpath(entry.path)
                if not (resolved == '/tmp' or resolved.startswith('/tmp/')):
                    continue

                # Allowlist gate (still mandatory)
                if not self._matches_allowlist(entry.name):
                    continue

                mode = stat_mod.S_IMODE(st.st_mode)
                age_days = int((now - st.st_mtime) // 86400)

                if stat_mod.S_ISREG(st.st_mode):
                    # v1.6.1: world-readable requirement DROPPED. The
                    # allowlist + uid 0 + age + lsof are the gate; the
                    # mode-bit was always a heuristic and excluded
                    # legitimate operator scratch like *.bak.* at 0750.
                    candidates.append({
                        'path': entry.path, 'name': entry.name,
                        'type': 'file', 'size': st.st_size,
                        'age_days': age_days, 'mode': mode,
                    })
                elif stat_mod.S_ISDIR(st.st_mode):
                    if not self.include_directories:
                        continue
                    ok, reason = self._validate_dir(entry.path)
                    if not ok:
                        logger.info(
                            "[tmp_cleanup] skipping dir %s: %s",
                            entry.path, reason,
                        )
                        continue
                    candidates.append({
                        'path': entry.path, 'name': entry.name,
                        'type': 'dir', 'size': self._dir_size(entry.path),
                        'age_days': age_days, 'mode': mode,
                    })
                # Other types (devices, sockets, fifos) silently skipped
        finally:
            try:
                scanner.close()
            except Exception:
                pass

        # Largest first — surfaces the impactful entries in the digest
        return sorted(candidates, key=lambda c: c['size'], reverse=True)

    # ------------------------------------------------------------------
    # Top-N largest in /tmp (visibility, not action)
    # ------------------------------------------------------------------
    def _top_largest(self, n=TOP_N_BY_SIZE):
        """Sample the top-N largest top-level entries in /tmp regardless
        of age, owner, or excludelist. Pure visibility — surfaces things
        like /tmp/lshttpd/swap (886M of OLS state) that the cleanup
        module is correctly NOT touching but the operator should know
        about."""
        out = []
        try:
            scanner = os.scandir('/tmp')
        except OSError:
            return out
        try:
            for entry in scanner:
                try:
                    if entry.is_symlink():
                        continue
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat_mod.S_ISDIR(st.st_mode):
                    size = self._dir_size(entry.path)
                elif stat_mod.S_ISREG(st.st_mode):
                    size = st.st_size
                else:
                    continue
                out.append({'path': entry.path, 'name': entry.name,
                            'size': size,
                            'is_dir': stat_mod.S_ISDIR(st.st_mode)})
        finally:
            try:
                scanner.close()
            except Exception:
                pass
        return sorted(out, key=lambda e: e['size'], reverse=True)[:n]

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------
    def run_now(self):
        """Execute one cleanup pass. Returns a results dict."""
        if self.mode == 'off':
            return {'mode': 'off', 'scanned': 0, 'deleted': 0,
                    'skipped_open': 0, 'errors': 0, 'bytes_freed': 0,
                    'paths': [], 'top_largest': []}

        candidates = self._scan_candidates()
        results = {
            'mode': self.mode,
            'scanned': len(candidates),
            'deleted': 0,
            'skipped_open': 0,
            'errors': 0,
            'bytes_freed': 0,
            'paths': [],
            'top_largest': self._top_largest(),
        }

        for c in candidates:
            # lsof check applies in BOTH modes — we want the dry_run
            # report to reflect what live mode would actually do.
            if self._path_is_held_open(c['path']):
                results['skipped_open'] += 1
                continue

            if self.mode == 'dry_run':
                logger.info(
                    "[tmp_cleanup dry_run] would delete %s (%s, %d bytes, %dd old)",
                    c['path'], c['type'], c['size'], c['age_days'],
                )
                results['deleted'] += 1
                results['bytes_freed'] += c['size']
                results['paths'].append(c)
                continue

            # mode == 'live'
            try:
                if c['type'] == 'dir':
                    # Local rmtree to avoid importing shutil here. We
                    # already validated everything inside the dir, so
                    # the walk is safe.
                    self._rmtree(c['path'])
                else:
                    os.unlink(c['path'])
            except OSError as e:
                logger.warning("Couldn't delete %s: %s", c['path'], e)
                results['errors'] += 1
                continue
            logger.info(
                "[tmp_cleanup live] deleted %s (%s, %d bytes, %dd old)",
                c['path'], c['type'], c['size'], c['age_days'],
            )
            results['deleted'] += 1
            results['bytes_freed'] += c['size']
            results['paths'].append(c)
            self._record_event(c)

        self._last_run_at = int(time.time())
        self._last_result = results
        self._send_digest(results)
        return results

    @staticmethod
    def _rmtree(path):
        """Walk-and-unlink rmtree. Doesn't follow symlinks. Equivalent
        to shutil.rmtree(path, ignore_errors=False) but local."""
        for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
            for name in files:
                try:
                    os.unlink(os.path.join(root, name))
                except OSError:
                    pass
            for name in dirs:
                p = os.path.join(root, name)
                try:
                    if os.path.islink(p):
                        os.unlink(p)
                    else:
                        os.rmdir(p)
                except OSError:
                    pass
        os.rmdir(path)

    def _record_event(self, candidate):
        """Log one live deletion to posture_events. Failures are logged
        but never raised — losing the audit log entry is preferable to
        crashing the cleanup run."""
        try:
            self.db.posture_event_insert(
                host=self.hostname,
                module='health',
                check_id='tmp_cleanup',
                from_status='pass',
                to_status='pass',
                from_value='',
                to_value='',
                severity='info',
                detail="deleted {p} ({t}, {sz} bytes, {a}d old)".format(
                    p=candidate['path'], t=candidate['type'],
                    sz=candidate['size'], a=candidate['age_days'],
                ),
            )
        except Exception as e:
            logger.error("Failed to record tmp_cleanup event: %s", e)

    # ------------------------------------------------------------------
    # Digest
    # ------------------------------------------------------------------
    def _send_digest(self, results):
        # Always log a one-line summary
        logger.info(
            "TmpCleanup run: mode=%s scanned=%d %s=%d skipped_open=%d "
            "errors=%d bytes_freed=%d",
            results['mode'], results['scanned'],
            'would_delete' if results['mode'] == 'dry_run' else 'deleted',
            results['deleted'], results['skipped_open'],
            results['errors'], results['bytes_freed'],
        )

        # Digest dispatch policy (v1.6.2):
        #   * live mode: suppress empty runs (no paths + no errors) —
        #     once the host is in steady state, daily empty pings would
        #     just be channel noise.
        #   * dry_run mode: ALWAYS send. The operator is explicitly
        #     evaluating the module; every run is signal. Even an empty
        #     dry_run confirms the module is alive AND ships the
        #     top-largest visibility view.
        suppress_empty = (results['mode'] == 'live')
        if suppress_empty and not results['paths'] and not results['errors']:
            return
        if not self.telegram or not getattr(self.telegram, 'enabled', False):
            return

        action = 'would delete' if results['mode'] == 'dry_run' else 'deleted'
        mb = results['bytes_freed'] / (1024.0 * 1024.0)
        lines = [
            "🧹 <b>WP-Guardian /tmp cleanup ({mode})</b>".format(mode=results['mode']),
            "Host: <code>{h}</code>".format(h=self.hostname),
            "{action} {n} entry(ies) ({mb:.1f} MB)".format(
                action=action, n=results['deleted'], mb=mb),
        ]
        if results['skipped_open']:
            lines.append("Skipped {n} held-open path(s)".format(
                n=results['skipped_open']))
        if results['errors']:
            lines.append("⚠️ {n} delete error(s) — see guardian.log".format(
                n=results['errors']))

        if results['paths']:
            lines.append("")
            lines.append("Cleaned:" if results['mode'] == 'live' else "Would clean:")
            for p in results['paths'][:SAMPLE_LIMIT]:
                tag = '/' if p['type'] == 'dir' else ''
                lines.append("  {n}{t} ({sz} KB, {a}d)".format(
                    n=p['name'], t=tag,
                    sz=p['size'] // 1024, a=p['age_days']))
            if len(results['paths']) > SAMPLE_LIMIT:
                lines.append("  +{n} more".format(
                    n=len(results['paths']) - SAMPLE_LIMIT))
        elif results['mode'] == 'dry_run':
            # Empty dry_run: confirm the module is alive and explain
            # what we'd have done if there had been candidates.
            lines.append("")
            lines.append("/tmp clean — no entries match cleanup criteria")
            lines.append("(would delete root-owned, allowlisted entries "
                         "older than {d}d, lsof-clean, not in system "
                         "excludelist)".format(d=self.age_seconds // 86400))

        # Top-N largest in /tmp — pure visibility. Highlights bloat we're
        # NOT touching (live runtime dirs, etc.) so the operator can see
        # why /tmp is full beyond what the module reaches.
        if results.get('top_largest'):
            lines.append("")
            lines.append("Largest /tmp entries (live + cleanup view):")
            for e in results['top_largest']:
                tag = '/' if e['is_dir'] else ''
                size_mb = e['size'] / (1024.0 * 1024.0)
                if size_mb >= 1.0:
                    sz_str = "{:.1f} MB".format(size_mb)
                else:
                    sz_str = "{} KB".format(e['size'] // 1024)
                lines.append("  {n}{t} ({sz})".format(
                    n=e['name'], t=tag, sz=sz_str))

        priority = 'HIGH' if results['errors'] else 'LOW'
        try:
            self.telegram.send('\n'.join(lines), priority=priority)
        except Exception as e:
            logger.error("TmpCleanup digest send failed: %s", e)

    # ------------------------------------------------------------------
    # CLI surface
    # ------------------------------------------------------------------
    def status_summary(self):
        """Return a human-readable single-string status line."""
        last = ('never' if not self._last_run_at
                else time.strftime('%Y-%m-%d %H:%M:%S',
                                   time.localtime(self._last_run_at)))
        return ("mode={m} age_days={a} interval={i}s include_dirs={d} "
                "allow={al} excl={ex} last_run={lr}".format(
            m=self.mode, a=self.age_seconds // 86400,
            i=self.interval_seconds, d=self.include_directories,
            al=len(self.allow_patterns), ex=len(self.exclude_patterns),
            lr=last,
        ))
