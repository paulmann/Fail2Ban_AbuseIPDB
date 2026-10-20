"""Command line entry points for the reporter, the queue helper and the updater."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import List, Optional

from . import api, db, enqueue, keys, log, reporter
from .config import Config, load_config

__version__ = "1.1.0"

#: Lock locations tried in order; the first writable one wins.  ``/run`` is the
#: normal place for a system service, the fallbacks keep the tool usable by an
#: unprivileged user (tests, CI) without silently skipping every run.
LOCK_CANDIDATES = (
    "/run/fail2ban-abuseipdb-reporter.lock",
    "/var/lock/fail2ban-abuseipdb-reporter.lock",
    os.path.join(tempfile.gettempdir(), "fail2ban-abuseipdb-reporter.lock"),
)


def acquire_lock(paths=None):
    """Try to take an exclusive lock.

    ``paths`` may be a single path, a list of candidates, or ``None`` for the
    default list.  Returns a file object when the lock is held, ``None`` when
    locking is not supported (e.g. Windows) or no candidate is writable, and
    ``False`` when another reporter instance already holds the lock.
    """
    try:
        import fcntl
    except ImportError:
        return None
    if paths is None:
        paths = LOCK_CANDIDATES
    elif isinstance(paths, str):
        paths = [paths]
    for path in paths:
        if not path:
            continue
        try:
            handle = open(path, "w")
        except OSError:
            continue  # not writable: try the next candidate
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return False  # held by another instance
        handle.write(str(os.getpid()))
        handle.flush()
        return handle
    return None  # no writable lock path: run without locking


def _stats_text(cfg: Config) -> str:
    import datetime
    import sqlite3
    import time

    conn = db.connect(cfg.db_path)
    try:
        now = int(time.time())
        midnight = int(
            datetime.datetime.fromtimestamp(now)
            .replace(hour=0, minute=0, second=0, microsecond=0)
            .timestamp()
        )
        lines = ["db: %s" % cfg.db_path]
        for label, query, args in (
            ("pending events", "SELECT COUNT(*) FROM events WHERE reported=0", ()),
            ("pending ips", "SELECT COUNT(DISTINCT ip) FROM events WHERE reported=0", ()),
            ("invalid (2)", "SELECT COUNT(*) FROM events WHERE reported=2", ()),
            ("gave up (3)", "SELECT COUNT(*) FROM events WHERE reported=3", ()),
            (
                "reports today",
                "SELECT COUNT(*) FROM reports WHERE status=200 AND reported_at>=?",
                (midnight,),
            ),
            ("reports total", "SELECT COUNT(*) FROM reports WHERE status=200", ()),
        ):
            value = conn.execute(query, args).fetchone()[0]
            lines.append("%-15s %s" % (label + ":", value))
        lines.append("last reports:")
        for row in conn.execute(
            "SELECT ip, jail, reported_at, status FROM reports ORDER BY id DESC LIMIT 8"
        ):
            lines.append(
                "  %-16s %-22s %s status=%s"
                % (row["ip"], row["jail"], row["reported_at"], row["status"])
            )
    finally:
        conn.close()

    try:
        f2b = sqlite3.connect("file:%s?mode=ro" % cfg.fail2ban_db, uri=True, timeout=5)
        try:
            count = f2b.execute("SELECT COUNT(*) FROM bips").fetchone()[0]
            lines.append("fail2ban current bans: %s" % count)
        finally:
            f2b.close()
    except sqlite3.Error as error:
        lines.append("fail2ban db: %r" % (error,))
    return "\n".join(lines)


def _key_status(cfg: Config) -> str:
    try:
        key, source = keys.resolve_api_key(cfg, prompt=False)
    except keys.ApiKeyMissing:
        return "API key not configured (expected at %s)" % keys.key_file_path(cfg)
    return "API key source: %s\nkey: %s" % (source, keys.mask_key(key))


def _check_key(cfg: Config, no_prompt: bool = False) -> int:
    try:
        key, source = keys.resolve_api_key(
            cfg, prompt=not no_prompt, interactive=None
        )
    except keys.ApiKeyMissing as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    api_cfg = cfg
    api_cfg.api_key = key
    status, body = api.check_key(api_cfg)
    print("key source: %s" % source)
    print("HTTP %s" % status)
    print(body[:500])
    return 0 if status == 200 else 1


def _resolve_key_for_run(cfg: Config, cli_key: Optional[str], no_prompt: bool) -> Optional[str]:
    try:
        key, source = keys.resolve_api_key(cfg, cli_key=cli_key, prompt=not no_prompt)
    except keys.ApiKeyMissing as error:
        log.log(cfg, "report: ERROR %s" % error)
        return None
    for warning in keys.validate_key(key):
        log.log(cfg, "report: warning: %s" % warning)
    log.log(cfg, "report: API key source: %s (%s)" % (source, keys.mask_key(key)))
    return key


def main_report(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="abuseipdb-report",
        description="Send queued fail2ban bans to the AbuseIPDB API (async worker).",
    )
    parser.add_argument("--config", default=None, help="path to reporter.conf")
    parser.add_argument("--db", default=None, help="override queue database path")
    parser.add_argument("--api-key", default=None, help="one-off API key (not persisted)")
    parser.add_argument("--dry-run", action="store_true", help="build payloads, do not call the API")
    parser.add_argument("--check-key", action="store_true", help="validate the API key")
    parser.add_argument("--stats", action="store_true", help="print queue statistics")
    parser.add_argument("--setup", action="store_true", help="ask for the API key and save it")
    parser.add_argument(
        "--migrate-key",
        action="store_true",
        help="move a legacy api_key from the config into the key file",
    )
    parser.add_argument("--key-status", action="store_true", help="show the API key source")
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="never ask for the key interactively (for systemd/cron)",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = parser.parse_args(argv)

    cfg = load_config(args.config, quiet=args.dry_run)
    if args.db:
        cfg.db_path = args.db

    if args.setup:
        try:
            keys.prompt_and_save(keys.key_file_path(cfg))
        except keys.ApiKeyMissing as error:
            print("error: %s" % error, file=sys.stderr)
            return 2
        return 0

    if args.migrate_key:
        try:
            migrated = keys.migrate_legacy_key(cfg, args.config or cfg.path)
        except (RuntimeError, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 1
        print("Legacy api_key moved to %s" % keys.key_file_path(cfg) if migrated
              else "No legacy api_key found; nothing to migrate")
        return 0

    if args.key_status:
        print(_key_status(cfg))
        return 0

    if args.stats:
        print(_stats_text(cfg))
        return 0
    if args.check_key:
        return _check_key(cfg, no_prompt=args.no_prompt)

    if args.dry_run:
        result = reporter.run_once(cfg, dry_run=True)
        for payload in result.payloads:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0

    key = _resolve_key_for_run(cfg, args.api_key, args.no_prompt)
    if key is None:
        return 2
    cfg.api_key = key

    lock = acquire_lock()
    if lock is False:
        log.log(cfg, "report: another instance is running, skip")
        return 0

    reporter.run_once(cfg)
    return 0


def main_enqueue(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="abuseipdb-enqueue",
        description="Queue a fail2ban ban for asynchronous AbuseIPDB reporting.",
    )
    parser.add_argument("--ip", required=True, help="banned IP address")
    parser.add_argument("--jail", required=True, help="fail2ban jail name")
    parser.add_argument("--bantime", default="0", help="ban duration in seconds")
    parser.add_argument("--failures", default="0", help="number of failures that triggered the ban")
    parser.add_argument("--config", default=None, help="path to reporter.conf")
    parser.add_argument("--db", default=None, help="override queue database path")
    parser.add_argument(
        "--allow-reserved", action="store_true", help="allow non-public IPs (tests only)"
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = parser.parse_args(argv)

    def as_int(value, default=0):
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return default

    cfg = load_config(args.config)
    if args.db:
        cfg.db_path = args.db
    try:
        enqueue.enqueue_ban(
            cfg,
            args.ip,
            args.jail,
            bantime=as_int(args.bantime),
            failures=as_int(args.failures),
            allow_reserved=args.allow_reserved,
        )
    except Exception as error:  # noqa: BLE001 - a ban must never fail because of reporting
        log.log(cfg, "enqueue: ERROR %r" % (error,))
    return 0


def main_upgrade(argv: Optional[List[str]] = None) -> int:
    from .updater import main_upgrade as _main_upgrade

    return _main_upgrade(argv)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main_report())