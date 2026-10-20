"""Command line entry points for ``abuseipdb-report`` and ``abuseipdb-enqueue``."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import api, db, enqueue, log, reporter
from .config import Config, load_config

__version__ = "1.0.0"
LOCK_PATH = "/run/fail2ban-abuseipdb-reporter.lock"


def acquire_lock(path: str = LOCK_PATH):
    """Try to take an exclusive lock.

    Returns a file object when the lock is held, ``None`` when locking is not
    supported (e.g. Windows development machines) and ``False`` when another
    reporter instance is already running.
    """
    try:
        import fcntl
    except ImportError:
        return None
    try:
        handle = open(path, "w")
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        handle.write(str(os.getpid()))
        handle.flush()
        return handle
    except OSError:
        return False


def _stats_text(cfg: Config) -> str:
    import sqlite3
    import time

    conn = db.connect(cfg.db_path)
    try:
        now = int(time.time())
        midnight = int(
            __import__("datetime")
            .datetime.fromtimestamp(now)
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


def _check_key(cfg: Config) -> int:
    if not cfg.api_key:
        print("api_key is empty")
        return 1
    status, body = api.check_key(cfg)
    print("HTTP %s" % status)
    print(body[:500])
    return 0 if status == 200 else 1


def main_report(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="abuseipdb-report",
        description="Send queued fail2ban bans to the AbuseIPDB API (async worker).",
    )
    parser.add_argument("--config", default=None, help="path to reporter.conf")
    parser.add_argument("--db", default=None, help="override queue database path")
    parser.add_argument("--dry-run", action="store_true", help="build payloads, do not call the API")
    parser.add_argument("--check-key", action="store_true", help="validate the API key")
    parser.add_argument("--stats", action="store_true", help="print queue statistics")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = parser.parse_args(argv)

    cfg = load_config(args.config, quiet=args.dry_run)
    if args.db:
        cfg.db_path = args.db

    if args.stats:
        print(_stats_text(cfg))
        return 0
    if args.check_key:
        return _check_key(cfg)

    lock = acquire_lock() if not args.dry_run else None
    if lock is False:
        log.log(cfg, "report: another instance is running, skip")
        return 0

    result = reporter.run_once(cfg, dry_run=args.dry_run)
    if args.dry_run:
        for payload in result.payloads:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
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


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main_report())