"""Queueing a ban (called from the fail2ban action, runs on every ban).

The action never blocks the ban, so this module must be both fast and quiet:
expected conditions (invalid address, ignored range, disabled reporter) return
``False`` without noise, and a lock contention with the reporter is retried a
few times with a short exponential backoff instead of losing the event.
"""
from __future__ import annotations

import sqlite3
import time
from typing import Optional

from . import db, iputil, log
from .config import Config

#: How many times a locked database is retried before the event is dropped.
ENQUEUE_RETRIES = 3
#: Base delay for the exponential backoff between retries, seconds.
ENQUEUE_BASE_DELAY = 0.2


def _is_lock_error(error: BaseException) -> bool:
    """True for SQLite contention errors that are worth retrying."""
    text = str(error).lower()
    return "locked" in text or "busy" in text


def store(
    cfg: Config, address: str, jail: str, bantime: int, failures: int
) -> Optional[bool]:
    """Write one event, retrying when the queue is locked.

    Returns ``True`` for a new event, ``False`` when an existing pending event
    was updated, and ``None`` when the write failed for good.
    """
    for attempt in range(ENQUEUE_RETRIES):
        try:
            conn = db.connect(cfg.db_path)
            try:
                return db.enqueue(
                    conn,
                    str(address),
                    jail,
                    bantime=int(bantime or 0),
                    failures=int(failures or 0),
                )
            finally:
                conn.close()
        except sqlite3.OperationalError as error:
            if _is_lock_error(error) and attempt + 1 < ENQUEUE_RETRIES:
                time.sleep(ENQUEUE_BASE_DELAY * (2 ** attempt))
                continue
            log.log(cfg, "enqueue: db error: %r" % (error,))
            return None
        except sqlite3.Error as error:
            log.log(cfg, "enqueue: db error: %r" % (error,))
            return None
    return None


def enqueue_ban(
    cfg: Config,
    ip: str,
    jail: str,
    bantime: int = 0,
    failures: int = 0,
    allow_reserved: bool = False,
) -> bool:
    """Validate and enqueue one ban event.

    Returns ``True`` when the event was queued, ``False`` when it was skipped
    (invalid address, ignored range, skipped jail or disabled reporter).
    Never raises for expected conditions: a reporting failure must never break
    the ban itself.
    """
    address = iputil.parse_ip(ip)
    if address is None:
        log.log(cfg, "enqueue: invalid ip %r - skipped" % (ip,))
        return False
    jail = (jail or "").strip()
    if not jail:
        return False
    if not cfg.enabled:
        return False
    if jail in cfg.skip_jails:
        return False
    if not allow_reserved and iputil.is_ignored(address, cfg.ignore_ranges):
        return False

    inserted = store(cfg, address, jail, bantime, failures)
    if inserted is None:
        return False
    log.log(
        cfg,
        "enqueue: ip=%s jail=%s bantime=%s failures=%s%s"
        % (address, jail, int(bantime or 0), int(failures or 0), "" if inserted else " (updated)"),
    )
    return True
