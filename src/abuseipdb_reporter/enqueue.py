"""Queueing a ban (called from the fail2ban action, runs on every ban)."""
from __future__ import annotations

from typing import Optional

from . import db, iputil, log
from .config import Config


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

    conn = db.connect(cfg.db_path)
    try:
        inserted = db.enqueue(
            conn,
            str(address),
            jail,
            bantime=int(bantime or 0),
            failures=int(failures or 0),
        )
    finally:
        conn.close()
    log.log(
        cfg,
        "enqueue: ip=%s jail=%s bantime=%s failures=%s%s"
        % (address, jail, int(bantime or 0), int(failures or 0), "" if inserted else " (updated)"),
    )
    return True