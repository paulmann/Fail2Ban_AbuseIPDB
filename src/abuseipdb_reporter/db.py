"""Local SQLite queue and report journal.

The queue is deliberately simple: one row per ban event, one row per API
attempt.  SQLite (WAL mode) is used because it is available everywhere,
survives reboots and needs no extra service.
"""
from __future__ import annotations

import os
import sqlite3
import time
from typing import Iterable, List, Optional, Sequence

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    jail TEXT NOT NULL,
    event_time INTEGER NOT NULL,
    bantime INTEGER NOT NULL DEFAULT 0,
    failures INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    reported INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    pushed INTEGER NOT NULL DEFAULT 0,
    origin TEXT NOT NULL DEFAULT '',
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_pending ON events(reported, ip);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip, event_time);
CREATE INDEX IF NOT EXISTS idx_events_push ON events(reported, pushed);
CREATE INDEX IF NOT EXISTS idx_events_origin ON events(created_at, origin);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    jail TEXT,
    reported_at INTEGER NOT NULL,
    status INTEGER NOT NULL,
    categories TEXT,
    comment TEXT,
    response TEXT
);
CREATE INDEX IF NOT EXISTS idx_reports_ip ON reports(ip, reported_at);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status, reported_at);

-- IPs recently reported by this node or by a peer (coordination, 1.4.0):
-- kept locally so a node never sends a second report for one address inside the
-- AbuseIPDB window, not even right after a role change or a failover.
CREATE TABLE IF NOT EXISTS reported_cache (
    ip TEXT PRIMARY KEY,
    reported_at INTEGER NOT NULL,
    source TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_reported_at ON reported_cache(reported_at);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

#: event.reported states
PENDING = 0
REPORTED = 1
INVALID = 2
GAVE_UP = 3


def connect(path: str) -> sqlite3.Connection:
    """Open (and initialise) the queue database.

    Older queue files are migrated in place: the ``pushed`` column (added in
    1.3.0 for leader/follower coordination) is created when missing, so an
    upgrade never loses or rewrites existing events.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    # Upgrade an existing queue **before** the schema script runs: the script also
    # creates an index on the new column, which would fail on an old table.
    _migrate(conn)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the first release (idempotent)."""
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    if "events" not in tables:
        return  # a brand-new database: SCHEMA already contains the column
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
    if "pushed" not in columns:
        conn.execute("ALTER TABLE events ADD COLUMN pushed INTEGER NOT NULL DEFAULT 0")
    if "origin" not in columns:
        conn.execute("ALTER TABLE events ADD COLUMN origin TEXT NOT NULL DEFAULT ''")
    conn.commit()


def enqueue(
    conn: sqlite3.Connection,
    ip: str,
    jail: str,
    event_time: Optional[int] = None,
    bantime: int = 0,
    failures: int = 0,
    dedupe_window: int = 300,
    origin: str = "",
) -> bool:
    """Insert a ban event, collapsing repeated bans of the same IP+jail.

    ``origin`` names the node that reported the ban (empty for local bans) and is
    what the coordination endpoint uses to avoid sending a ban straight back to
    the node it came from.

    Returns True when a new row was inserted, False when an existing pending
    row was updated (deduplication window).
    """
    now = int(event_time if event_time is not None else time.time())
    bantime = int(bantime or 0)
    failures = int(failures or 0)
    origin = str(origin or "")[:64]
    row = conn.execute(
        "SELECT id FROM events WHERE ip=? AND jail=? AND reported=? AND pushed=0 AND created_at>=?"
        " ORDER BY id DESC LIMIT 1",
        (ip, jail, PENDING, now - dedupe_window),
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE events SET event_time=?, bantime=?, failures=? WHERE id=?",
            (now, bantime, failures, row["id"]),
        )
        conn.commit()
        return False
    conn.execute(
        "INSERT INTO events(ip, jail, event_time, bantime, failures, created_at, origin)"
        " VALUES (?,?,?,?,?,?,?)",
        (ip, jail, now, bantime, failures, now, origin),
    )
    conn.commit()
    return True


def pending_ips(
    conn: sqlite3.Connection, max_attempts: int, limit: int
) -> List[sqlite3.Row]:
    """Return IPs with pending events (oldest first)."""
    return conn.execute(
        "SELECT ip, COUNT(*) AS n, MIN(event_time) AS first FROM events"
        " WHERE reported=? AND pushed=0 AND attempts<? GROUP BY ip ORDER BY first ASC LIMIT ?",
        (PENDING, max_attempts, limit),
    ).fetchall()


def events_for(conn: sqlite3.Connection, ip: str) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM events WHERE ip=? AND reported=? AND pushed=0 ORDER BY event_time",
        (ip, PENDING),
    ).fetchall()


def last_success(conn: sqlite3.Connection, ip: str) -> int:
    row = conn.execute(
        "SELECT MAX(reported_at) FROM reports WHERE ip=? AND status=200", (ip,)
    ).fetchone()
    return int(row[0] or 0)


def reports_today(conn: sqlite3.Connection, now: int, timezone: str = "utc") -> int:
    """Reports accepted since the budget day started (same rule as the reporter)."""
    import datetime

    if str(timezone).strip().lower() in ("local", "localtime"):
        moment = datetime.datetime.fromtimestamp(int(now))
        start = int(moment.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    else:
        moment = datetime.datetime.fromtimestamp(int(now), tz=datetime.timezone.utc)
        start = int(moment.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    return reported_since(conn, start)


def reported_since(conn: sqlite3.Connection, since: int) -> int:
    return int(
        conn.execute(
            "SELECT COUNT(*) FROM reports WHERE status=200 AND reported_at>=?", (since,)
        ).fetchone()[0]
    )


def record_attempt(
    conn: sqlite3.Connection,
    ip: str,
    jail: str,
    status: int,
    categories: str,
    comment: str,
    response: str,
    reported_at: Optional[int] = None,
) -> None:
    conn.execute(
        "INSERT INTO reports(ip, jail, reported_at, status, categories, comment, response)"
        " VALUES (?,?,?,?,?,?,?)",
        (
            ip,
            jail,
            int(reported_at if reported_at is not None else time.time()),
            int(status or 0),
            categories,
            comment,
            (response or "")[:500],
        ),
    )


def mark_reported(conn: sqlite3.Connection, ip: str) -> None:
    conn.execute(
        "UPDATE events SET reported=? WHERE ip=? AND reported=?", (REPORTED, ip, PENDING)
    )


def mark_invalid(conn: sqlite3.Connection, ip: str, note: str) -> None:
    conn.execute(
        "UPDATE events SET reported=?, note=? WHERE ip=? AND reported=?",
        (INVALID, (note or "")[:300], ip, PENDING),
    )


def bump_attempts(conn: sqlite3.Connection, ip: str, max_attempts: int) -> None:
    conn.execute(
        "UPDATE events SET attempts=attempts+1 WHERE ip=? AND reported=?", (ip, PENDING)
    )
    conn.execute(
        "UPDATE events SET reported=? WHERE ip=? AND reported=? AND attempts>=?",
        (GAVE_UP, ip, PENDING, max_attempts),
    )


def pending_count(conn: sqlite3.Connection) -> int:
    return int(
        conn.execute("SELECT COUNT(*) FROM events WHERE reported=?", (PENDING,)).fetchone()[0]
    )


def pending_events_for_push(
    conn: sqlite3.Connection, limit: int
) -> List[sqlite3.Row]:
    """Events that still have to be delivered to a leader (follower role)."""
    return conn.execute(
        "SELECT id, ip, jail, event_time, bantime, failures FROM events"
        " WHERE reported=? AND pushed=0 ORDER BY event_time ASC, id ASC LIMIT ?",
        (PENDING, int(limit)),
    ).fetchall()


def mark_pushed(conn: sqlite3.Connection, ids: Sequence[int]) -> int:
    """Mark events as delivered to the leader; returns the number of rows."""
    ids = [int(value) for value in ids]
    if not ids:
        return 0
    placeholders = ",".join("?" * len(ids))
    cursor = conn.execute(
        "UPDATE events SET pushed=1 WHERE reported=? AND pushed=0 AND id IN (%s)"
        % placeholders,
        [PENDING] + ids,
    )
    conn.commit()
    return int(cursor.rowcount or 0)


def unpushed_count(conn: sqlite3.Connection) -> int:
    """Events not yet delivered to a leader and not yet reported locally."""
    return int(
        conn.execute(
            "SELECT COUNT(*) FROM events WHERE reported=? AND pushed=0", (PENDING,)
        ).fetchone()[0]
    )


def cleanup(conn: sqlite3.Connection, retention_days: int, now: Optional[int] = None) -> None:
    """Drop finished events, old report records and stale peer cache entries."""
    now = int(now if now is not None else time.time())
    cutoff = now - int(retention_days) * 86400
    conn.execute("DELETE FROM events WHERE reported!=? AND created_at<?", (PENDING, cutoff))
    # events already handed to a leader are finished work for this node
    conn.execute(
        "DELETE FROM events WHERE reported=? AND pushed=1 AND created_at<?", (PENDING, cutoff)
    )
    conn.execute("DELETE FROM reports WHERE reported_at<?", (cutoff,))
    conn.execute("DELETE FROM reported_cache WHERE reported_at<?", (cutoff,))
    conn.commit()


# ---------------------------------------------------------------------------
# coordination helpers (1.4.0)
# ---------------------------------------------------------------------------
def get_meta(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return str(row[0]) if row and row[0] is not None else default


def set_meta(conn: sqlite3.Connection, key: str, value) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(key), str(value)),
    )
    conn.commit()


def recent_reports(
    conn: sqlite3.Connection, since: int, limit: int = 500
) -> dict:
    """IPs this node reported successfully since *since*: ``{ip: last_ts}``."""
    rows = conn.execute(
        "SELECT ip, MAX(reported_at) AS ts FROM reports"
        " WHERE status=200 AND reported_at>=? GROUP BY ip ORDER BY ts DESC LIMIT ?",
        (int(since), int(limit)),
    ).fetchall()
    return {str(row["ip"]): int(row["ts"]) for row in rows}


def merge_reported(
    conn: sqlite3.Connection,
    mapping: dict,
    source: str = "leader",
    now: Optional[int] = None,
) -> int:
    """Store peer-reported timestamps locally; returns the number of entries kept.

    A timestamp far in the future is a broken clock or a hostile peer, so it is
    clamped to *now*: a wrong future value would otherwise block reports for that
    address for a very long time.
    """
    now = int(now if now is not None else time.time())
    kept = 0
    for ip, ts in (mapping or {}).items():
        try:
            stamp = int(ts)
        except (TypeError, ValueError):
            continue
        text = str(ip or "").strip()
        if not text or stamp <= 0:
            continue
        stamp = min(stamp, now)
        conn.execute(
            "INSERT INTO reported_cache(ip, reported_at, source) VALUES (?,?,?)"
            " ON CONFLICT(ip) DO UPDATE SET"
            " reported_at=MAX(reported_cache.reported_at, excluded.reported_at),"
            " source=excluded.source",
            (text, stamp, str(source or "")[:32]),
        )
        kept += 1
    conn.commit()
    return kept


def is_recently_reported(
    conn: sqlite3.Connection, ip: str, window: int = 900, now: Optional[int] = None
) -> bool:
    """True when *ip* was reported (here or by a peer) inside the window."""
    row = conn.execute(
        "SELECT reported_at FROM reported_cache WHERE ip=?", (str(ip),)
    ).fetchone()
    if not row:
        return False
    moment = int(now if now is not None else time.time())
    return (moment - int(row[0])) < int(window)


def bans_since(
    conn: sqlite3.Connection, since: int, exclude_origin: str = "", limit: int = 50
) -> List[dict]:
    """Bans created after *since* that a peer does not have yet.

    ``exclude_origin`` is the asking node: an event that node sent must not be
    sent back to it.  One entry per (ip, jail), newest first.
    """
    query = (
        "SELECT ip, jail, MAX(event_time) AS event_time, MAX(bantime) AS bantime"
        " FROM events WHERE created_at>?"
    )
    args = [int(since)]
    if exclude_origin:
        query += " AND origin<>?"
        args.append(str(exclude_origin))
    query += " GROUP BY ip, jail ORDER BY event_time DESC LIMIT ?"
    args.append(int(limit))
    rows = conn.execute(query, args).fetchall()
    return [
        {
            "ip": str(row["ip"]),
            "jail": str(row["jail"]),
            "event_time": int(row["event_time"] or 0),
            "bantime": int(row["bantime"] or 0),
        }
        for row in rows
    ]