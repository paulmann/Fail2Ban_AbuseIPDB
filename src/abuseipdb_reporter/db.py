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
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_pending ON events(reported, ip);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip, event_time);
CREATE INDEX IF NOT EXISTS idx_events_push ON events(reported, pushed);

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
    conn.commit()


def enqueue(
    conn: sqlite3.Connection,
    ip: str,
    jail: str,
    event_time: Optional[int] = None,
    bantime: int = 0,
    failures: int = 0,
    dedupe_window: int = 300,
) -> bool:
    """Insert a ban event, collapsing repeated bans of the same IP+jail.

    Returns True when a new row was inserted, False when an existing pending
    row was updated (deduplication window).
    """
    now = int(event_time if event_time is not None else time.time())
    bantime = int(bantime or 0)
    failures = int(failures or 0)
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
        "INSERT INTO events(ip, jail, event_time, bantime, failures, created_at)"
        " VALUES (?,?,?,?,?,?)",
        (ip, jail, now, bantime, failures, now),
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
    """Drop finished events and old report records."""
    now = int(now if now is not None else time.time())
    cutoff = now - int(retention_days) * 86400
    conn.execute("DELETE FROM events WHERE reported!=? AND created_at<?", (PENDING, cutoff))
    # events already handed to a leader are finished work for this node
    conn.execute(
        "DELETE FROM events WHERE reported=? AND pushed=1 AND created_at<?", (PENDING, cutoff)
    )
    conn.execute("DELETE FROM reports WHERE reported_at<?", (cutoff,))
    conn.commit()