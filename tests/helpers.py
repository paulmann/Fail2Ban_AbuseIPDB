"""Shared helpers for the unit tests (temporary databases, configs, fail2ban DB)."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest

from abuseipdb_reporter import db
from abuseipdb_reporter.config import Config, parse_ranges


def make_config(directory: str, **overrides) -> Config:
    """Build an isolated Config pointing at temporary paths."""
    cfg = Config(
        path=os.path.join(directory, "reporter.conf"),
        api_key="test-api-key",
        api_url="http://127.0.0.1:9/api/v2/report",
        check_url="http://127.0.0.1:9/api/v2/check",
        timeout=2,
        db_path=os.path.join(directory, "queue.sqlite3"),
        fail2ban_db=os.path.join(directory, "fail2ban.sqlite3"),
        log_path=os.path.join(directory, "reporter.log"),
        server_ip="203.0.113.10",
        quiet=True,
        ignore_ranges=parse_ranges("127.0.0.0/8, 192.0.2.0/24"),
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


def seed_fail2ban_db(path: str, records) -> None:
    """Create a minimal fail2ban ``bips`` table.

    ``records`` is a sequence of (ip, jail, matches, failures) tuples.
    """
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS bips ("
        "ip TEXT NOT NULL, jail TEXT NOT NULL, timeofban INTEGER NOT NULL,"
        "bantime INTEGER NOT NULL, bancount INTEGER NOT NULL DEFAULT 1, data JSON)"
    )
    for ip, jail, matches, failures in records:
        payload = json.dumps({"matches": matches, "failures": failures})
        conn.execute(
            "INSERT INTO bips(ip, jail, timeofban, bantime, bancount, data)"
            " VALUES (?,?,?,?,?,?)",
            (ip, jail, 1700000000, 86400, 1, payload),
        )
    conn.commit()
    conn.close()


class TempDirTestCase(unittest.TestCase):
    """Base class: a temporary directory available as ``self.tmp``."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="f2b-abuseipdb-")
        self.tmp = self._tmpdir.name
        self.cfg = make_config(self.tmp)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def connection(self):
        return db.connect(self.cfg.db_path)

    def enqueue(self, ip="198.51.100.7", jail="sshd", event_time=None, bantime=86400, failures=4):
        conn = db.connect(self.cfg.db_path)
        try:
            db.enqueue(
                conn,
                ip,
                jail,
                event_time=event_time,
                bantime=bantime,
                failures=failures,
            )
        finally:
            conn.close()