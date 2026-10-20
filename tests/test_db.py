"""Queue database tests."""
import time
import unittest

import tests  # noqa: F401
from abuseipdb_reporter import db
from tests.helpers import TempDirTestCase


class DatabaseTests(TempDirTestCase):
    def test_enqueue_creates_pending_event(self):
        conn = self.connection()
        inserted = db.enqueue(conn, "198.51.100.7", "sshd", event_time=1000, bantime=86400, failures=4)
        self.assertTrue(inserted)
        self.assertEqual(db.pending_count(conn), 1)
        events = db.events_for(conn, "198.51.100.7")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["jail"], "sshd")
        self.assertEqual(events[0]["failures"], 4)
        self.assertEqual(events[0]["bantime"], 86400)
        conn.close()

    def test_duplicate_ban_updates_pending_row(self):
        conn = self.connection()
        self.assertTrue(db.enqueue(conn, "198.51.100.7", "sshd", event_time=1000))
        inserted = db.enqueue(conn, "198.51.100.7", "sshd", event_time=1010, failures=9)
        self.assertFalse(inserted)
        self.assertEqual(db.pending_count(conn), 1)
        events = db.events_for(conn, "198.51.100.7")
        self.assertEqual(events[0]["failures"], 9)
        conn.close()

    def test_different_jails_are_separate_events(self):
        conn = self.connection()
        db.enqueue(conn, "198.51.100.7", "sshd", event_time=1000)
        db.enqueue(conn, "198.51.100.7", "nginx-attack-scan", event_time=1001)
        self.assertEqual(db.pending_count(conn), 2)
        rows = db.pending_ips(conn, max_attempts=10, limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["n"], 2)
        conn.close()

    def test_report_flow_and_counters(self):
        conn = self.connection()
        db.enqueue(conn, "198.51.100.7", "sshd", event_time=1000)
        db.record_attempt(conn, "198.51.100.7", "sshd", 200, "18,22", "comment", "{}", reported_at=2000)
        db.mark_reported(conn, "198.51.100.7")
        conn.commit()
        self.assertEqual(db.pending_count(conn), 0)
        self.assertEqual(db.last_success(conn, "198.51.100.7"), 2000)
        self.assertEqual(db.reported_since(conn, 1999), 1)
        self.assertEqual(db.reported_since(conn, 2001), 0)
        conn.close()

    def test_invalid_and_gave_up_states(self):
        conn = self.connection()
        db.enqueue(conn, "198.51.100.1", "sshd", event_time=1000)
        db.enqueue(conn, "198.51.100.2", "sshd", event_time=1000)
        db.mark_invalid(conn, "198.51.100.1", "bad ip")
        db.bump_attempts(conn, "198.51.100.2", max_attempts=1)
        conn.commit()
        states = dict(
            (row["ip"], row["reported"])
            for row in conn.execute("SELECT ip, reported FROM events")
        )
        self.assertEqual(states["198.51.100.1"], db.INVALID)
        self.assertEqual(states["198.51.100.2"], db.GAVE_UP)
        self.assertEqual(db.pending_count(conn), 0)
        conn.close()

    def test_cleanup_keeps_pending_and_recent_rows(self):
        conn = self.connection()
        now = int(time.time())
        db.enqueue(conn, "198.51.100.1", "sshd", event_time=now)
        db.enqueue(conn, "198.51.100.2", "sshd", event_time=now - 40 * 86400)
        db.mark_reported(conn, "198.51.100.2")
        db.record_attempt(conn, "198.51.100.2", "sshd", 200, "18", "c", "{}", reported_at=now)
        conn.commit()
        db.cleanup(conn, retention_days=30, now=now)
        self.assertEqual(db.pending_count(conn), 1)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0], 1)
        conn.close()


if __name__ == "__main__":
    unittest.main()