"""Ban queueing tests."""
import unittest

import tests  # noqa: F401
from abuseipdb_reporter import db, enqueue
from tests.helpers import TempDirTestCase


class EnqueueTests(TempDirTestCase):
    def test_public_ip_is_queued(self):
        self.assertTrue(enqueue.enqueue_ban(self.cfg, "8.8.8.8", "sshd", bantime=86400, failures=5))
        conn = self.connection()
        try:
            rows = conn.execute("SELECT ip, jail, bantime, failures FROM events").fetchall()
        finally:
            conn.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "8.8.8.8")
        self.assertEqual(rows[0]["jail"], "sshd")

    def test_ignored_and_invalid_addresses_are_skipped(self):
        self.assertFalse(enqueue.enqueue_ban(self.cfg, "127.0.0.1", "sshd"))
        self.assertFalse(enqueue.enqueue_ban(self.cfg, "192.0.2.5", "sshd"))
        self.assertFalse(enqueue.enqueue_ban(self.cfg, "not-an-ip", "sshd"))
        conn = self.connection()
        try:
            self.assertEqual(db.pending_count(conn), 0)
        finally:
            conn.close()

    def test_reserved_address_can_be_allowed_for_tests(self):
        self.assertTrue(
            enqueue.enqueue_ban(self.cfg, "192.0.2.5", "sshd", allow_reserved=True)
        )

    def test_skipped_jails_and_disabled_reporter(self):
        self.assertFalse(enqueue.enqueue_ban(self.cfg, "8.8.8.8", "recidive"))
        self.cfg.enabled = False
        self.assertFalse(enqueue.enqueue_ban(self.cfg, "8.8.8.8", "sshd"))

    def test_duplicate_ban_is_updated(self):
        enqueue.enqueue_ban(self.cfg, "8.8.8.8", "sshd", failures=4)
        enqueue.enqueue_ban(self.cfg, "8.8.8.8", "sshd", failures=9)
        conn = self.connection()
        try:
            rows = conn.execute("SELECT failures, COUNT(*) AS n FROM events").fetchall()
        finally:
            conn.close()
        self.assertEqual(rows[0]["n"], 1)
        self.assertEqual(rows[0]["failures"], 9)


if __name__ == "__main__":
    unittest.main()