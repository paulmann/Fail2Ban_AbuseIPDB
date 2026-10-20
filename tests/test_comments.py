"""Comment construction tests."""
import datetime
import unittest

import tests  # noqa: F401
from abuseipdb_reporter import comments
from tests.helpers import TempDirTestCase


def event(event_time, bantime=86400, failures=4, jail="sshd"):
    return {"event_time": event_time, "bantime": bantime, "failures": failures, "jail": jail}


class CommentTests(TempDirTestCase):
    def test_human_duration(self):
        self.assertEqual(comments.human_duration(86400), "1d")
        self.assertEqual(comments.human_duration(3600), "1h")
        self.assertEqual(comments.human_duration(604800), "1w")
        self.assertEqual(comments.human_duration(0), "unknown")
        self.assertEqual(comments.human_duration(90), "90s")

    def test_truncate_bytes_respects_utf8_limit(self):
        text = "a" * 50 + "Привет" * 10
        truncated = comments.truncate_bytes(text, 40)
        self.assertLessEqual(len(truncated.encode("utf-8")), 40)
        self.assertTrue(truncated.endswith("..."))

    def test_build_comment_contains_type_time_and_counters(self):
        now = 1700000000
        comment, categories, timestamp = comments.build_comment(
            self.cfg,
            "198.51.100.7",
            [event(now - 60)],
            ["sshd"],
            {"sshd": ["sshd[1]: Failed password for root from 198.51.100.7"]},
            now=now,
        )
        self.assertIn("SSH brute-force", comment)
        self.assertIn("jails: sshd", comment)
        self.assertIn("4 failed attempts", comment)
        self.assertIn("Patterns:", comment)
        self.assertIn("no personal data", comment)
        self.assertEqual(categories, [18, 22])
        self.assertEqual(timestamp, comments.iso(now - 60))

    def test_union_of_categories_and_sqli(self):
        now = 1700000000
        lines = {
            "nginx-attack-scan": [
                'x - - [02/Jan/2026:00:00:00 +0000] "GET /a?id=1%20UNION%20SELECT%20@@version HTTP/1.1" 404 0'
            ],
            "sshd": ["sshd[1]: Failed password for root from 198.51.100.7"],
        }
        comment, categories, _ = comments.build_comment(
            self.cfg,
            "198.51.100.7",
            [event(now - 10, jail="nginx-attack-scan"), event(now - 5, jail="sshd")],
            ["nginx-attack-scan", "sshd"],
            lines,
            now=now,
        )
        self.assertIn(16, categories)  # SQL injection detected
        self.assertIn(18, categories)
        self.assertIn(19, categories)
        self.assertIn(21, categories)
        self.assertIn(22, categories)
        self.assertIn("web application vulnerability", comment)
        self.assertIn("SSH brute-force", comment)

    def test_log_evidence_fallback(self):
        now = 1700000000
        comment, _, _ = comments.build_comment(
            self.cfg,
            "198.51.100.7",
            [event(now)],
            ["proftpd"],
            {"proftpd": ["proftpd[1]: USER test: no such user found from 198.51.100.7"]},
            now=now,
        )
        self.assertIn("FTP brute-force", comment)
        self.assertIn("Patterns:", comment)

    def test_no_attempted_usernames_leak(self):
        now = 1700000000
        lines = {
            "sshd": [
                "sshd[1]: Failed password for invalid user secretusername from 198.51.100.7 port 22",
                "sshd[1]: Invalid user secretusername2 from 198.51.100.7 port 22",
            ]
        }
        comment, _, _ = comments.build_comment(
            self.cfg, "198.51.100.7", [event(now)], ["sshd"], lines, now=now
        )
        self.assertNotIn("secretusername", comment)
        self.assertNotIn("secretusername2", comment)

    def test_comment_size_limit(self):
        self.cfg.comment_max_bytes = 300
        self.cfg.evidence_max_lines = 10
        now = 1700000000
        lines = {
            "nginx-attack-scan": [
                'x - - [02/Jan/2026:00:00:00 +0000] "GET /%s HTTP/1.1" 404 0' % ("a" * 200)
                for _ in range(5)
            ]
        }
        comment, _, _ = comments.build_comment(
            self.cfg,
            "198.51.100.7",
            [event(now, jail="nginx-attack-scan")],
            ["nginx-attack-scan"],
            lines,
            now=now,
        )
        self.assertLessEqual(len(comment.encode("utf-8")), 300)

    def test_old_backlog_timestamp_is_now(self):
        now = 1700000000
        comment, _, timestamp = comments.build_comment(
            self.cfg,
            "198.51.100.7",
            [event(now - 25 * 3600)],
            ["sshd"],
            {},
            now=now,
        )
        parsed = datetime.datetime.fromisoformat(timestamp)
        self.assertLess(abs(parsed.timestamp() - now), 120)
        self.assertIn("Observed:", comment)


if __name__ == "__main__":
    unittest.main()