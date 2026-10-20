"""Evidence extraction from fail2ban's database and log line classification."""
import unittest

import tests  # noqa: F401
from abuseipdb_reporter import evidence
from tests.helpers import TempDirTestCase, seed_fail2ban_db


class EvidenceTests(TempDirTestCase):
    def test_clean_line_strips_timestamp_and_hostname(self):
        raw = (
            "2026-01-02T03:04:05.123456+00:00 web01 sshd-session[123]: "
            "Failed password for root from 198.51.100.7 port 22 ssh2"
        )
        self.assertEqual(
            evidence.clean_line(raw),
            "sshd-session[123]: Failed password for root from 198.51.100.7 port 22 ssh2",
        )

    def test_read_matches_supports_strings_and_tuples(self):
        ip, jail = "198.51.100.7", "sshd"
        seed_fail2ban_db(
            self.cfg.fail2ban_db,
            [
                (
                    ip,
                    jail,
                    [
                        ["", "2026-01-02T03:04:05 ", "web01 sshd[1]: Invalid user test from 198.51.100.7"],
                        "2026-01-02T03:04:06 web01 sshd[1]: Failed password for root from 198.51.100.7",
                    ],
                    4,
                )
            ],
        )
        lines = evidence.read_matches(self.cfg.fail2ban_db, ip, jail)
        self.assertEqual(len(lines), 2)
        self.assertIn("Invalid user test", lines[0])
        self.assertNotIn("2026-01-02T03:04:05", lines[0])
        self.assertTrue(lines[1].startswith("sshd[1]:"))

    def test_read_matches_missing_database(self):
        lines = evidence.read_matches("/nonexistent/fail2ban.sqlite3", "198.51.100.7", "sshd")
        self.assertEqual(lines, [])

    def test_classify_web_requests_and_sqli(self):
        lines = [
            '198.51.100.7 - - [02/Jan/2026:03:04:05 +0000] "GET /.env HTTP/1.1" 404 1 "-" "ua"',
            '198.51.100.7 - - [02/Jan/2026:03:04:06 +0000] "POST /login?x=1%20UNION%20SELECT%20@@version HTTP/1.1" 403 1 "-" "ua"',
        ]
        patterns, indicators, sqli = evidence.classify("nginx-attack-scan", lines)
        self.assertEqual(patterns, [])
        self.assertTrue(sqli)
        self.assertEqual(indicators[0], "GET /.env -> 404")
        self.assertIn("POST /login", indicators[1])
        self.assertNotIn("HTTP/1.1", indicators[0])

    def test_classify_ssh_patterns(self):
        lines = [
            "sshd[1]: Failed password for root from 198.51.100.7 port 22 ssh2",
            "sshd[1]: Invalid user attacker-name from 198.51.100.7 port 22",
            "sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=198.51.100.7",
        ]
        patterns, indicators, sqli = evidence.classify("sshd", lines)
        self.assertIn("root password attempts", patterns)
        self.assertIn("invalid usernames tried", patterns)
        self.assertIn("PAM authentication failures", patterns)
        self.assertEqual(indicators, [])
        self.assertFalse(sqli)

    def test_classify_exim_codes(self):
        lines = [
            "exim[1]: authenticator failed for [198.51.100.7]: 535 Incorrect authentication data",
            "exim[1]: authenticator failed for [198.51.100.7]: 435 Unable to authenticate at present",
        ]
        patterns, _, _ = evidence.classify("exim-auth-fail", lines)
        self.assertIn("SMTP AUTH with incorrect credentials (535)", patterns)
        self.assertIn("SMTP AUTH rejected by auth backend (435)", patterns)

    def test_classify_proftpd(self):
        lines = ["proftpd[1]: USER test: no such user found from 198.51.100.7"]
        patterns, _, _ = evidence.classify("proftpd", lines)
        self.assertIn("FTP login with non-existent user", patterns)


if __name__ == "__main__":
    unittest.main()