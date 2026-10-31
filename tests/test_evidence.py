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

    def test_classify_vsftpd(self):
        lines = [
            "vsftpd[1]: pam_unix(vsftpd:auth): authentication failure; rhost=198.51.100.7",
            "vsftpd[1]: FAIL LOGIN: Client \"198.51.100.7\"",
        ]
        patterns, _, _ = evidence.classify("vsftpd", lines)
        self.assertIn("PAM authentication failures", patterns)
        self.assertIn("FTP login failed", patterns)

    def test_classify_postfix_sasl(self):
        lines = [
            "postfix/smtpd[1]: warning: unknown[198.51.100.7]: SASL LOGIN authentication failed: authentication failure",
        ]
        patterns, _, _ = evidence.classify("postfix-sasl", lines)
        self.assertIn("SMTP AUTH failure (SASL)", patterns)

    def test_classify_dovecot(self):
        lines = [
            "dovecot[1]: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<x>, method=PLAIN, rip=198.51.100.7",
            "dovecot[1]: pop3-login: Aborted login (auth failed, 1 attempts): user=<y>, rip=198.51.100.7",
        ]
        patterns, _, _ = evidence.classify("dovecot", lines)
        self.assertIn("IMAP/POP3 authentication failures", patterns)
        self.assertIn("IMAP/POP3 authentication aborted", patterns)

    def test_unknown_web_jail_still_yields_requests(self):
        lines = [
            '198.51.100.7 - - [02/Jan/2026:03:04:05 +0000] "GET /wp-login.php HTTP/1.1" 403 1',
            '198.51.100.7 - - [02/Jan/2026:03:04:06 +0000] "GET /?id=1%20UNION%20SELECT%201 HTTP/1.1" 500 1',
        ]
        patterns, indicators, sqli = evidence.classify("my-custom-web-jail", lines)
        self.assertTrue(sqli)
        self.assertIn("SQL injection attempts", patterns)
        self.assertEqual(indicators[0], "GET /wp-login.php -> 403")

    def test_unknown_jail_without_requests_is_silent(self):
        patterns, indicators, sqli = evidence.classify(
            "some-service", ["some-service[1]: something happened"]
        )
        self.assertEqual((patterns, indicators, sqli), ([], [], False))

    def test_apache_jail_is_treated_as_web(self):
        self.assertTrue(evidence.is_web_jail("apache-badbots"))
        self.assertTrue(evidence.is_web_jail("nginx-attack-scan"))
        self.assertFalse(evidence.is_web_jail("sshd"))
        self.assertFalse(evidence.is_web_jail(""))

    def test_registry_is_ordered_and_extensible(self):
        self.assertIs(evidence.classifier_for("sshd"), evidence._classify_sshd)
        self.assertIs(evidence.classifier_for("dovecot"), evidence._classify_imap)
        self.assertIs(evidence.classifier_for("unknown"), evidence._classify_generic)
        prefixes = [prefix for group, _ in evidence.CLASSIFIERS for prefix in group]
        self.assertIn("nginx", prefixes)
        self.assertIn("postfix", prefixes)


if __name__ == "__main__":
    unittest.main()