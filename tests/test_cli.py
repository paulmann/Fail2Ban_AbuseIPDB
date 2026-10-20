"""CLI tests for the two entry points."""
import contextlib
import io
import json
import os
import unittest
from unittest import mock

import tests  # noqa: F401
from abuseipdb_reporter import cli, db
from tests.helpers import TempDirTestCase


def write_config(tmp: str, cfg, key_file=None, legacy_key="test", extra=""):
    path = os.path.join(tmp, "cli.conf")
    key_block = ""
    if key_file:
        key_block = "api_key_file = %s\n" % key_file
    if legacy_key:
        key_block += "api_key = %s\n" % legacy_key
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "[abuseipdb]\n%s"
            "[ignore]\nranges = 127.0.0.0/8, 192.0.2.0/24\n"
            "[database]\npath = %s\nfail2ban_db = %s\n"
            "[report]\nserver_ip = 203.0.113.10\n"
            "[logging]\npath = %s\n%s"
            % (key_block, cfg.db_path, cfg.fail2ban_db, cfg.log_path, extra)
        )
    return path


class CliTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.config_path = write_config(self.tmp, self.cfg)

    def test_enqueue_command(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main_enqueue(
                [
                    "--ip",
                    "8.8.8.8",
                    "--jail",
                    "sshd",
                    "--bantime",
                    "86400",
                    "--failures",
                    "4",
                    "--config",
                    self.config_path,
                ]
            )
        self.assertEqual(code, 0)
        conn = db.connect(self.cfg.db_path)
        try:
            self.assertEqual(db.pending_count(conn), 1)
        finally:
            conn.close()
        self.assertIn("enqueue:", output.getvalue())

    def test_stats_command(self):
        cli.main_enqueue(["--ip", "8.8.8.8", "--jail", "sshd", "--config", self.config_path])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main_report(["--stats", "--config", self.config_path])
        self.assertEqual(code, 0)
        text = output.getvalue()
        self.assertIn("pending events", text)
        self.assertIn("reports today", text)

    def test_dry_run_prints_json_payload(self):
        cli.main_enqueue(["--ip", "8.8.8.8", "--jail", "sshd", "--config", self.config_path])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main_report(["--dry-run", "--config", self.config_path])
        self.assertEqual(code, 0)
        lines = [line for line in output.getvalue().splitlines() if line.strip()]
        payloads = [json.loads(line) for line in lines if line.startswith("{")]
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["ip"], "8.8.8.8")
        self.assertIn("comment", payloads[0])

    def test_acquire_lock_is_exclusive(self):
        try:
            import fcntl  # noqa: F401
        except ImportError:
            self.skipTest("fcntl is not available on this platform")
        lock_path = os.path.join(self.tmp, "reporter.lock")
        first = cli.acquire_lock([lock_path])
        self.assertIsNotNone(first)
        self.assertFalse(cli.acquire_lock([lock_path]))
        first.close()
        second = cli.acquire_lock([lock_path])
        self.assertIsNotNone(second)
        second.close()

    def test_setup_prompts_and_saves_key(self):
        key_file = os.path.join(self.tmp, "keys", ".abuseipdb.key")
        config_path = write_config(self.tmp, self.cfg, key_file=key_file, legacy_key=None)
        output = io.StringIO()
        with mock.patch("abuseipdb_reporter.keys.getpass.getpass", return_value="a" * 80), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = cli.main_report(["--setup", "--config", config_path])
        self.assertEqual(code, 0)
        with open(key_file, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read().strip(), "a" * 80)

    def test_key_status_reports_source(self):
        key_file = os.path.join(self.tmp, "keys", ".abuseipdb.key")
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        with open(key_file, "w", encoding="utf-8") as handle:
            handle.write("b" * 80 + "\n")
        config_path = write_config(self.tmp, self.cfg, key_file=key_file, legacy_key=None)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(cli.main_report(["--key-status", "--config", config_path]), 0)
        self.assertIn("key file", output.getvalue())
        self.assertIn("bbbbbb...bbbb", output.getvalue())

    def test_migrate_key_moves_secret(self):
        key_file = os.path.join(self.tmp, "keys", ".abuseipdb.key")
        config_path = write_config(self.tmp, self.cfg, key_file=key_file, legacy_key="c" * 80)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(cli.main_report(["--migrate-key", "--config", config_path]), 0)
        with open(key_file, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read().strip(), "c" * 80)
        with open(config_path, "r", encoding="utf-8") as handle:
            self.assertNotIn("c" * 80, handle.read())

    def test_missing_key_noninteractive_returns_2(self):
        key_file = os.path.join(self.tmp, "keys", ".abuseipdb.key")
        config_path = write_config(self.tmp, self.cfg, key_file=key_file, legacy_key=None)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main_report(["--no-prompt", "--config", config_path])
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(key_file))

    def test_invalid_ip_does_not_raise(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main_enqueue(
                ["--ip", "not-an-ip", "--jail", "sshd", "--config", self.config_path]
            )
        self.assertEqual(code, 0)
        conn = db.connect(self.cfg.db_path)
        try:
            self.assertEqual(db.pending_count(conn), 0)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()