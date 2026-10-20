"""CLI tests for the two entry points."""
import contextlib
import io
import json
import os
import unittest

import tests  # noqa: F401
from abuseipdb_reporter import cli, db
from tests.helpers import TempDirTestCase


def write_config(tmp: str, cfg) -> str:
    path = os.path.join(tmp, "cli.conf")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "[abuseipdb]\napi_key = test\n"
            "[ignore]\nranges = 127.0.0.0/8, 192.0.2.0/24\n"
            "[database]\npath = %s\nfail2ban_db = %s\n"
            "[report]\nserver_ip = 203.0.113.10\n"
            "[logging]\npath = %s\n" % (cfg.db_path, cfg.fail2ban_db, cfg.log_path)
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