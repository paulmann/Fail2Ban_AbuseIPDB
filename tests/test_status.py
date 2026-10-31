"""Status document, Prometheus textfile and the ``--status`` command."""
import json
import os
import unittest

import tests  # noqa: F401
from abuseipdb_reporter import __version__, cli, reporter, status
from tests.helpers import TempDirTestCase


class _Result:
    """Stand-in for reporter.RunResult in the pure tests."""

    def __init__(self, **values):
        self.sent = values.get("sent", 0)
        self.skipped = values.get("skipped", 0)
        self.errors = values.get("errors", 0)
        self.pending = values.get("pending", 0)
        self.today = values.get("today", 0)
        self.retry_after = values.get("retry_after", 0)
        self.waited = values.get("waited", 0.0)
        self.stopped_reason = values.get("stopped_reason", "")


class StatusDocumentTests(TempDirTestCase):
    def test_build_contains_run_counters(self):
        result = _Result(sent=3, skipped=1, errors=0, pending=5, today=7, waited=2.5)
        payload = status.build(self.cfg, result, now=1767227400, version="9.9.9")
        self.assertEqual(payload["ts"], 1767227400)
        self.assertEqual(payload["iso"], status._iso(1767227400))
        self.assertEqual(payload["sent"], 3)
        self.assertEqual(payload["skipped"], 1)
        self.assertEqual(payload["pending"], 5)
        self.assertEqual(payload["today"], 7)
        self.assertEqual(payload["max_per_day"], self.cfg.max_reports_per_day)
        self.assertEqual(payload["waited_seconds"], 2.5)
        self.assertEqual(payload["version"], "9.9.9")
        self.assertEqual(payload["budget_timezone"], "utc")
        self.assertEqual(payload["stopped"], "")

    def test_prometheus_exposition(self):
        payload = status.build(
            self.cfg, _Result(sent=2, pending=4, today=10, errors=1, stopped_reason="x"),
            now=1767227400, version="9.9.9",
        )
        text = status.prometheus(payload)
        self.assertIn("# TYPE abuseipdb_reporter_pending_events gauge", text)
        self.assertIn("abuseipdb_reporter_pending_events 4", text)
        self.assertIn("abuseipdb_reporter_reports_today 10", text)
        self.assertIn("abuseipdb_reporter_sent_last_run 2", text)
        self.assertIn("abuseipdb_reporter_run_ok 0", text)
        self.assertIn("abuseipdb_reporter_budget_remaining %d" % (self.cfg.max_reports_per_day - 10), text)
        self.assertIn(
            'abuseipdb_reporter_info{version="9.9.9",stopped="x",budget_timezone="utc"} 1', text
        )
        self.assertTrue(text.endswith("\n"))

    def test_write_json_is_atomic_and_readable(self):
        path = os.path.join(self.tmp, "nested", "status.json")
        payload = {"b": 2, "a": 1}
        self.assertTrue(status.write_json(path, payload))
        self.assertEqual(status.read(path), payload)
        with open(path, "r", encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), payload)
        leftovers = [name for name in os.listdir(os.path.dirname(path)) if name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_write_reports_failure_instead_of_raising(self):
        blocker = os.path.join(self.tmp, "blocker")
        with open(blocker, "w", encoding="utf-8") as handle:
            handle.write("not a directory")
        self.assertFalse(status.write_text(os.path.join(blocker, "status.json"), "x"))
        self.assertFalse(status.write_text("", "x"))
        self.assertIsNone(status.read(os.path.join(blocker, "status.json")))
        self.assertIsNone(status.read(""))

    def test_record_writes_only_configured_files(self):
        cfg = self.cfg
        cfg.status_path = ""
        cfg.prometheus_textfile = ""
        payload = status.record(cfg, _Result(sent=1), now=1767227400, version=__version__)
        self.assertEqual(payload["sent"], 1)
        self.assertEqual([name for name in os.listdir(self.tmp) if name != "reporter.conf"], [])


class StatusCliTests(TempDirTestCase):
    def _config(self, status_path):
        path = os.path.join(self.tmp, "cli.conf")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "[database]\npath = %s\nfail2ban_db = %s\n[logging]\npath = %s\nstatus_path = %s\n"
                % (self.cfg.db_path, self.cfg.fail2ban_db, self.cfg.log_path, status_path)
            )
        return path

    def test_status_command_prints_json(self):
        status_path = os.path.join(self.tmp, "status.json")
        config_path = self._config(status_path)
        self.enqueue(event_time=1767227000)
        result = reporter.run_once(self.cfg, now=1767227400, dry_run=True)
        self.assertEqual(result.sent, 1)
        status.write_json(status_path, status.build(self.cfg, result, now=1767227400, version=__version__))

        import contextlib
        import io

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main_report(["--status", "--config", config_path])
        self.assertEqual(code, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["sent"], 1)
        self.assertEqual(payload["version"], __version__)

    def test_status_command_without_file_returns_1(self):
        config_path = self._config(os.path.join(self.tmp, "absent.json"))

        import contextlib
        import io

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main_report(["--status", "--config", config_path])
        self.assertEqual(code, 1)
        self.assertIn("no status file", output.getvalue())


if __name__ == "__main__":
    unittest.main()
