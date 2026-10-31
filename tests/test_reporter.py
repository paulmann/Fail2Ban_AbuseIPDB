"""Reporter worker tests (no network: the HTTP call is injected)."""
import datetime
import json
import os
import time
import unittest
from unittest import mock

import tests  # noqa: F401
from abuseipdb_reporter import __version__, db, reporter, status
from tests.helpers import TempDirTestCase, seed_fail2ban_db


class FakeHttp:
    """Injectable HTTP function that records calls and replays responses."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, api_key, fields, timeout):
        self.calls.append({"url": url, "key": api_key, "fields": dict(fields)})
        if not self.responses:
            return 200, '{"data": {"abuseConfidenceScore": 50}}'
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class ReporterTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.now = int(time.time())
        self.cfg.min_interval_ip = 1200

    def _rows(self, sql, args=()):
        conn = self.connection()
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    def test_successful_report_marks_events(self):
        self.enqueue(event_time=self.now - 60)
        http = FakeHttp((200, '{"data": {"abuseConfidenceScore": 50}}'))
        result = reporter.run_once(self.cfg, now=self.now, http=http)
        self.assertEqual(result.sent, 1)
        self.assertEqual(result.errors, 0)
        self.assertEqual(result.pending, 0)
        self.assertEqual(len(http.calls), 1)
        fields = http.calls[0]["fields"]
        self.assertEqual(fields["ip"], "198.51.100.7")
        self.assertEqual(fields["categories"], "18,22")
        self.assertIn("SSH brute-force", fields["comment"])
        self.assertLessEqual(len(fields["comment"].encode("utf-8")), self.cfg.comment_max_bytes)
        rows = self._rows("SELECT status FROM reports")
        self.assertEqual([row["status"] for row in rows], [200])

    def test_same_ip_is_throttled(self):
        self.enqueue(event_time=self.now - 60)
        http = FakeHttp()
        reporter.run_once(self.cfg, now=self.now, http=http)
        self.enqueue(event_time=self.now + 10)
        result = reporter.run_once(self.cfg, now=self.now + 10, http=http)
        self.assertEqual(result.sent, 0)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(len(http.calls), 1)
        self.assertEqual(result.pending, 1)

    def test_retry_after_per_ip_rate_limit(self):
        self.enqueue(event_time=self.now - 60)
        body_429 = '{"errors": [{"detail": "You can only report the same IP address once in 15 minutes."}]}'
        http = FakeHttp((429, body_429), (200, "{}"))
        first = reporter.run_once(self.cfg, now=self.now, http=http)
        self.assertEqual(first.sent, 0)
        self.assertEqual(first.pending, 1)
        second = reporter.run_once(self.cfg, now=self.now + 1300, http=http)
        self.assertEqual(second.sent, 1)
        self.assertEqual(second.pending, 0)

    def test_global_rate_limit_stops_the_run(self):
        self.enqueue(event_time=self.now - 60)
        http = FakeHttp((429, '{"errors": [{"detail": "Too many requests"}]}'))
        result = reporter.run_once(self.cfg, now=self.now, http=http)
        self.assertEqual(result.sent, 0)
        self.assertEqual(result.stopped_reason, "global rate limit")
        self.assertEqual(result.pending, 1)

    def test_invalid_report_marks_events(self):
        self.enqueue(event_time=self.now - 60)
        http = FakeHttp((422, '{"errors": [{"detail": "bad ip"}]}'))
        result = reporter.run_once(self.cfg, now=self.now, http=http)
        self.assertEqual(result.errors, 1)
        rows = self._rows("SELECT reported FROM events")
        self.assertEqual(rows[0]["reported"], db.INVALID)

    def test_transient_error_then_success(self):
        self.enqueue(event_time=self.now - 60)
        http = FakeHttp((500, "server error"), (200, "{}"))
        first = reporter.run_once(self.cfg, now=self.now, http=http)
        self.assertEqual(first.errors, 1)
        self.assertEqual(first.pending, 1)
        attempts = self._rows("SELECT attempts FROM events")[0]["attempts"]
        self.assertEqual(attempts, 1)
        second = reporter.run_once(self.cfg, now=self.now + 5, http=http)
        self.assertEqual(second.sent, 1)

    def test_unauthorized_stops_the_run(self):
        self.enqueue(event_time=self.now - 60)
        http = FakeHttp((401, "unauthorized"))
        result = reporter.run_once(self.cfg, now=self.now, http=http)
        self.assertEqual(result.stopped_reason, "unauthorized")
        self.assertEqual(result.pending, 1)

    def test_dry_run_builds_payload_without_calls(self):
        self.enqueue(event_time=self.now - 60)
        http = FakeHttp()
        result = reporter.run_once(self.cfg, now=self.now, http=http, dry_run=True)
        self.assertEqual(result.sent, 1)
        self.assertEqual(len(result.payloads), 1)
        self.assertEqual(http.calls, [])
        self.assertEqual(result.pending, 1)
        self.assertIn("timestamp", result.payloads[0])

    def test_disabled_and_missing_key(self):
        self.cfg.enabled = False
        self.assertEqual(reporter.run_once(self.cfg, now=self.now).stopped_reason, "disabled")
        self.cfg.enabled = True
        self.cfg.api_key = ""
        self.assertEqual(
            reporter.run_once(self.cfg, now=self.now).stopped_reason, "missing api key"
        )

    def test_daily_budget(self):
        self.cfg.max_reports_per_day = 1
        self.enqueue(event_time=self.now - 60)
        http = FakeHttp()
        reporter.run_once(self.cfg, now=self.now, http=http)
        self.enqueue(ip="198.51.100.8", event_time=self.now)
        result = reporter.run_once(self.cfg, now=self.now + 5, http=http)
        self.assertEqual(result.sent, 0)
        self.assertEqual(result.stopped_reason, "daily budget exhausted")

    def test_multi_jail_comment_uses_evidence(self):
        ip = "198.51.100.7"
        seed_fail2ban_db(
            self.cfg.fail2ban_db,
            [
                (
                    ip,
                    "nginx-attack-scan",
                    ['x - - [02/Jan/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 404 0'],
                    5,
                )
            ],
        )
        self.enqueue(ip=ip, jail="nginx-attack-scan", event_time=self.now - 60, failures=5)
        self.enqueue(ip=ip, jail="sshd", event_time=self.now - 50, failures=4)
        http = FakeHttp()
        result = reporter.run_once(self.cfg, now=self.now, http=http, dry_run=True)
        payload = result.payloads[0]
        self.assertIn("GET /.env -> 404", payload["comment"])
        self.assertIn("18", payload["categories"])
        self.assertIn("21", payload["categories"])

    def test_retry_after_pause_is_honoured(self):
        self.enqueue(event_time=self.now - 60)
        body_429 = '{"errors": [{"detail": "You can only report the same IP address once in 15 minutes."}]}'
        http = FakeHttp((429, body_429, 7), (200, "{}"))
        with mock.patch("time.sleep") as sleep:
            result = reporter.run_once(self.cfg, now=self.now, http=http)
        self.assertEqual(result.retry_after, 7)
        self.assertEqual(result.waited, 7.0)
        sleep.assert_called_once_with(7.0)

    def test_transient_errors_back_off_exponentially(self):
        self.cfg.request_delay = 1.0
        self.cfg.retry_after_cap = 60
        for last_octet in (7, 8, 9):
            self.enqueue(ip="198.51.100.%d" % last_octet, event_time=self.now - 60)
        http = FakeHttp((500, "boom"), (500, "boom"), (200, "{}"))
        with mock.patch("time.sleep") as sleep:
            result = reporter.run_once(self.cfg, now=self.now, http=http)
        self.assertEqual(result.sent, 1)
        self.assertEqual(result.errors, 2)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2.0, 4.0, 1.0])
        self.assertEqual(result.waited, 7.0)

    def test_status_file_and_prometheus_are_written(self):
        self.cfg.status_path = os.path.join(self.tmp, "status.json")
        self.cfg.prometheus_textfile = os.path.join(self.tmp, "abuseipdb.prom")
        self.enqueue(event_time=self.now - 60)
        http = FakeHttp((200, "{}"))
        reporter.run_once(self.cfg, now=self.now, http=http)
        payload = status.read(self.cfg.status_path)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["sent"], 1)
        self.assertEqual(payload["pending"], 0)
        self.assertEqual(payload["version"], __version__)
        self.assertEqual(payload["budget_timezone"], "utc")
        with open(self.cfg.prometheus_textfile, "r", encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("abuseipdb_reporter_pending_events 0", text)
        self.assertIn('version="%s"' % __version__, text)

    def test_status_is_written_when_the_budget_is_exhausted(self):
        self.cfg.status_path = os.path.join(self.tmp, "status.json")
        self.cfg.max_reports_per_day = 1
        self.enqueue(event_time=self.now - 60)
        http = FakeHttp((200, "{}"))
        reporter.run_once(self.cfg, now=self.now, http=http)
        self.enqueue(ip="198.51.100.8", event_time=self.now)
        result = reporter.run_once(self.cfg, now=self.now + 5, http=http)
        self.assertEqual(result.stopped_reason, "daily budget exhausted")
        payload = status.read(self.cfg.status_path)
        self.assertEqual(payload["stopped"], "daily budget exhausted")
        self.assertEqual(payload["pending"], 1)

    def test_dry_run_does_not_overwrite_status(self):
        self.cfg.status_path = os.path.join(self.tmp, "status.json")
        self.enqueue(event_time=self.now - 60)
        http = FakeHttp()
        reporter.run_once(self.cfg, now=self.now, http=http)
        first = status.read(self.cfg.status_path)
        reporter.run_once(self.cfg, now=self.now + 60, http=http, dry_run=True)
        self.assertEqual(status.read(self.cfg.status_path), first)

    def test_two_tuple_http_client_is_still_supported(self):
        self.enqueue(event_time=self.now - 60)
        http = FakeHttp((200, "{}"))  # a 1.1-era client returns (status, body)
        result = reporter.run_once(self.cfg, now=self.now, http=http)
        self.assertEqual(result.sent, 1)
        self.assertEqual(result.retry_after, 0)


class ScheduleTests(unittest.TestCase):
    """Budget day alignment and adaptive delay (pure functions)."""

    def test_day_start_utc(self):
        moment = 1767227400  # 2026-01-01T00:30:00Z
        start = reporter.day_start(moment, "utc")
        self.assertEqual(
            datetime.datetime.fromtimestamp(start, tz=datetime.timezone.utc).isoformat(),
            "2026-01-01T00:00:00+00:00",
        )
        self.assertLessEqual(start, moment)
        self.assertGreater(moment - start, 1700)

    def test_day_start_local_uses_local_midnight(self):
        moment = int(time.time())
        start = reporter.day_start(moment, "local")
        local = datetime.datetime.fromtimestamp(start)
        self.assertEqual((local.hour, local.minute, local.second), (0, 0, 0))
        self.assertEqual(start, reporter._midnight(moment))

    def test_next_delay(self):
        cfg = _DictConfig(request_delay=1.5, retry_after_cap=60)
        self.assertEqual(reporter.next_delay(cfg), 1.5)
        self.assertEqual(reporter.next_delay(cfg, streak=1), 3.0)
        self.assertEqual(reporter.next_delay(cfg, streak=3), 12.0)
        self.assertEqual(reporter.next_delay(cfg, streak=9), 60.0)  # capped
        self.assertEqual(reporter.next_delay(cfg, streak=1, retry_after=5), 5.0)
        self.assertEqual(reporter.next_delay(cfg, streak=1, retry_after=600), 60.0)
        self.assertEqual(
            reporter.next_delay(_DictConfig(request_delay=0.0, retry_after_cap=60)), 0.0
        )


class _DictConfig:
    """Minimal stand-in for Config in the pure-function tests."""

    def __init__(self, **values):
        self.request_delay = values.get("request_delay", 1.0)
        self.retry_after_cap = values.get("retry_after_cap", 60)


if __name__ == "__main__":
    unittest.main()