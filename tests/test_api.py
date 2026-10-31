"""HTTP client tests against a local server (no external network)."""
import datetime
import email.utils
import http.server
import json
import threading
import unittest
import urllib.parse

import tests  # noqa: F401
from abuseipdb_reporter import api


class _Handler(http.server.BaseHTTPRequestHandler):
    requests = []
    fail_path = "/fail"
    slow_path = "/slow"

    def log_message(self, *args):
        pass

    def _respond(self, code, payload, headers=None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        type(self).requests.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
        self._respond(200, {"data": {"ok": True}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode()
        type(self).requests.append(
            {"method": "POST", "path": self.path, "headers": dict(self.headers), "body": body}
        )
        if self.path.startswith(self.slow_path):
            self._respond(
                429,
                {"errors": [{"detail": "rate limited"}]},
                {"Retry-After": "30"},
            )
            return
        if self.path.startswith(self.fail_path):
            self._respond(429, {"errors": [{"detail": "rate limited"}]})
            return
        self._respond(200, {"data": {"abuseConfidenceScore": 50}})


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _Handler.requests = []

    def test_post_sends_form_fields_and_api_key(self):
        url = "http://127.0.0.1:%d/api/v2/report" % self.port
        status, body, retry_after = api.request(url, "secret-key", {"ip": "8.8.8.8", "categories": "18"})
        self.assertEqual(status, 200)
        self.assertIsNone(retry_after)
        call = _Handler.requests[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["headers"].get("Key"), "secret-key")
        fields = urllib.parse.parse_qs(call["body"])
        self.assertEqual(fields["ip"], ["8.8.8.8"])
        self.assertEqual(fields["categories"], ["18"])
        self.assertIn("abuseConfidenceScore", body)

    def test_get_check_request(self):
        url = "http://127.0.0.1:%d/api/v2/check?ipAddress=8.8.8.8" % self.port
        status, _body, _retry_after = api.request(url, "secret-key", None)
        self.assertEqual(status, 200)
        self.assertEqual(_Handler.requests[0]["method"], "GET")

    def test_http_error_is_returned_not_raised(self):
        url = "http://127.0.0.1:%d/fail" % self.port
        status, body, retry_after = api.request(url, "secret-key", {"ip": "8.8.8.8"})
        self.assertEqual(status, 429)
        self.assertIn("rate limited", body)
        self.assertIsNone(retry_after)

    def test_retry_after_header_is_parsed_from_429(self):
        url = "http://127.0.0.1:%d/slow" % self.port
        status, body, retry_after = api.request(url, "secret-key", {"ip": "8.8.8.8"})
        self.assertEqual(status, 429)
        self.assertIn("rate limited", body)
        self.assertEqual(retry_after, 30)

    def test_transport_error_returns_none(self):
        status, body, retry_after = api.request(
            "http://127.0.0.1:1/api", "k", {"ip": "8.8.8.8"}, timeout=1
        )
        self.assertIsNone(status)
        self.assertTrue(body)
        self.assertIsNone(retry_after)

    def test_parse_retry_after_seconds(self):
        self.assertEqual(api.parse_retry_after("120"), 120)
        self.assertEqual(api.parse_retry_after(" 45 "), 45)
        self.assertEqual(api.parse_retry_after("0"), 0)

    def test_parse_retry_after_http_date(self):
        now = 1767225600  # 2026-01-01T00:00:00Z
        when = datetime.datetime.fromtimestamp(now + 90, tz=datetime.timezone.utc)
        header = email.utils.format_datetime(when, usegmt=True)
        self.assertEqual(api.parse_retry_after(header, now=now), 90)
        past = datetime.datetime.fromtimestamp(now - 90, tz=datetime.timezone.utc)
        self.assertEqual(api.parse_retry_after(email.utils.format_datetime(past, usegmt=True), now=now), 0)

    def test_parse_retry_after_garbage(self):
        for value in (None, "", "   ", "soon", "12.5", "-3"):
            self.assertIsNone(api.parse_retry_after(value), value)


if __name__ == "__main__":
    unittest.main()
