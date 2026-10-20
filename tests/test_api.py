"""HTTP client tests against a local server (no external network)."""
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

    def log_message(self, *args):
        pass

    def _respond(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
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
        status, body = api.request(url, "secret-key", {"ip": "8.8.8.8", "categories": "18"})
        self.assertEqual(status, 200)
        call = _Handler.requests[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["headers"].get("Key"), "secret-key")
        fields = urllib.parse.parse_qs(call["body"])
        self.assertEqual(fields["ip"], ["8.8.8.8"])
        self.assertEqual(fields["categories"], ["18"])
        self.assertIn("abuseConfidenceScore", body)

    def test_get_check_request(self):
        url = "http://127.0.0.1:%d/api/v2/check?ipAddress=8.8.8.8" % self.port
        status, _ = api.request(url, "secret-key", None)
        self.assertEqual(status, 200)
        self.assertEqual(_Handler.requests[0]["method"], "GET")

    def test_http_error_is_returned_not_raised(self):
        url = "http://127.0.0.1:%d/fail" % self.port
        status, body = api.request(url, "secret-key", {"ip": "8.8.8.8"})
        self.assertEqual(status, 429)
        self.assertIn("rate limited", body)

    def test_transport_error_returns_none(self):
        status, body = api.request("http://127.0.0.1:1/api", "k", {"ip": "8.8.8.8"}, timeout=1)
        self.assertIsNone(status)
        self.assertTrue(body)


if __name__ == "__main__":
    unittest.main()