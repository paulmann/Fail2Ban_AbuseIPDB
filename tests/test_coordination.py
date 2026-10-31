"""Leader/follower coordination: queue migration, client, endpoint, follower path."""
import json
import os
import socket
import sqlite3
import threading
import unittest
import urllib.error
import urllib.request

import tests  # noqa: F401
from abuseipdb_reporter import coord_server, coordination, db, reporter
from tests.helpers import TempDirTestCase

SECRET = "coord-secret-" + "x" * 32


class FakeHttp:
    """Injectable AbuseIPDB client that must never be used by a follower."""

    def __init__(self):
        self.calls = []

    def __call__(self, url, api_key, fields, timeout):
        self.calls.append({"url": url, "fields": dict(fields)})
        return 200, "{}", None


def write_secret(cfg, value=SECRET):
    with open(cfg.shared_secret_file, "w", encoding="utf-8") as handle:
        handle.write(value + "\n")
    return value


class ConfigurationTests(TempDirTestCase):
    def test_a_fresh_config_is_standalone(self):
        self.assertEqual(coordination.mode_of(self.cfg), "none")
        self.assertFalse(coordination.is_follower(self.cfg))
        self.assertFalse(coordination.is_leader(self.cfg))
        self.assertEqual(self.cfg.push_batch_size, 50)
        self.assertEqual(self.cfg.coord_port, 8765)
        self.assertEqual(self.cfg.coord_bind, "127.0.0.1")

    def test_load_secret(self):
        self.cfg.shared_secret_file = os.path.join(self.tmp, "coord.secret")
        self.assertEqual(coordination.load_secret(os.path.join(self.tmp, "absent")), "")
        self.assertEqual(coordination.load_secret(""), "")
        write_secret(self.cfg, "  value-with-spaces  \n")
        self.assertEqual(coordination.load_secret(self.cfg.shared_secret_file), "value-with-spaces")

    def test_events_to_payload(self):
        conn = db.connect(self.cfg.db_path)
        try:
            db.enqueue(conn, "198.51.100.7", "sshd", event_time=1700000000, bantime=7200, failures=5)
            rows = db.pending_events_for_push(conn, 10)
        finally:
            conn.close()
        payload = coordination.events_to_payload(rows)
        self.assertEqual(
            payload,
            [
                {
                    "ip": "198.51.100.7",
                    "jail": "sshd",
                    "event_time": 1700000000,
                    "bantime": 7200,
                    "failures": 5,
                }
            ],
        )


class QueueMigrationTests(TempDirTestCase):
    def test_old_queue_without_pushed_column_is_migrated(self):
        path = self.cfg.db_path
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL,"
            " jail TEXT NOT NULL, event_time INTEGER NOT NULL, bantime INTEGER NOT NULL DEFAULT 0,"
            " failures INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,"
            " reported INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, note TEXT)"
        )
        conn.execute(
            "INSERT INTO events(ip,jail,event_time,created_at) VALUES (?,?,?,?)",
            ("198.51.100.7", "sshd", 1700000000, 1700000000),
        )
        conn.commit()
        conn.close()

        conn = db.connect(path)
        try:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
            pending = db.pending_events_for_push(conn, 10)
            self.assertIn("pushed", columns)
            self.assertEqual(len(pending), 1)
            self.assertEqual(db.unpushed_count(conn), 1)
        finally:
            conn.close()

    def test_mark_pushed_and_unpushed_count(self):
        conn = db.connect(self.cfg.db_path)
        try:
            db.enqueue(conn, "198.51.100.7", "sshd")
            db.enqueue(conn, "198.51.100.8", "sshd")
            ids = [row["id"] for row in db.pending_events_for_push(conn, 10)]
            self.assertEqual(len(ids), 2)
            self.assertEqual(db.mark_pushed(conn, ids[:1]), 1)
            self.assertEqual(db.unpushed_count(conn), 1)
            self.assertEqual(db.mark_pushed(conn, ids[:1]), 0)  # already pushed
            self.assertEqual(len(db.pending_events_for_push(conn, 10)), 1)
        finally:
            conn.close()

    def test_pushed_events_are_not_reported_by_the_leader_path(self):
        conn = db.connect(self.cfg.db_path)
        try:
            db.enqueue(conn, "198.51.100.7", "sshd")
            ids = [row["id"] for row in db.pending_events_for_push(conn, 10)]
            db.mark_pushed(conn, ids)
            self.assertEqual(db.events_for(conn, "198.51.100.7"), [])
            self.assertEqual(db.pending_ips(conn, 10, 10), [])
        finally:
            conn.close()

    def test_cleanup_removes_pushed_events_only_after_retention(self):
        conn = db.connect(self.cfg.db_path)
        try:
            db.enqueue(conn, "198.51.100.7", "sshd", event_time=1700000000)
            ids = [row["id"] for row in db.pending_events_for_push(conn, 10)]
            db.mark_pushed(conn, ids)
            db.cleanup(conn, retention_days=30, now=1700000000 + 3600)
            self.assertEqual(len(db.pending_events_for_push(conn, 10)), 0)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM events WHERE pushed=1").fetchone()[0], 1
            )
            db.cleanup(conn, retention_days=30, now=1700000000 + 40 * 86400)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
        finally:
            conn.close()


class EndpointTests(TempDirTestCase):
    """The leader endpoint, reached over real HTTP on the loopback interface."""

    def setUp(self):
        super().setUp()
        self.cfg.coordination_mode = "leader"
        self.cfg.node_id = "leader-1"
        self.cfg.coord_bind = "127.0.0.1"
        self.cfg.coord_port = 0  # ephemeral port
        self.cfg.shared_secret_file = os.path.join(self.tmp, "coord.secret")
        write_secret(self.cfg)
        self.server = coord_server.make_server(self.cfg)
        self.port = self.server.server_address[1]
        self.url = "http://127.0.0.1:%d" % self.port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def _post(self, path, payload, secret=SECRET, raw=None):
        data = raw if raw is not None else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if secret is not None:
            headers["X-Coord-Secret"] = secret
        request = urllib.request.Request(self.url + path, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8") or "{}")

    def _get(self, path, secret=SECRET):
        headers = {"X-Coord-Secret": secret} if secret else {}
        request = urllib.request.Request(self.url + path, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8") or "{}")

    def _pending(self):
        conn = db.connect(self.cfg.db_path)
        try:
            return db.pending_count(conn)
        finally:
            conn.close()

    def test_make_server_requires_a_secret(self):
        cfg = self.cfg
        cfg.shared_secret_file = os.path.join(self.tmp, "absent.secret")
        with self.assertRaises(ValueError):
            coord_server.make_server(cfg)

    def test_push_is_accepted_and_queued(self):
        events = [
            {"ip": "198.51.100.7", "jail": "sshd", "event_time": 1700000000, "bantime": 3600, "failures": 4},
            {"ip": "198.51.100.8", "jail": "nginx-attack-scan", "event_time": 1700000001},
        ]
        status, body = self._post("/v1/push", {"node_id": "web-1", "events": events})
        self.assertEqual(status, 200)
        self.assertEqual(
            {key: body[key] for key in ("accepted", "inserted", "rejected")},
            {"accepted": 2, "inserted": 2, "rejected": 0},
        )
        self.assertEqual(self._pending(), 2)
        conn = db.connect(self.cfg.db_path)
        try:
            row = conn.execute(
                "SELECT jail, bantime, failures FROM events WHERE ip='198.51.100.7'"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual((row["jail"], row["bantime"], row["failures"]), ("sshd", 3600, 4))

    def test_repeated_push_is_deduplicated(self):
        events = [
            {"ip": "198.51.100.7", "jail": "sshd", "event_time": 1700000000, "bantime": 60, "failures": 1}
        ]
        first = self._post("/v1/push", {"node_id": "web-1", "events": events})
        second = self._post("/v1/push", {"node_id": "web-1", "events": events})
        self.assertEqual(first[1]["inserted"], 1)
        self.assertEqual(second[1]["inserted"], 0)
        self.assertEqual(self._pending(), 1)

    def test_leader_applies_its_own_filters(self):
        events = [
            {"ip": "not-an-ip", "jail": "sshd"},
            {"ip": "127.0.0.1", "jail": "sshd"},  # inside the configured ignore range
            {"ip": "198.51.100.9", "jail": "recidive"},  # skipped jail
            {"ip": "198.51.100.10", "jail": ""},
            {"ip": "198.51.100.11", "jail": "sshd"},
        ]
        status, body = self._post("/v1/push", {"node_id": "web-1", "events": events})
        self.assertEqual(status, 200)
        self.assertEqual(body["accepted"], 5)
        self.assertEqual(body["rejected"], 4)
        self.assertEqual(body["inserted"], 1)
        self.assertEqual(self._pending(), 1)

    def test_wrong_secret_is_forbidden(self):
        status, body = self._post("/v1/push", {"events": []}, secret="wrong")
        self.assertEqual(status, 403)
        self.assertEqual(body, {"error": "forbidden"})
        self.assertEqual(self._pending(), 0)

    def test_missing_secret_is_forbidden(self):
        status, _body = self._post("/v1/push", {"events": []}, secret=None)
        self.assertEqual(status, 403)

    def test_bad_json_is_rejected(self):
        status, body = self._post("/v1/push", None, raw=b"{not json")
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "bad json"})

    def test_events_must_be_a_list(self):
        status, body = self._post("/v1/push", {"events": {"ip": "198.51.100.7"}})
        self.assertEqual(status, 400)
        self.assertIn("list", body["error"])

    def test_oversized_body_is_rejected(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(
                (
                    "POST /v1/push HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    "X-Coord-Secret: %s\r\nContent-Type: application/json\r\n"
                    "Content-Length: %d\r\nConnection: close\r\n\r\n"
                    % (SECRET, coord_server.MAX_BODY_BYTES + 1)
                ).encode("ascii")
            )
            head = sock.recv(128).decode("latin-1")
        self.assertIn("413", head.split("\r\n")[0])

    def test_status_route(self):
        status, body = self._get("/v1/status")
        self.assertEqual(status, 200)
        self.assertEqual(body["role"], "leader")
        self.assertEqual(body["node_id"], "leader-1")
        self.assertIn("pending", body)
        self.assertEqual(self._get("/v1/status", secret="wrong")[0], 403)

    def test_unknown_routes(self):
        self.assertEqual(self._get("/nope")[0], 404)
        self.assertEqual(self._post("/nope", {})[0], 404)


class FollowerTests(TempDirTestCase):
    """The follower role: push, never report, never need an API key."""

    def setUp(self):
        super().setUp()
        self.leader_cfg = self.cfg
        self.leader_cfg.coordination_mode = "leader"
        self.leader_cfg.coord_bind = "127.0.0.1"
        self.leader_cfg.coord_port = 0
        self.leader_cfg.shared_secret_file = os.path.join(self.tmp, "coord.secret")
        write_secret(self.leader_cfg)
        self.server = coord_server.make_server(self.leader_cfg)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        # a separate queue for the follower, in its own directory
        self.follower_dir = os.path.join(self.tmp, "follower")
        os.makedirs(self.follower_dir, exist_ok=True)
        self.follower = self._follower_config()

    def _follower_config(self):
        from tests.helpers import make_config

        cfg = make_config(self.follower_dir)
        cfg.coordination_mode = "follower"
        cfg.node_id = "web-1"
        cfg.leader_url = self.url
        cfg.shared_secret_file = self.leader_cfg.shared_secret_file
        return cfg

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def _enqueue(self, ip="198.51.100.7", jail="sshd"):
        conn = db.connect(self.follower.db_path)
        try:
            db.enqueue(conn, ip, jail, event_time=1700000000, bantime=3600, failures=4)
        finally:
            conn.close()

    def _follower_rows(self):
        conn = db.connect(self.follower.db_path)
        try:
            return conn.execute("SELECT pushed, reported FROM events").fetchall()
        finally:
            conn.close()

    def test_follower_pushes_and_marks_without_calling_the_api(self):
        self._enqueue()
        self._enqueue(ip="198.51.100.8")
        http = FakeHttp()
        result = reporter.run_once(self.follower, now=1700000100, http=http)
        self.assertEqual(http.calls, [])  # the API is the leader's business only
        self.assertEqual(result.sent, 2)
        self.assertEqual(result.pending, 0)
        self.assertTrue(result.stopped_reason.startswith("follower"))
        self.assertEqual([row["pushed"] for row in self._follower_rows()], [1, 1])
        self.assertEqual(self.leader_cfg.db_path, self.cfg.db_path)
        leader_conn = db.connect(self.cfg.db_path)
        try:
            self.assertEqual(db.pending_count(leader_conn), 2)
        finally:
            leader_conn.close()

    def test_follower_does_not_need_an_api_key(self):
        self._enqueue()
        self.follower.api_key = ""
        result = reporter.run_once(self.follower, now=1700000100, http=FakeHttp())
        self.assertEqual(result.sent, 1)

    def test_missing_secret_keeps_events_pending(self):
        self._enqueue()
        self.follower.shared_secret_file = os.path.join(self.tmp, "absent.secret")
        result = reporter.run_once(self.follower, now=1700000100, http=FakeHttp())
        self.assertEqual(result.sent, 0)
        self.assertIn("missing shared secret", result.stopped_reason)
        self.assertEqual(result.pending, 1)
        self.assertEqual([row["pushed"] for row in self._follower_rows()], [0])

    def test_unreachable_leader_keeps_events_pending(self):
        self._enqueue()
        self.follower.leader_url = "http://127.0.0.1:1"
        self.follower.timeout = 1
        result = reporter.run_once(self.follower, now=1700000100, http=FakeHttp())
        self.assertEqual(result.sent, 0)
        self.assertEqual(result.pending, 1)
        self.assertTrue(result.stopped_reason.startswith("follower ("), result.stopped_reason)

    def test_wrong_secret_keeps_events_pending(self):
        self._enqueue()
        write_secret(self.follower, "not-the-same-secret")
        result = reporter.run_once(self.follower, now=1700000100, http=FakeHttp())
        self.assertEqual(result.sent, 0)
        self.assertIn("403", result.stopped_reason)

    def test_dry_run_previews_without_pushing(self):
        self._enqueue()
        result = reporter.run_once(self.follower, now=1700000100, http=FakeHttp(), dry_run=True)
        self.assertEqual(result.stopped_reason, "follower dry-run")
        self.assertEqual(len(result.payloads), 1)
        self.assertEqual(result.payloads[0]["ip"], "198.51.100.7")
        self.assertEqual([row["pushed"] for row in self._follower_rows()], [0])

    def test_batch_size_limits_one_push(self):
        self._enqueue(ip="198.51.100.7")
        self._enqueue(ip="198.51.100.8")
        self.follower.push_batch_size = 1
        result = reporter.run_once(self.follower, now=1700000100, http=FakeHttp())
        self.assertEqual(result.sent, 1)
        self.assertEqual(result.pending, 1)
        second = reporter.run_once(self.follower, now=1700000200, http=FakeHttp())
        self.assertEqual(second.sent, 1)
        self.assertEqual(second.pending, 0)

    def test_non_http_leader_url_is_refused(self):
        self._enqueue()
        self.follower.leader_url = "file:///etc/passwd"
        result = reporter.run_once(self.follower, now=1700000100, http=FakeHttp())
        self.assertEqual(result.sent, 0)
        self.assertIn("http", result.stopped_reason)

    def test_cli_does_not_require_a_key_on_a_follower(self):
        from abuseipdb_reporter import cli

        self._enqueue()
        config_path = os.path.join(self.follower_dir, "follower.conf")
        with open(config_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(
                "[database]\npath = %s\nfail2ban_db = %s\n"
                "[logging]\npath = %s\n"
                "[coordination]\nmode = follower\nnode_id = web-1\n"
                "leader_url = %s\nshared_secret_file = %s\n"
                % (
                    self.follower.db_path.replace("\\", "/"),
                    self.follower.fail2ban_db.replace("\\", "/"),
                    self.follower.log_path.replace("\\", "/"),
                    self.url,
                    self.follower.shared_secret_file,
                )
            )
        self.assertEqual(cli.main_report(["--config", config_path]), 0)
        conn = db.connect(self.follower.db_path)
        try:
            self.assertEqual(db.unpushed_count(conn), 0)
        finally:
            conn.close()

    def test_leader_mode_still_reports_locally(self):
        self.cfg.coordination_mode = "leader"
        self.enqueue()  # into the leader's own queue (helpers.TempDirTestCase)
        http = FakeHttp()
        result = reporter.run_once(self.cfg, now=1700000100, http=http)
        self.assertEqual(result.sent, 1)
        self.assertEqual(len(http.calls), 1)


if __name__ == "__main__":
    unittest.main()
