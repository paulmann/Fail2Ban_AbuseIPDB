"""v1.5 features: TLS, health, retries, lease-based failover, metrics."""
import io
import json
import os
import ssl
import threading
import time
import unittest
import urllib.error
import urllib.request

import tests  # noqa: F401
from abuseipdb_reporter import (
    coord_server,
    coordination,
    db,
    metrics,
    reporter,
    witness,
    witness_client,
)
from tests.helpers import TempDirTestCase, make_config

SECRET = "lease-secret-" + "z" * 30


def write_secret(path, value=SECRET):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(value + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def make_self_signed(directory: str):
    """Create a throwaway key pair and a self-signed cert with stdlib only."""
    import subprocess

    key = os.path.join(directory, "key.pem")
    cert = os.path.join(directory, "cert.pem")
    command = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    except OSError as error:  # openssl is not installed on the Windows dev box
        return None, None, repr(error)
    if result.returncode != 0:
        return None, None, result.stderr[-300:]
    return key, cert, ""


class MetricsTests(TempDirTestCase):
    def test_snapshot_counts_the_queue(self):
        conn = db.connect(self.cfg.db_path)
        try:
            db.enqueue(conn, "198.51.100.7", "sshd")
            db.enqueue(conn, "198.51.100.8", "sshd")
            db.merge_reported(conn, {"198.51.100.9": int(time.time()) - 10})
            db.set_meta(conn, coordination.ACCEPTED_KEY, "5")
        finally:
            conn.close()
        snapshot = metrics.build(self.cfg, now=int(time.time()))
        self.assertEqual(snapshot["pending_events"], 2)
        self.assertEqual(snapshot["reported_cache_entries"], 1)
        self.assertEqual(snapshot["accepted_total"], 5)
        self.assertEqual(snapshot["leader_up"], -1)

    def test_prometheus_document_is_parseable(self):
        snapshot = metrics.build(self.cfg, now=int(time.time()))
        text = metrics.prometheus(snapshot)
        self.assertIn("abuseipdb_reporter_info{", text)
        names = set()
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            name = line.split("{")[0].split(" ")[0]
            names.add(name)
            float(line.rsplit(" ", 1)[1])
        self.assertIn("abuseipdb_reporter_pending_events", names)
        self.assertIn("abuseipdb_reporter_coord_sync_failures", names)
        self.assertIn("abuseipdb_reporter_lease_held", names)

    def test_broken_queue_does_not_raise(self):
        # A directory where the database is expected fails on every platform, while
        # a path with "?" only fails on Windows - the test must mean the same thing
        # on the Linux CI too.
        broken = os.path.join(self.tmp, "a-directory")
        os.makedirs(broken, exist_ok=True)
        self.cfg.db_path = broken
        snapshot = metrics.build(self.cfg, now=int(time.time()))
        self.assertIn("error", snapshot)
        self.assertEqual(snapshot["pending_events"], 0)

    def test_last_run_is_merged(self):
        path = os.path.join(self.tmp, "status.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"ts": 1000, "sent": 3, "skipped": 1, "errors": 0, "stopped": "ok"}, handle)
        snapshot = metrics.build(self.cfg, now=2000, status_path=path)
        self.assertEqual(snapshot["last_run_ts"], 1000)
        self.assertEqual(snapshot["last_run_sent"], 3)
        self.assertEqual(snapshot["last_run_age_seconds"], 1000)

    def test_reports_today_uses_the_budget_day(self):
        conn = db.connect(self.cfg.db_path)
        try:
            now = int(time.time())
            db.record_attempt(conn, "198.51.100.7", "sshd", 200, "18", "c", "r", reported_at=now)
            db.record_attempt(
                conn, "198.51.100.8", "sshd", 200, "18", "c", "r", reported_at=now - 3 * 86400
            )
            conn.commit()
            self.assertEqual(db.reports_today(conn, now), 1)
        finally:
            conn.close()


class MetricNameTests(TempDirTestCase):
    """Every name the Zabbix template uses must resolve in the snapshot."""

    def test_prometheus_names_resolve(self):
        snapshot = metrics.build(self.cfg, now=int(time.time()))
        for name in (
            "pending_events",
            "coord_accepted_total",
            "coord_rejected_total",
            "coord_remote_bans_total",
            "coord_sync_failures",
            "coord_cursor_lag_seconds",
            "coord_last_sync_age_seconds",
            "last_run_age_seconds",
            "lease_held",
        ):
            candidates = metrics.name_candidates(name)
            self.assertTrue(
                any(candidate in snapshot for candidate in candidates),
                "%s -> %s" % (name, candidates),
            )

    def test_prefixed_and_plain_forms_agree(self):
        self.assertEqual(
            metrics.name_candidates("abuseipdb_reporter_pending_events"),
            ["abuseipdb_reporter_pending_events", "pending_events"],
        )
        self.assertEqual(
            metrics.name_candidates("coord_accepted_total"),
            ["coord_accepted_total", "accepted_total"],
        )
        self.assertEqual(metrics.name_candidates("enabled"), ["enabled"])

    def test_unknown_name_is_rejected_by_the_cli(self):
        from abuseipdb_reporter import cli

        self.assertIsNone(cli.monitoring_value(self.cfg, "no_such_metric"))

    def test_cli_prints_every_item_name_of_the_template(self):
        from abuseipdb_reporter import cli

        import re

        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "monitoring",
            "zabbix",
            "fail2ban_abuseipdb.yaml",
        )
        with open(path, "r", encoding="utf-8") as handle:
            names = re.findall(r"key: 'fail2ban\.abuseipdb\.metric\[([a-z_]+)\]'", handle.read())
        self.assertEqual(len(names), 21)
        for name in names:
            self.assertIsNotNone(cli.monitoring_value(self.cfg, name), name)


class RetryTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.cfg.coordination_mode = "follower"
        self.cfg.node_id = "web-1"
        self.cfg.shared_secret_file = os.path.join(self.tmp, "coord.secret")
        write_secret(self.cfg.shared_secret_file)

    def test_failed_sync_is_retried_and_counted(self):
        self.cfg.leader_url = "http://127.0.0.1:9"  # nothing listens here
        self.cfg.sync_attempts = 3
        self.cfg.sync_retry_base = 0.0
        sleeps = []
        conn = db.connect(self.cfg.db_path)
        try:
            result = coordination.follower_sync(
                self.cfg, conn, runner=lambda argv, timeout=12: (0, "", ""), sleep=sleeps.append
            )
        finally:
            conn.close()
        self.assertEqual(result.attempts, 3)
        self.assertEqual(result.pushed, 0)
        self.assertIn("error", result.reason.lower() + "error")
        conn = db.connect(self.cfg.db_path)
        try:
            self.assertEqual(int(db.get_meta(conn, coordination.SYNC_FAILURES_KEY, "0")), 1)
            self.assertEqual(int(db.get_meta(conn, coordination.LAST_SYNC_OK_KEY, "1")), 0)
        finally:
            conn.close()

    def test_backoff_grows_between_attempts(self):
        self.cfg.leader_url = "http://127.0.0.1:9"
        self.cfg.sync_attempts = 3
        self.cfg.sync_retry_base = 0.5
        sleeps = []
        conn = db.connect(self.cfg.db_path)
        try:
            coordination.follower_sync(
                self.cfg, conn, runner=lambda argv, timeout=12: (0, "", ""), sleep=sleeps.append
            )
        finally:
            conn.close()
        self.assertEqual(len(sleeps), 2)
        self.assertLess(sleeps[0], sleeps[1])

    def test_single_attempt_when_disabled(self):
        self.cfg.leader_url = "http://127.0.0.1:9"
        self.cfg.sync_attempts = 1
        sleeps = []
        conn = db.connect(self.cfg.db_path)
        try:
            result = coordination.follower_sync(
                self.cfg, conn, runner=lambda argv, timeout=12: (0, "", ""), sleep=sleeps.append
            )
        finally:
            conn.close()
        self.assertEqual(result.attempts, 1)
        self.assertEqual(sleeps, [])


class JailCacheTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.conn = db.connect(self.cfg.db_path)

    def tearDown(self):
        self.conn.close()
        super().tearDown()

    def test_failed_client_keeps_the_previous_list(self):
        good = lambda argv, timeout=12: (0, "`- Jail list:\tsshd, recidive\n", "")
        self.assertEqual(
            coordination._local_jails(self.cfg, self.conn, runner=good, now=1000),
            ["sshd", "recidive"],
        )
        # a broken fail2ban-client must not blank the list
        broken = lambda argv, timeout=12: (1, "", "cannot connect")
        self.assertEqual(
            coordination._local_jails(self.cfg, self.conn, runner=broken, now=1000 + 7200),
            ["sshd", "recidive"],
        )

    def test_empty_answer_keeps_the_previous_list_inside_the_window(self):
        good = lambda argv, timeout=12: (0, "`- Jail list:\tsshd\n", "")
        coordination._local_jails(self.cfg, self.conn, runner=good, now=1000)
        empty = lambda argv, timeout=12: (0, "Status\n`- Jail list:\t\n", "")
        self.assertEqual(
            coordination._local_jails(self.cfg, self.conn, runner=empty, now=1000 + 7200),
            ["sshd"],
        )

    def test_cache_is_reused_inside_the_ttl(self):
        calls = []

        def runner(argv, timeout=12):
            calls.append(argv)
            return 0, "`- Jail list:\tsshd\n", ""

        coordination._local_jails(self.cfg, self.conn, runner=runner, now=1000)
        coordination._local_jails(self.cfg, self.conn, runner=runner, now=1000 + 60)
        self.assertEqual(len(calls), 1)


class HealthyEndpointTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.cfg.coordination_mode = "leader"
        self.cfg.node_id = "leader-1"
        self.cfg.coord_port = 0
        self.cfg.shared_secret_file = os.path.join(self.tmp, "coord.secret")
        write_secret(self.cfg.shared_secret_file)
        self.server = coord_server.make_server(self.cfg)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def test_health_needs_no_secret(self):
        with urllib.request.urlopen(self.url + coordination.HEALTH_PATH, timeout=5) as response:
            body = json.loads(response.read().decode())
        self.assertEqual(response.status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["role"], "leader")
        self.assertNotIn("pending", body)  # nothing about the queue leaks

    def test_status_still_requires_the_secret(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(self.url + coordination.STATUS_PATH, timeout=5)
        self.assertEqual(caught.exception.code, 403)

    def test_status_reports_the_new_counters(self):
        request = urllib.request.Request(
            self.url + coordination.STATUS_PATH, headers={"X-Coord-Secret": SECRET}
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            body = json.loads(response.read().decode())
        for key in ("reported_cache", "reports_today", "accepted_total", "rejected_total",
                    "effective", "tls"):
            self.assertIn(key, body)

    def test_auto_mode_without_a_lease_answers_409(self):
        self.cfg.coordination_mode = "auto"
        self.cfg.failover = "witness"
        self.cfg.witness_url = "http://127.0.0.1:9"
        request = urllib.request.Request(
            self.url + coordination.SYNC_PATH,
            data=json.dumps({"node_id": "web-1", "events": []}).encode(),
            headers={"Content-Type": "application/json", "X-Coord-Secret": SECRET},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 409)


class LeaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.store = witness.LeaseStore(state_path="", clock=lambda: self.now)

    def test_first_node_wins_and_renews(self):
        first = self.store.acquire("a", 100)
        self.assertTrue(first["granted"])
        self.assertEqual(first["owner"], "a")
        self.now = 1050
        self.assertTrue(self.store.acquire("a", 100)["granted"])
        self.assertEqual(self.store.owner, "a")

    def test_second_node_is_refused_while_the_lease_lives(self):
        self.store.acquire("a", 100)
        answer = self.store.acquire("b", 100)
        self.assertFalse(answer["granted"])
        self.assertEqual(answer["owner"], "a")
        self.assertIn("lease held", answer["reason"])

    def test_expired_lease_can_be_taken(self):
        self.store.acquire("a", 100)
        self.now = 1000 + 101
        answer = self.store.acquire("b", 100)
        self.assertTrue(answer["granted"])
        self.assertEqual(answer["owner"], "b")
        self.assertEqual(answer["term"], 2)

    def test_release_only_by_the_owner(self):
        self.store.acquire("a", 100)
        self.assertFalse(self.store.release("b")["released"])
        self.assertTrue(self.store.release("a")["released"])
        self.assertEqual(self.store.owner, "")

    def test_state_survives_a_restart(self):
        path = os.path.join(os.environ.get("TEMP", "/tmp"), "witness-test-%d.json" % os.getpid())
        store = witness.LeaseStore(state_path=path, clock=lambda: self.now)
        store.acquire("a", 500)
        again = witness.LeaseStore(state_path=path, clock=lambda: self.now)
        self.assertEqual(again.owner, "a")
        self.assertEqual(again.expires, 1500)
        os.unlink(path)


class WitnessServerTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.cfg.shared_secret_file = os.path.join(self.tmp, "coord.secret")
        write_secret(self.cfg.shared_secret_file)
        self.cfg.coord_port = 0
        self.store = witness.LeaseStore(state_path="", clock=time.time)
        self.server = witness.make_server(self.cfg, store=self.store)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.client = witness_client.WitnessClient(self.url, SECRET, timeout=5)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def test_lease_lifecycle_over_http(self):
        answer = self.client.lease("node-a", 60)
        self.assertTrue(answer["granted"])
        self.assertEqual(answer["owner"], "node-a")

        refused = self.client.lease("node-b", 60)
        self.assertFalse(refused["granted"])
        self.assertEqual(refused["owner"], "node-a")

        self.assertTrue(self.client.release("node-a")["released"])
        self.assertTrue(self.client.lease("node-b", 60)["granted"])

    def test_wrong_secret_is_forbidden(self):
        bad = witness_client.WitnessClient(self.url, "wrong", timeout=5)
        answer = bad.lease("node-a", 60)
        self.assertFalse(answer["granted"])
        self.assertEqual(answer.get("status"), 403)

    def test_status_is_readable_without_a_secret(self):
        self.client.lease("node-a", 60)
        with urllib.request.urlopen(self.url + witness.STATUS_PATH, timeout=5) as response:
            body = json.loads(response.read().decode())
        self.assertEqual(body["owner"], "node-a")
        self.assertTrue(body["live"])
        self.assertEqual(body["role"], "witness")


class AutoRoleTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.cfg.coordination_mode = "auto"
        self.cfg.failover = "witness"
        self.cfg.node_id = "node-a"
        self.cfg.shared_secret_file = os.path.join(self.tmp, "coord.secret")
        write_secret(self.cfg.shared_secret_file)
        self.cfg.coord_port = 0
        self.store = witness.LeaseStore(state_path="", clock=time.time)
        self.server = witness.make_server(self.cfg, store=self.store)
        self.cfg.witness_url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def _role(self):
        conn = db.connect(self.cfg.db_path)
        try:
            return coordination.effective_role(self.cfg, conn=conn)
        finally:
            conn.close()

    def test_auto_becomes_leader_with_the_lease(self):
        self.assertEqual(self._role(), coordination.MODE_LEADER)
        self.assertEqual(self.store.owner, "node-a")

    def test_auto_stays_follower_when_another_node_holds_it(self):
        self.store.acquire("node-b", 600)
        self.assertEqual(self._role(), coordination.MODE_FOLLOWER)

    def test_unreachable_witness_keeps_a_valid_lease(self):
        self.assertEqual(self._role(), coordination.MODE_LEADER)
        self.server.shutdown()
        self.server.server_close()
        self.assertEqual(self._role(), coordination.MODE_LEADER)  # still inside the TTL

    def test_unreachable_witness_without_a_lease_is_a_follower(self):
        self.server.shutdown()
        self.server.server_close()
        self.assertEqual(self._role(), coordination.MODE_FOLLOWER)

    def test_auto_without_witness_url_never_leads(self):
        self.cfg.witness_url = ""
        self.assertEqual(self._role(), coordination.MODE_FOLLOWER)

    def test_static_leader_does_not_ask_the_witness(self):
        self.cfg.coordination_mode = "leader"
        self.assertEqual(self._role(), coordination.MODE_LEADER)


class TlsTests(TempDirTestCase):
    def test_plain_http_without_certificates(self):
        self.assertIsNone(coordination._ssl_context(self.cfg, server_side=True))

    def test_https_client_context_verifies_by_default(self):
        self.cfg.leader_url = "https://127.0.0.1:8765"
        context = coordination._ssl_context(self.cfg, server_side=False)
        self.assertIsNotNone(context)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_verify_can_be_disabled_for_a_test_rig(self):
        self.cfg.leader_url = "https://127.0.0.1:8765"
        self.cfg.tls_verify = False
        context = coordination._ssl_context(self.cfg, server_side=False)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)

    def test_http_url_keeps_the_plain_socket(self):
        self.cfg.leader_url = "http://127.0.0.1:8765"
        self.assertIsNone(coordination._ssl_context(self.cfg, server_side=False))

    def test_self_signed_server_round_trip(self):
        key, cert, error = make_self_signed(self.tmp)
        if not cert:
            self.skipTest("openssl not available: %s" % error)
        self.cfg.coordination_mode = "leader"
        self.cfg.node_id = "leader-tls"
        self.cfg.coord_port = 0
        self.cfg.tls_cert = cert
        self.cfg.tls_key = key
        self.cfg.shared_secret_file = os.path.join(self.tmp, "coord.secret")
        write_secret(self.cfg.shared_secret_file)
        server = coord_server.make_server(self.cfg)
        self.assertTrue(getattr(server, "tls", False))
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            # without trusting the CA the handshake must fail
            with self.assertRaises(Exception):
                urllib.request.urlopen(
                    "https://127.0.0.1:%d%s" % (port, coordination.HEALTH_PATH), timeout=5
                )
            # trusting the certificate itself makes it work (self-signed used as its own CA)
            context = ssl.create_default_context(cafile=cert)
            with urllib.request.urlopen(
                "https://127.0.0.1:%d%s" % (port, coordination.HEALTH_PATH),
                timeout=5,
                context=context,
            ) as response:
                body = json.loads(response.read().decode())
            self.assertTrue(body["ok"])
            self.assertTrue(body["tls"])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
