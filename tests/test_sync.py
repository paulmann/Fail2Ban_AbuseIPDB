"""Two-way sync: report deduplication and ban propagation (1.4.0)."""
import json
import os
import threading
import time
import unittest

import tests  # noqa: F401
from abuseipdb_reporter import coord_server, coordination, db, reporter
from tests.helpers import TempDirTestCase

SECRET = "sync-secret-" + "y" * 30


class FakeRunner:
    """Records the fail2ban-client calls instead of running them."""

    def __init__(self, code=0, stderr="", jails=("sshd",)):
        self.calls = []
        self.code = code
        self.stderr = stderr
        self.jails = list(jails)

    def __call__(self, argv, timeout=12):
        self.calls.append(list(argv))
        if list(argv)[1:] == ["status"]:
            return 0, "Status\n`- Jail list:\t%s\n" % ", ".join(self.jails), ""
        return self.code, "", self.stderr

    def banned(self):
        return [call[4] for call in self.calls if call[1:2] != ["status"]]

    def ban_calls(self):
        return [call for call in self.calls if call[1:2] != ["status"]]


def write_secret(cfg, value=SECRET):
    with open(cfg.shared_secret_file, "w", encoding="utf-8") as handle:
        handle.write(value + "\n")


class CacheTests(TempDirTestCase):
    def test_merge_and_window(self):
        conn = db.connect(self.cfg.db_path)
        try:
            now = 1767225600
            kept = db.merge_reported(conn, {"198.51.100.7": now - 60, "bad": "x"}, now=now)
            self.assertEqual(kept, 1)
            self.assertTrue(db.is_recently_reported(conn, "198.51.100.7", 900, now=now))
            self.assertFalse(db.is_recently_reported(conn, "198.51.100.7", 30, now=now))
            self.assertFalse(db.is_recently_reported(conn, "198.51.100.8", 900, now=now))
        finally:
            conn.close()

    def test_future_timestamps_are_clamped(self):
        conn = db.connect(self.cfg.db_path)
        try:
            now = 1767225600
            db.merge_reported(conn, {"198.51.100.9": now + 999999}, now=now)
            stamp = conn.execute(
                "SELECT reported_at FROM reported_cache WHERE ip='198.51.100.9'"
            ).fetchone()[0]
            self.assertEqual(int(stamp), now)
        finally:
            conn.close()

    def test_merge_keeps_the_newest_entry(self):
        conn = db.connect(self.cfg.db_path)
        try:
            now = 1767225600
            db.merge_reported(conn, {"198.51.100.7": now - 600}, now=now)
            db.merge_reported(conn, {"198.51.100.7": now - 60}, now=now)
            db.merge_reported(conn, {"198.51.100.7": now - 900}, now=now)
            stamp = conn.execute(
                "SELECT reported_at FROM reported_cache WHERE ip='198.51.100.7'"
            ).fetchone()[0]
            self.assertEqual(int(stamp), now - 60)
        finally:
            conn.close()

    def test_cleanup_prunes_the_cache(self):
        conn = db.connect(self.cfg.db_path)
        try:
            db.merge_reported(conn, {"198.51.100.7": 1000}, now=1000)
            db.cleanup(conn, retention_days=30, now=1000 + 31 * 86400)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM reported_cache").fetchone()[0], 0
            )
        finally:
            conn.close()

    def test_recent_reports_reads_the_journal(self):
        conn = db.connect(self.cfg.db_path)
        try:
            db.record_attempt(conn, "198.51.100.7", "sshd", 200, "18", "c", "r", reported_at=5000)
            db.record_attempt(conn, "198.51.100.8", "sshd", 422, "18", "c", "r", reported_at=5000)
            db.record_attempt(conn, "198.51.100.9", "sshd", 200, "18", "c", "r", reported_at=100)
            conn.commit()
            mapping = db.recent_reports(conn, since=4000)
            self.assertEqual(mapping, {"198.51.100.7": 5000})
        finally:
            conn.close()

    def test_origin_is_stored_and_filtered(self):
        conn = db.connect(self.cfg.db_path)
        try:
            db.enqueue(conn, "198.51.100.7", "sshd", origin="web-1")
            db.enqueue(conn, "198.51.100.8", "sshd", origin="mail-1")
            db.enqueue(conn, "198.51.100.9", "sshd")
            now = int(time.time())
            self.assertEqual(
                sorted(item["ip"] for item in db.bans_since(conn, since=now - 60, exclude_origin="web-1")),
                ["198.51.100.8", "198.51.100.9"],
            )
            self.assertEqual(
                len(db.bans_since(conn, since=now - 60, exclude_origin="", limit=10)), 3
            )
            self.assertEqual(db.bans_since(conn, since=now + 60, exclude_origin=""), [])
        finally:
            conn.close()


class RemoteBanTests(TempDirTestCase):
    def test_ban_command_is_built_without_a_shell(self):
        runner = FakeRunner()
        applied = coordination.apply_remote_bans(
            self.cfg, [{"ip": "198.51.100.7", "jail": "sshd"}], runner=runner
        )
        self.assertEqual(applied, 1)
        self.assertEqual(runner.calls[0], ["fail2ban-client", "set", "sshd", "banip", "198.51.100.7"])

    def test_ignored_ranges_and_own_address_are_skipped(self):
        runner = FakeRunner()
        self.cfg.server_ip = "203.0.113.10"
        applied = coordination.apply_remote_bans(
            self.cfg,
            [
                {"ip": "127.0.0.1", "jail": "sshd"},  # ignore range (helpers config)
                {"ip": "203.0.113.10", "jail": "sshd"},  # own server_ip
                {"ip": "not-an-ip", "jail": "sshd"},
                {"ip": "198.51.100.7", "jail": "sshd"},
            ],
            runner=runner,
        )
        self.assertEqual(applied, 1)
        self.assertEqual(runner.banned(), ["198.51.100.7"])

    def test_invalid_jail_is_skipped(self):
        runner = FakeRunner()
        applied = coordination.apply_remote_bans(
            self.cfg,
            [
                {"ip": "198.51.100.7", "jail": "sshd; rm -rf /"},
                {"ip": "198.51.100.8", "jail": ""},
                {"ip": "198.51.100.9", "jail": "sshd"},
            ],
            runner=runner,
        )
        self.assertEqual(applied, 1)
        self.assertEqual(runner.calls[0][3:], ["banip", "198.51.100.9"])

    def test_cap_limits_one_run(self):
        runner = FakeRunner()
        items = [{"ip": "198.51.100.%d" % n, "jail": "sshd"} for n in range(10, 20)]
        applied = coordination.apply_remote_bans(self.cfg, items, limit=3, runner=runner)
        self.assertEqual(applied, 3)
        self.assertEqual(len(runner.calls), 3)

    def test_failed_command_is_not_counted(self):
        runner = FakeRunner(code=255, stderr="ERROR unable to find jail")
        applied = coordination.apply_remote_bans(
            self.cfg, [{"ip": "198.51.100.7", "jail": "nosuchjail"}], runner=runner
        )
        self.assertEqual(applied, 0)

    def test_sync_bans_can_be_disabled(self):
        self.cfg.sync_bans = False
        self.assertFalse(self.cfg.sync_bans)


class LeaderAnswerTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.cfg.coordination_mode = "leader"
        self.cfg.node_id = "leader-1"
        conn = db.connect(self.cfg.db_path)
        try:
            now = int(time.time())
            # a ban that came from another node, and one this node made itself
            conn.execute(
                "INSERT INTO events(ip, jail, event_time, created_at, origin) VALUES (?,?,?,?,?)",
                ("198.51.100.20", "sshd", now - 30, now - 30, "web-1"),
            )
            conn.execute(
                "INSERT INTO events(ip, jail, event_time, created_at, origin) VALUES (?,?,?,?,?)",
                ("198.51.100.21", "sshd", now - 20, now - 20, ""),
            )
            conn.commit()
        finally:
            conn.close()

    def test_answer_carries_bans_reports_and_cursor(self):
        now = int(time.time())
        answer = coordination.sync_response(
            self.cfg, "mail-1", [{"ip": "198.51.100.30", "jail": "sshd"}], since=now - 120, now=now
        )
        self.assertTrue(answer["ok"])
        self.assertEqual(answer["accepted"], 1)
        self.assertEqual(answer["inserted"], 1)
        self.assertEqual(answer["next_since"], now)
        self.assertEqual(answer["node_id"], "leader-1")
        self.assertEqual(
            sorted(item["ip"] for item in answer["to_ban"]),
            ["198.51.100.20", "198.51.100.21"],
        )

    def test_bans_are_not_echoed_to_their_origin(self):
        now = int(time.time())
        answer = coordination.sync_response(
            self.cfg, "web-1", [], since=now - 120, now=now
        )
        self.assertEqual([item["ip"] for item in answer["to_ban"]], ["198.51.100.21"])

    def test_old_bans_are_not_propagated_twice(self):
        now = int(time.time())
        answer = coordination.sync_response(self.cfg, "mail-1", [], since=now + 60, now=now)
        self.assertEqual(answer["to_ban"], [])

    def test_recently_reported_uses_the_peer_window(self):
        conn = db.connect(self.cfg.db_path)
        try:
            db.record_attempt(
                conn, "198.51.100.40", "sshd", 200, "18", "c", "r", reported_at=int(time.time()) - 60
            )
            conn.commit()
        finally:
            conn.close()
        answer = coordination.sync_response(self.cfg, "mail-1", [], now=int(time.time()))
        self.assertEqual(answer["recently_reported"], {"198.51.100.40": int(time.time()) - 60})


class JailFilterTests(TempDirTestCase):
    """A node declares what it can ban in; the leader sends nothing else."""

    def setUp(self):
        super().setUp()
        self.cfg.coordination_mode = "leader"
        self.cfg.node_id = "leader-1"
        now = int(time.time())
        conn = db.connect(self.cfg.db_path)
        try:
            for ip, jail in (
                ("198.51.100.11", "sshd"),
                ("198.51.100.12", "nginx-php-probe"),
                ("198.51.100.13", "sshd"),
            ):
                conn.execute(
                    "INSERT INTO events(ip, jail, event_time, created_at, origin)"
                    " VALUES (?,?,?,?,?)",
                    (ip, jail, now - 5, now - 5, ""),
                )
            conn.commit()
        finally:
            conn.close()

    def test_only_declared_jails_are_sent(self):
        answer = coordination.sync_response(
            self.cfg, "web-1", [], since=int(time.time()) - 300, jails=["sshd"]
        )
        self.assertEqual(
            sorted(item["ip"] for item in answer["to_ban"]), ["198.51.100.11", "198.51.100.13"]
        )
        self.assertTrue(all(item["jail"] == "sshd" for item in answer["to_ban"]))

    def test_unknown_jail_list_sends_everything(self):
        answer = coordination.sync_response(
            self.cfg, "web-1", [], since=int(time.time()) - 300
        )
        self.assertEqual(len(answer["to_ban"]), 3)

    def test_empty_list_is_treated_as_unknown(self):
        answer = coordination.sync_response(
            self.cfg, "web-1", [], since=int(time.time()) - 300, jails=[]
        )
        self.assertEqual(len(answer["to_ban"]), 3)

    def test_garbage_in_the_declared_list_is_ignored(self):
        answer = coordination.sync_response(
            self.cfg,
            "web-1",
            [],
            since=int(time.time()) - 300,
            jails=["sshd", "sshd; rm -rf /", ""],
        )
        self.assertEqual(
            sorted(item["ip"] for item in answer["to_ban"]), ["198.51.100.11", "198.51.100.13"]
        )

    def test_the_cap_is_applied_after_filtering(self):
        answer = coordination.sync_response(
            self.cfg, "web-1", [], since=int(time.time()) - 300, jails=["sshd"], now=int(time.time())
        )
        self.cfg.max_sync_bans = 1
        answer = coordination.sync_response(
            self.cfg, "web-1", [], since=int(time.time()) - 300, jails=["sshd"]
        )
        self.assertEqual(len(answer["to_ban"]), 1)

    def test_local_jails_are_parsed_and_cached(self):
        conn = db.connect(self.cfg.db_path)
        try:
            calls = []

            def runner(argv, timeout=12):
                calls.append(list(argv))
                return (
                    0,
                    "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, nginx-php-probe\n",
                    "",
                )

            jails = coordination._local_jails(self.cfg, conn, runner=runner, now=1000)
            self.assertEqual(jails, ["sshd", "nginx-php-probe"])
            self.assertEqual(calls[0], ["fail2ban-client", "status"])
            # a second call inside the TTL does not shell out again
            again = coordination._local_jails(self.cfg, conn, runner=runner, now=1100)
            self.assertEqual(again, ["sshd", "nginx-php-probe"])
            self.assertEqual(len(calls), 1)
            # after the TTL it does
            coordination._local_jails(self.cfg, conn, runner=runner, now=1000 + coordination.JAILS_TTL + 5)
            self.assertEqual(len(calls), 2)
        finally:
            conn.close()

    def test_missing_fail2ban_client_declares_nothing(self):
        conn = db.connect(self.cfg.db_path)
        try:
            def runner(argv, timeout=12):
                return 1, "", "No such file or directory"

            self.assertEqual(coordination._local_jails(self.cfg, conn, runner=runner), [])
        finally:
            conn.close()


class SyncEndToEndTests(TempDirTestCase):
    """Leader endpoint + follower run, on the loopback interface."""

    def setUp(self):
        super().setUp()
        self.leader_cfg = self.cfg
        self.leader_cfg.coordination_mode = "leader"
        self.leader_cfg.node_id = "leader-1"
        self.leader_cfg.coord_bind = "127.0.0.1"
        self.leader_cfg.coord_port = 0
        self.leader_cfg.shared_secret_file = os.path.join(self.tmp, "coord.secret")
        write_secret(self.leader_cfg)
        self.server = coord_server.make_server(self.leader_cfg)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        self.follower_dir = os.path.join(self.tmp, "follower")
        os.makedirs(self.follower_dir, exist_ok=True)
        self.follower = self._follower_config()

        # a ban the leader knows about, created by another node
        conn = db.connect(self.leader_cfg.db_path)
        try:
            now = int(time.time())
            conn.execute(
                "INSERT INTO events(ip, jail, event_time, created_at, origin) VALUES (?,?,?,?,?)",
                ("198.51.100.50", "sshd", now - 10, now - 10, "mail-1"),
            )
            conn.commit()
        finally:
            conn.close()

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

    def _enqueue(self, ip="198.51.100.60"):
        conn = db.connect(self.follower.db_path)
        try:
            db.enqueue(conn, ip, "sshd", event_time=int(time.time()) - 5, bantime=3600, failures=3)
        finally:
            conn.close()

    def _meta(self, key):
        conn = db.connect(self.follower.db_path)
        try:
            return db.get_meta(conn, key, "")
        finally:
            conn.close()

    def test_sync_pushes_events_and_applies_remote_bans(self):
        self._enqueue()
        runner = FakeRunner()
        result = reporter.run_once(self.follower, http=None, runner=runner)
        self.assertEqual(result.sent, 1)
        self.assertEqual(result.banned, 1)
        self.assertEqual(result.pending, 0)
        self.assertEqual(runner.banned(), ["198.51.100.50"])
        self.assertTrue(int(self._meta(coordination.CURSOR_KEY)) > 0)
        # the leader got the event
        leader = db.connect(self.leader_cfg.db_path)
        try:
            rows = leader.execute("SELECT ip, origin FROM events WHERE ip='198.51.100.60'").fetchall()
        finally:
            leader.close()
        self.assertEqual([(row["ip"], row["origin"]) for row in rows], [("198.51.100.60", "web-1")])

    def test_second_sync_does_not_repeat_the_ban(self):
        runner = FakeRunner()
        reporter.run_once(self.follower, runner=runner)
        first = len(runner.ban_calls())
        reporter.run_once(self.follower, runner=runner)
        self.assertEqual(len(runner.ban_calls()), first)

    def test_a_node_only_gets_bans_for_jails_it_has(self):
        # the leader's fixture ban is for sshd; this node has another jail only
        runner = FakeRunner(jails=("ragraf-sync-test",))
        result = reporter.run_once(self.follower, runner=runner)
        self.assertEqual(result.banned, 0)
        self.assertEqual(runner.banned(), [])

    def test_cache_from_the_leader_blocks_a_duplicate_report(self):
        # the leader reports 198.51.100.70 successfully, then a follower gets it
        conn = db.connect(self.leader_cfg.db_path)
        try:
            db.record_attempt(
                conn, "198.51.100.70", "sshd", 200, "18", "c", "r", reported_at=int(time.time()) - 30
            )
            conn.commit()
        finally:
            conn.close()
        self._enqueue(ip="198.51.100.70")
        runner = FakeRunner()
        reporter.run_once(self.follower, runner=runner)
        conn = db.connect(self.follower.db_path)
        try:
            self.assertTrue(db.is_recently_reported(conn, "198.51.100.70", 900))
        finally:
            conn.close()

    def test_leader_skips_an_address_a_peer_already_reported(self):
        conn = db.connect(self.leader_cfg.db_path)
        try:
            db.merge_reported(conn, {"198.51.100.80": int(time.time()) - 60}, source="web-1")
            db.enqueue(conn, "198.51.100.80", "sshd")
        finally:
            conn.close()
        http = _ForbiddenHttp()
        result = reporter.run_once(self.leader_cfg, http=http)
        reported_ips = [call.get("ip") for call in http.calls]
        self.assertNotIn("198.51.100.80", reported_ips)
        # the fixture's own ban is still reported; only the cached one is skipped
        self.assertIn("198.51.100.50", reported_ips)
        self.assertEqual(result.skipped, 1)
        conn = db.connect(self.leader_cfg.db_path)
        try:
            state = conn.execute(
                "SELECT reported FROM events WHERE ip='198.51.100.80'"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(int(state), db.REPORTED)

    def test_sync_bans_off_only_syncs_events(self):
        self._enqueue()
        self.follower.sync_bans = False
        runner = FakeRunner()
        result = reporter.run_once(self.follower, runner=runner)
        self.assertEqual(result.sent, 1)
        self.assertEqual(result.banned, 0)
        self.assertEqual(runner.calls, [])  # no fail2ban-client call at all

    def test_missing_secret_reports_a_reason(self):
        self._enqueue()
        self.follower.shared_secret_file = os.path.join(self.tmp, "absent.secret")
        result = reporter.run_once(self.follower, runner=FakeRunner())
        self.assertEqual(result.sent, 0)
        self.assertIn("missing shared secret", result.stopped_reason)

    def test_legacy_push_route_still_answers(self):
        import urllib.request

        request = urllib.request.Request(
            self.url + "/v1/push",
            data=json.dumps({"node_id": "old-node", "events": [
                {"ip": "198.51.100.90", "jail": "sshd", "event_time": int(time.time())}
            ]}).encode(),
            headers={"Content-Type": "application/json", "X-Coord-Secret": SECRET},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            body = json.loads(response.read().decode())
        self.assertEqual(response.status, 200)
        self.assertEqual(body["inserted"], 1)
        self.assertIn("to_ban", body)


class _ForbiddenHttp:
    """An AbuseIPDB client that records the fields it was asked to report."""

    def __init__(self):
        self.calls = []

    def __call__(self, url, api_key, fields, timeout):
        self.calls.append(dict(fields))
        return 200, "{}", None


if __name__ == "__main__":
    unittest.main()
