"""Windows-side end-to-end rehearsal of the worker (the bash integration test
uses POSIX paths and runs in CI on Linux).

Starts the bundled mock AbuseIPDB API, seeds a fail2ban evidence database,
enqueues one ban, then checks: dry-run payload, a real run against the mock,
the queue state, status.json, the Prometheus textfile and ``--status``.
"""
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise SystemExit("mock API did not start on port %d" % port)


def run(args, **kwargs):
    return subprocess.run(args, cwd=REPO, capture_output=True, text=True, **kwargs)


def coordination_round(work, leader_config, requests_path):
    """Leader/follower round trip on the loopback interface, no external network."""
    coord_port = free_port()
    secret_path = os.path.join(work, "coord.secret")
    with open(secret_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("e2e-" + "s" * 40 + "\n")

    with open(leader_config, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(
            "\n[coordination]\nmode = leader\nnode_id = leader-1\n"
            "shared_secret_file = %s\ncoord_bind = 127.0.0.1\ncoord_port = %d\n"
            % (secret_path.replace("\\", "/"), coord_port)
        )

    coord = subprocess.Popen(
        [PY, "bin/abuseipdb-coord", "--config", leader_config],
        cwd=REPO,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_for(coord_port)
        check = run([PY, "bin/abuseipdb-coord", "--check", "--config", leader_config])
        assert check.returncode == 0, check.stdout + check.stderr
        assert "secret: present" in check.stdout, check.stdout

        follower_dir = os.path.join(work, "follower")
        os.makedirs(follower_dir, exist_ok=True)
        follower_config = os.path.join(follower_dir, "reporter.conf")
        with open(follower_config, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(
                "[abuseipdb]\ntimeout = 5\n"
                "[database]\npath = %s\nfail2ban_db = %s\n"
                "[logging]\npath = %s\n"
                "[ignore]\nranges = 127.0.0.0/8\n"
                "[coordination]\nmode = follower\nnode_id = web-1\n"
                "leader_url = http://127.0.0.1:%d\nshared_secret_file = %s\n"
                "push_batch_size = 50\n"
                % (
                    os.path.join(follower_dir, "queue.sqlite3").replace("\\", "/"),
                    os.path.join(work, "fail2ban.sqlite3").replace("\\", "/"),
                    os.path.join(follower_dir, "reporter.log").replace("\\", "/"),
                    coord_port,
                    secret_path.replace("\\", "/"),
                )
            )

        for ip in ("198.51.100.20", "198.51.100.21"):
            out = run(
                [PY, "bin/abuseipdb-enqueue", "--config", follower_config, "--ip", ip,
                 "--jail", "sshd", "--bantime", "3600", "--failures", "5"]
            )
            assert out.returncode == 0, out.stderr

        dry = run([PY, "bin/abuseipdb-report", "--config", follower_config, "--dry-run"])
        assert dry.returncode == 0, dry.stderr
        previews = [json.loads(line) for line in dry.stdout.splitlines() if line.startswith("{")]
        assert len(previews) == 2, previews

        pushed = run([PY, "bin/abuseipdb-report", "--config", follower_config])
        assert pushed.returncode == 0, pushed.stderr
        assert "pushed=2" in pushed.stdout, pushed.stdout

        follower_db = sqlite3.connect(os.path.join(follower_dir, "queue.sqlite3"))
        states = follower_db.execute("SELECT pushed, reported FROM events").fetchall()
        follower_db.close()
        assert states == [(1, 0), (1, 0)], states

        leader_db = sqlite3.connect(os.path.join(work, "queue.sqlite3"))
        queued = [
            row[0]
            for row in leader_db.execute("SELECT ip FROM events WHERE reported=0 ORDER BY ip")
        ]
        leader_db.close()
        assert queued == ["198.51.100.20", "198.51.100.21"], queued

        status_out = run([PY, "bin/abuseipdb-report", "--config", follower_config, "--coord-status"])
        assert status_out.returncode == 0, status_out.stderr
        assert '"role": "leader"' in status_out.stdout, status_out.stdout

        leader_run = run([PY, "bin/abuseipdb-report", "--config", leader_config])
        assert leader_run.returncode == 0, leader_run.stderr
        assert "sent=2" in leader_run.stdout, leader_run.stdout
        with open(requests_path, "r", encoding="utf-8") as handle:
            total = [json.loads(line) for line in handle if line.strip()]
        assert len(total) == 3, "expected 3 API calls in total, got %d" % len(total)
        print(
            "coordination OK: follower pushed 2 events, leader reported them "
            "(3 API calls in total)"
        )
    finally:
        coord.terminate()
        try:
            coord.wait(timeout=5)
        except subprocess.TimeoutExpired:
            coord.kill()


def main() -> int:
    work = tempfile.mkdtemp(prefix="f2b-e2e-")
    port = free_port()
    requests_path = os.path.join(work, "requests.jsonl")

    fail2ban_db = os.path.join(work, "fail2ban.sqlite3")
    conn = sqlite3.connect(fail2ban_db)
    conn.execute(
        "CREATE TABLE bips (ip TEXT NOT NULL, jail TEXT NOT NULL, timeofban INTEGER NOT NULL,"
        " bantime INTEGER NOT NULL, bancount INTEGER NOT NULL DEFAULT 1, data JSON)"
    )
    matches = [
        '198.51.100.7 - - [02/Jan/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 404 0',
        '198.51.100.7 - - [02/Jan/2026:00:00:01 +0000] "GET /?id=1%20UNION%20SELECT%201 HTTP/1.1" 500 0',
    ]
    conn.execute(
        "INSERT INTO bips(ip,jail,timeofban,bantime,bancount,data) VALUES (?,?,?,?,?,?)",
        ("198.51.100.7", "nginx-attack-scan", 1700000000, 86400, 1,
         json.dumps({"matches": matches, "failures": 5})),
    )
    conn.commit()
    conn.close()

    key_file = os.path.join(work, ".abuseipdb.key")
    with open(key_file, "w", encoding="utf-8") as handle:
        handle.write("integration-test-key\n")

    config = os.path.join(work, "reporter.conf")
    with open(config, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(
            "[abuseipdb]\n"
            "api_key_file = %s\n"
            "api_url = http://127.0.0.1:%d/api/v2/report\n"
            "check_url = http://127.0.0.1:%d/api/v2/check\n"
            "timeout = 5\nmax_reports_per_run = 10\nmax_reports_per_day = 100\n"
            "[database]\npath = %s\nfail2ban_db = %s\n"
            "[report]\nserver_ip = 203.0.113.10\n"
            "[logging]\npath = %s\nstatus_path = %s\nprometheus_textfile = %s\n"
            "[ignore]\nranges = 127.0.0.0/8\n"
            "[category_map]\nnginx-attack-scan = 21,19\n"
            % (
                key_file.replace("\\", "/"),
                port, port,
                os.path.join(work, "queue.sqlite3").replace("\\", "/"),
                fail2ban_db.replace("\\", "/"),
                os.path.join(work, "reporter.log").replace("\\", "/"),
                os.path.join(work, "status.json").replace("\\", "/"),
                os.path.join(work, "abuseipdb.prom").replace("\\", "/"),
            )
        )

    mock = subprocess.Popen(
        [PY, os.path.join(REPO, "tools", "mock_abuseipdb.py"), requests_path, str(port)],
        cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        wait_for(port)
        print("mock API on 127.0.0.1:%d" % port)

        out = run([PY, "bin/abuseipdb-enqueue", "--config", config, "--ip", "198.51.100.7",
                   "--jail", "nginx-attack-scan", "--bantime", "86400", "--failures", "5"])
        assert out.returncode == 0, out.stderr
        print("enqueue:", out.stdout.strip())

        dry = run([PY, "bin/abuseipdb-report", "--config", config, "--dry-run"])
        assert dry.returncode == 0, dry.stderr
        payload = json.loads([line for line in dry.stdout.splitlines() if line.strip()][-1])
        assert payload["ip"] == "198.51.100.7", payload
        assert "GET /.env -> 404" in payload["comment"], payload["comment"]
        categories = payload["categories"].split(",")
        assert "16" in categories, payload["categories"]  # SQL injection detected
        assert "19" in categories and "21" in categories, payload["categories"]
        assert payload["comment"].endswith(
            "Reported via Fail2Ban_AbuseIPDB Monitor: https://github.com/paulmann/Fail2Ban_AbuseIPDB"
        )
        assert len(payload["comment"].encode()) <= 1000
        print("dry-run payload OK (%d bytes, categories %s)"
              % (len(payload["comment"].encode()), payload["categories"]))

        real = run([PY, "bin/abuseipdb-report", "--config", config])
        assert real.returncode == 0, real.stderr
        print("run:", [line for line in real.stdout.splitlines() if "run done" in line][-1])

        with open(requests_path, "r", encoding="utf-8") as handle:
            sent = [json.loads(line) for line in handle if line.strip()]
        assert len(sent) == 1, "expected one API call, got %d" % len(sent)
        assert sent[0]["headers"].get("Key") == "integration-test-key", sent[0]["headers"]
        assert "ip=198.51.100.7" in sent[0]["body"]

        queue = sqlite3.connect(os.path.join(work, "queue.sqlite3"))
        pending = queue.execute("SELECT COUNT(*) FROM events WHERE reported=0").fetchone()[0]
        accepted = queue.execute("SELECT COUNT(*) FROM reports WHERE status=200").fetchone()[0]
        queue.close()
        assert pending == 0 and accepted == 1, (pending, accepted)

        with open(os.path.join(work, "status.json"), "r", encoding="utf-8") as handle:
            status = json.load(handle)
        assert status["sent"] == 1 and status["pending"] == 0, status
        assert status["budget_timezone"] == "utc", status
        with open(os.path.join(work, "abuseipdb.prom"), "r", encoding="utf-8") as handle:
            metrics = handle.read()
        for name in ("pending_events", "reports_today", "sent_last_run", "run_ok", "budget_remaining"):
            assert "abuseipdb_reporter_%s " % name in metrics, name

        printed = run([PY, "bin/abuseipdb-report", "--config", config, "--status"])
        assert printed.returncode == 0, printed.stderr
        assert json.loads(printed.stdout)["version"] == status["version"]

        print("queue state, status.json, metrics and --status OK (version %s)"
              % status["version"])

        coordination_round(work, config, requests_path)
    finally:
        mock.terminate()
        try:
            mock.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mock.kill()
    print("E2E OK; work dir:", work)
    return 0


if __name__ == "__main__":
    sys.exit(main())
