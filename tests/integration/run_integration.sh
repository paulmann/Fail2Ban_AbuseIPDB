#!/usr/bin/env bash
# End-to-end integration test against a local mock AbuseIPDB API.
# No external network access and no root privileges are required.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${MOCK_PORT:-8899}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/f2b-abuseipdb-int.XXXXXX")"
MOCK_PID=""

cleanup() {
  if [ -n "$MOCK_PID" ]; then
    kill "$MOCK_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

cd "$REPO_DIR"
export PYTHONPATH="$REPO_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

echo "== starting mock API on 127.0.0.1:${PORT}"
python3 tools/mock_abuseipdb.py "$WORK/requests.jsonl" "$PORT" >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 50); do
  if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.2); sys.exit(0 if s.connect_ex(('127.0.0.1',$PORT))==0 else 1)"; then
    break
  fi
  sleep 0.1
done

echo "== creating temporary config and fail2ban evidence database"
python3 - "$WORK" <<'PY'
import json, os, sqlite3, sys
work = sys.argv[1]
db = sqlite3.connect(os.path.join(work, "fail2ban.sqlite3"))
db.execute(
    "CREATE TABLE bips (ip TEXT NOT NULL, jail TEXT NOT NULL, timeofban INTEGER NOT NULL,"
    " bantime INTEGER NOT NULL, bancount INTEGER NOT NULL DEFAULT 1, data JSON)"
)
matches = [
    '198.51.100.7 - - [02/Jan/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 404 0',
    '198.51.100.7 - - [02/Jan/2026:00:00:01 +0000] "GET /.git/config HTTP/1.1" 404 0',
]
db.execute(
    "INSERT INTO bips(ip,jail,timeofban,bantime,bancount,data) VALUES (?,?,?,?,?,?)",
    ("198.51.100.7", "nginx-attack-scan", 1700000000, 86400, 1,
     json.dumps({"matches": matches, "failures": 5})),
)
db.commit()
db.close()
PY

cat > "$WORK/reporter.conf" <<EOF
[abuseipdb]
api_key = integration-test-key
api_url = http://127.0.0.1:${PORT}/api/v2/report
check_url = http://127.0.0.1:${PORT}/api/v2/check
timeout = 5
min_interval_ip = 1200
max_reports_per_run = 10
max_reports_per_day = 100

[database]
path = $WORK/queue.sqlite3
fail2ban_db = $WORK/fail2ban.sqlite3

[report]
server_ip = 203.0.113.10

[ignore]
ranges = 127.0.0.0/8

[category_map]
nginx-attack-scan = 21,19
EOF

echo "== queueing one ban (as the fail2ban action would)"
python3 bin/abuseipdb-enqueue --config "$WORK/reporter.conf" --ip 198.51.100.7 \
  --jail nginx-attack-scan --bantime 86400 --failures 5

echo "== dry-run payload"
python3 bin/abuseipdb-report --config "$WORK/reporter.conf" --dry-run > "$WORK/dry.jsonl"
python3 - "$WORK/dry.jsonl" <<'PY'
import json, sys
payloads = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
assert len(payloads) == 1, payloads
payload = payloads[0]
assert payload["ip"] == "198.51.100.7"
assert "GET /.env -> 404" in payload["comment"], payload["comment"]
assert payload["comment"].endswith(
    "Reported via Fail2Ban_AbuseIPDB Monitor: https://github.com/paulmann/Fail2Ban_AbuseIPDB"
), payload["comment"]
assert len(payload["comment"].encode()) <= 1000
print("dry-run payload OK (%d bytes)" % len(payload["comment"].encode()))
PY

echo "== real run against the mock API"
python3 bin/abuseipdb-report --config "$WORK/reporter.conf"

python3 - "$WORK" <<'PY'
import json, os, sqlite3, sys
work = sys.argv[1]
requests = [json.loads(line) for line in open(os.path.join(work, "requests.jsonl"))]
assert len(requests) == 1, "expected exactly one API call, got %d" % len(requests)
record = requests[0]
assert record["path"] == "/api/v2/report"
assert record["headers"].get("Key") == "integration-test-key"
assert "ip=198.51.100.7" in record["body"]
assert "categories=19%2C21" in record["body"] or "categories=21%2C19" in record["body"]
db = sqlite3.connect(os.path.join(work, "queue.sqlite3"))
assert db.execute("SELECT COUNT(*) FROM events WHERE reported=0").fetchone()[0] == 0
assert db.execute("SELECT COUNT(*) FROM reports WHERE status=200").fetchone()[0] == 1
print("API call, report journal and queue state OK")
PY

echo "== failure modes (429 / 422 / 500-then-200)"
python3 bin/abuseipdb-enqueue --config "$WORK/reporter.conf" --ip 203.0.113.250 --jail nginx-attack-scan --allow-reserved
python3 bin/abuseipdb-enqueue --config "$WORK/reporter.conf" --ip 203.0.113.251 --jail nginx-attack-scan --allow-reserved
python3 bin/abuseipdb-enqueue --config "$WORK/reporter.conf" --ip 203.0.113.252 --jail nginx-attack-scan --allow-reserved
python3 bin/abuseipdb-report --config "$WORK/reporter.conf" >/dev/null
python3 bin/abuseipdb-report --config "$WORK/reporter.conf" >/dev/null

python3 - "$WORK" <<'PY'
import os, sqlite3, sys
work = sys.argv[1]
db = sqlite3.connect(os.path.join(work, "queue.sqlite3"))
states = dict(db.execute("SELECT ip, reported FROM events WHERE ip LIKE '203.0.113.%'"))
assert states["203.0.113.250"] == 0, "429 must stay pending"
assert states["203.0.113.251"] == 2, "422 must be marked invalid"
assert states["203.0.113.252"] == 1, "500 must be retried and then succeed"
print("failure-mode handling OK")
PY

echo
echo "INTEGRATION TEST PASSED"