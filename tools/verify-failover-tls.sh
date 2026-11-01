#!/bin/bash
# End-to-end check of the failover arbiter and TLS on a real Linux host.
# Everything lives in /tmp: the production configuration is not touched.
#   LIB - directory that contains the abuseipdb_reporter package to test
set -u
WORK=${WORK:-/tmp/f2b-verify}
LIB=${LIB:-/usr/local/lib}
CONF="$WORK/witness.conf"
STATE="$WORK/lease.json"
SECRET="$WORK/secret"
CERT="$WORK/cert.pem"
KEY="$WORK/key.pem"
PORT=${PORT:-18765}

rm -rf "$WORK"
mkdir -p "$WORK"

# launchers, so the package under test wins over the installed one
cat > "$WORK/run-report" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[1])
from abuseipdb_reporter.cli import main_report
sys.exit(main_report(sys.argv[2:]))
PYEOF
cat > "$WORK/run-witness" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[1])
from abuseipdb_reporter.witness_cli import main
sys.exit(main(sys.argv[2:]))
PYEOF
report() { python3 "$WORK/run-report" "$LIB" "$@"; }
witness() { python3 "$WORK/run-witness" "$LIB" "$@"; }

# wait until the arbiter actually accepts a connection: a fixed sleep races with
# the interpreter start and made the TLS step look broken
wait_port() {
  local port=$1
  for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3>&-; return 0; fi
    sleep 0.2
  done
  echo "port $port did not open"
  return 1
}

# a port that is still bound by the previous instance makes the *new* server exit
# with "address already in use", and the next probe silently talks to the old one
wait_closed() {
  local port=$1
  for _ in $(seq 1 50); do
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then return 0; fi
    exec 3>&- 2>/dev/null || true
    sleep 0.2
  done
  echo "port $port is still open"
  return 1
}

# an orphan from an earlier run keeps the port bound even after "kill $PID" of the
# *new* instance: free it by the socket owner, not by a pattern that also matches
# this script's own command line
free_port() {
  local port=$1
  for pid in $(ss -lntpH 2>/dev/null | grep ":$port " | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
    kill "$pid" 2>/dev/null || true
  done
  sleep 1
}

cleanup() {
  [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null
  sleep 1
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== version"
report --version
echo "lib: $LIB"

echo "== secret"
head -c 32 /dev/urandom | base64 | tr -d '\n=' > "$SECRET"
chmod 600 "$SECRET"
SECRET_VALUE=$(cat "$SECRET")

cat > "$CONF" <<EOF
[abuseipdb]
api_key = none
enabled = yes

[database]
path = $WORK/queue.sqlite3

[coordination]
mode = auto
node_id = node-a
coord_bind = 127.0.0.1
coord_port = $PORT
shared_secret_file = $SECRET
lease_state_path = $STATE
failover = witness
EOF

echo "== witness --check"
witness --config "$CONF" --check || exit 1

echo "== start witness (plain HTTP)"
free_port "$PORT"
witness --config "$CONF" --state "$STATE" >"$WORK/witness.log" 2>&1 &
PID=$!
wait_port "$PORT" || { cat "$WORK/witness.log"; exit 1; }
kill -0 "$PID" 2>/dev/null || { echo "arbiter exited:"; cat "$WORK/witness.log"; exit 1; }

echo "-- health without a secret"
curl -sS -m 5 -w "\nhttp=%{http_code}\n" "http://127.0.0.1:$PORT/v1/health"

echo "-- node-a asks for the lease"
curl -sS -m 5 -w "\nhttp=%{http_code}\n" -X POST "http://127.0.0.1:$PORT/v1/lease" \
  -H "X-Coord-Secret: $SECRET_VALUE" -H 'Content-Type: application/json' \
  -d '{"node_id":"node-a","ttl":60}'

echo "-- node-b asks while node-a holds it"
curl -sS -m 5 -w "\nhttp=%{http_code}\n" -X POST "http://127.0.0.1:$PORT/v1/lease" \
  -H "X-Coord-Secret: $SECRET_VALUE" -H 'Content-Type: application/json' \
  -d '{"node_id":"node-b","ttl":60}'

echo "-- status"
curl -sS -m 5 "http://127.0.0.1:$PORT/v1/status"; echo

echo "-- wrong secret is refused"
curl -sS -m 5 -o /dev/null -w "http=%{http_code}\n" -X POST "http://127.0.0.1:$PORT/v1/lease" \
  -H "X-Coord-Secret: wrong" -H 'Content-Type: application/json' -d '{"node_id":"node-c","ttl":60}'

echo "== lease survives a restart"
kill "$PID"; wait_closed "$PORT" || { free_port "$PORT"; wait_closed "$PORT" || exit 1; }
witness --config "$CONF" --state "$STATE" >"$WORK/witness2.log" 2>&1 &
PID=$!
wait_port "$PORT" || { cat "$WORK/witness2.log"; exit 1; }
kill -0 "$PID" 2>/dev/null || { echo "arbiter exited:"; cat "$WORK/witness2.log"; exit 1; }
witness --config "$CONF" --state "$STATE" --status | head -8

echo "== TLS"
kill "$PID"; wait_closed "$PORT" || { free_port "$PORT"; wait_closed "$PORT" || exit 1; }
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$KEY" -out "$CERT" \
  -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1 || { echo "openssl missing"; exit 1; }
cat >> "$CONF" <<EOF
tls_cert = $CERT
tls_key = $KEY
EOF
witness --config "$CONF" --state "$STATE" >"$WORK/witness3.log" 2>&1 &
PID=$!
wait_port "$PORT" || { cat "$WORK/witness3.log"; exit 1; }
kill -0 "$PID" 2>/dev/null || { echo "arbiter exited:"; cat "$WORK/witness3.log"; exit 1; }
echo "-- without trusting the certificate (must fail)"
curl -sS -m 5 -o /dev/null -w "http=%{http_code}\n" "https://127.0.0.1:$PORT/v1/health" 2>&1 | tail -1
echo "-- with the certificate as CA"
curl -sS -m 5 --cacert "$CERT" -w "\nhttp=%{http_code}\n" "https://127.0.0.1:$PORT/v1/health"

echo "== follower sync against a closed port (retries + counters)"
cat > "$WORK/follower.conf" <<EOF
[abuseipdb]
api_key = none
enabled = yes
metrics_json_path = $WORK/metrics.json
metrics_textfile = $WORK/metrics.prom

[database]
path = $WORK/follower.sqlite3

[coordination]
mode = follower
node_id = node-b
leader_url = http://127.0.0.1:19
shared_secret_file = $SECRET
sync_attempts = 2
sync_retry_base = 0.2
EOF
report --config "$WORK/follower.conf" 2>&1 | tail -4
echo "-- metrics after the failed sync"
report --config "$WORK/follower.conf" --metric coord_sync_failures
report --config "$WORK/follower.conf" --metric leader_up

echo "== coordinator endpoint over TLS (leader side)"
cat > "$WORK/leader.conf" <<EOF
[abuseipdb]
api_key = none
enabled = yes

[database]
path = $WORK/leader.sqlite3

[coordination]
mode = leader
node_id = node-leader
coord_bind = 127.0.0.1
coord_port = 18768
shared_secret_file = $SECRET
skip_jails =
tls_cert = $CERT
tls_key = $KEY
EOF
cat > "$WORK/run-coord" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[1])
from abuseipdb_reporter.coord_server import main
sys.exit(main(sys.argv[2:]))
PYEOF
python3 "$WORK/run-coord" "$LIB" --config "$WORK/leader.conf" >"$WORK/coord.log" 2>&1 &
COORD_PID=$!
free_port 18768
for _ in $(seq 1 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/18768") 2>/dev/null; then exec 3>&-; break; fi
  sleep 0.2
done
kill -0 "$COORD_PID" 2>/dev/null || { echo "coordinator exited:"; cat "$WORK/coord.log"; }

echo "-- health, no secret"
curl -sS -m 5 --cacert "$CERT" -w "\nhttp=%{http_code}\n" https://127.0.0.1:18768/v1/health

echo "-- status without a secret is refused"
curl -sS -m 5 --cacert "$CERT" -o /dev/null -w "http=%{http_code}\n" https://127.0.0.1:18768/v1/status

echo "-- one sync with the secret"
curl -sS -m 5 --cacert "$CERT" -X POST "https://127.0.0.1:18768/v1/sync" \
  -H "X-Coord-Secret: $SECRET_VALUE" -H 'Content-Type: application/json' \
  -d '{"node_id":"node-b","since":0,"events":[{"ip":"198.51.100.77","jail":"sshd","event_time":0,"bantime":600,"failures":3}],"jails":["sshd"]}'
echo
# 198.51.100.0/24 is in the default [ignore] ranges on purpose, so "inserted: 0,
# rejected: 1" above is the rails working, not a failure
echo "-- the event landed in the leader queue"
report --config "$WORK/leader.conf" --metric pending_events
kill "$COORD_PID" 2>/dev/null

echo "== auto role without the arbiter (must stay follower)"
sed -i "s|^coord_port = .*|coord_port = 18799|" "$CONF"
report --config "$CONF" --coord-status 2>&1 | head -8

echo "== done"
