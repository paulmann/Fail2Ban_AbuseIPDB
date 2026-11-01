#!/bin/bash
# Real-host check of the crawler rail, outside the installed configuration.
#   LIB=/path/containing/abuseipdb_reporter bash check-crawler-rail.sh
set -u
LIB=${LIB:-/usr/local/lib}
W=${W:-/tmp/f2b-crawler-rail}
rm -rf "$W"; mkdir -p "$W"

# launcher, so the package under test wins over the installed one
cat > "$W/run" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[1])
from abuseipdb_reporter.cli import main_report
sys.exit(main_report(sys.argv[2:]))
PYEOF
report() { python3 "$W/run" "$LIB" "$@"; }

cat > "$W/reporter.conf" <<EOF
[abuseipdb]
api_key = none
enabled = yes

[database]
path = $W/queue.sqlite3

[logging]
file = $W/reporter.log

[report]
never_report_crawlers = yes
crawler_rdns = yes
EOF

echo "== crawler status"
report --config "$W/reporter.conf" --crawler-status | head -6

echo
echo "== three addresses"
for ip in 66.249.66.5 157.55.39.10 8.8.8.8; do
    report --config "$W/reporter.conf" --crawler-check "$ip"
done

echo
echo "== queue one Googlebot address and one ordinary address, then run the reporter"
PYTHONPATH="$LIB" python3 - "$LIB" "$W" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from abuseipdb_reporter import config, db, reporter
cfg = config.load_config(sys.argv[2] + "/reporter.conf", quiet=True)
conn = db.connect(cfg.db_path)
db.enqueue(conn, "66.249.66.5", "sshd")
db.enqueue(conn, "185.220.101.44", "sshd")
conn.commit(); conn.close()
result = reporter.run_once(cfg, dry_run=True)
print("dry run: skipped=%d crawlers_skipped=%d" % (result.skipped, result.crawlers_skipped))
conn = db.connect(cfg.db_path)
print("pending after the run: %d" % db.pending_count(conn))
conn.close()
PY

echo
echo "== what the log says"
grep -i crawler "$W/reporter.log" 2>/dev/null | tail -3 || echo "  (log line went to syslog/journal)"
