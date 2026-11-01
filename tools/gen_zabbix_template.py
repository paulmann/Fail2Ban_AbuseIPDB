"""Generate the Zabbix template and the agent2 UserParameter from one list.

The template is data, and a hand-written 900-line YAML is where mistakes live: a
mistyped metric name silently becomes "no data" months later.  Here every item is
generated from the same table the collector emits, so a renamed metric breaks the
generator test instead of the monitoring.

Layout follows the **Zabbix 8.0** export format, which is what the reference
installation returns from ``configuration.export``: UUIDs are 32 hex characters
without dashes, ``template_groups`` sits at the export root, and a trigger belongs to
the item it evaluates (``items[].triggers[]``).

Usage:

    python tools/gen_zabbix_template.py                 # write monitoring/zabbix/*
    python tools/gen_zabbix_template.py --check         # fail if the files are stale
    python tools/gen_zabbix_template.py --zabbix-version 7.0

The template has no dependency besides the Zabbix agent 2 ``UserParameter`` we ship:
``fail2ban.abuseipdb.metrics`` runs ``abuseipdb-report --metrics`` and returns the
Prometheus snapshot; dependent items parse it with the Prometheus preprocessing
rule.  Triggers carry ``server={HOST.HOST}`` and ``service=fail2ban-abuseipdb`` so a
service in the Services tree can match them per host.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from abuseipdb_reporter import __version__  # noqa: E402

TEMPLATE_NAME = "Fail2Ban AbuseIPDB reporter"
TEMPLATE_VISIBLE_NAME = "Fail2Ban AbuseIPDB reporter"
TEMPLATE_GROUP = "Templates/Applications"
ITEM_KEY = "fail2ban.abuseipdb.metrics"
SERVICE_TAG_VALUE = "fail2ban-abuseipdb"
DELAY = "5m"
UUID_NAMESPACE = "fail2ban-abuseipdb/zabbix"
#: Zabbix export layout; 8.0 is what the reference installation runs.
ZABBIX_EXPORT_VERSION = "8.0"

#: name, metric, value_type (3 = unsigned, 0 = float), units, description
NUMBER_ITEMS = [
    ("Pending events", "pending_events", 3, "", "Ban events waiting for a report."),
    ("Unpushed events", "unpushed_events", 3, "", "Follower: events not delivered to the leader."),
    ("Reported cache entries", "reported_cache_entries", 3, "",
     "Addresses reported by the cluster inside the dedupe window."),
    ("Reports today", "reports_today", 3, "", "Reports accepted since the budget day started."),
    ("Daily budget", "max_per_day", 3, "", "Configured daily report budget."),
    ("Budget remaining", "budget_remaining", 3, "", "Reports still allowed today."),
    ("Last run age", "last_run_age_seconds", 0, "s", "Seconds since the last reporter run."),
    ("Last run sent", "last_run_sent", 3, "", "Reports accepted during the last run."),
    ("Last run skipped", "last_run_skipped", 3, "", "Addresses skipped during the last run."),
    ("Last run errors", "last_run_errors", 3, "", "Errors during the last run."),
    ("Crawlers skipped", "last_run_crawlers_skipped", 3, "",
     "Addresses not reported because they are published/verified crawlers."),
    ("Sync cursor lag", "coord_cursor_lag_seconds", 0, "s",
     "Follower: seconds since the leader cursor was refreshed."),
    ("Last sync age", "coord_last_sync_age_seconds", 0, "s",
     "Follower: seconds since the last successful sync."),
    ("Sync failures", "coord_sync_failures", 3, "", "Follower: consecutive failed sync attempts."),
    ("Leader up", "leader_up", 0, "", "1 when the leader answered, 0 when it did not."),
    ("Lease held", "lease_held", 3, "", "1 when this node holds the failover lease."),
    ("Lease expires", "lease_expires", 3, "", "Unix time the failover lease expires."),
    ("Events accepted", "coord_accepted_total", 3, "",
     "Leader: events accepted from followers (cumulative)."),
    ("Events inserted", "coord_inserted_total", 3, "",
     "Leader: events queued from followers (cumulative)."),
    ("Events rejected", "coord_rejected_total", 3, "",
     "Leader: events refused by the leader's filters (cumulative)."),
    ("Remote bans applied", "coord_remote_bans_total", 3, "",
     "Follower: bans applied from other nodes (cumulative)."),
    ("Enabled", "enabled", 3, "", "1 when reporting is enabled."),
]

#: metric, trigger name, operator, constant, severity (0..5), description
TRIGGERS = [
    ("last_run_age_seconds", "Fail2Ban AbuseIPDB: no reporter run for 2 hours", ">",
     "{$ABUSEIPDB.RUN_STALE}", 3,
     "The timer or cron job stopped running: bans are queued but never reported."),
    ("last_run_errors", "Fail2Ban AbuseIPDB: last run had errors", ">", "0", 1,
     "Transient API or payload errors; a single occurrence is often a 429."),
    ("last_run_crawlers_skipped", "Fail2Ban AbuseIPDB: a crawler was banned", ">", "0", 2,
     "A fail2ban rule banned a search/LLM crawler; the report was withheld. Fix the jail "
     "- a good bot must not be banned at all."),
    ("pending_events", "Fail2Ban AbuseIPDB: queue is growing", ">",
     "{$ABUSEIPDB.PENDING.MAX}", 2,
     "Pending events keep growing: check the budget, the key and the log."),
    ("budget_remaining", "Fail2Ban AbuseIPDB: daily budget exhausted", "=", "0", 2,
     "Reports stopped for today; the queue drains after midnight UTC."),
    ("coord_last_sync_age_seconds", "Fail2Ban AbuseIPDB: follower has not synced for 45 minutes",
     ">", "{$ABUSEIPDB.SYNC_STALE}", 4,
     "Follower cannot reach the leader: events are stuck on this node."),
    ("coord_sync_failures", "Fail2Ban AbuseIPDB: follower sync is failing", ">", "2", 4,
     "Three failed sync attempts in a row: check the secret, the URL and the network."),
    ("leader_up", "Fail2Ban AbuseIPDB: leader is unreachable", "=", "0", 4,
     "The follower asked the leader and got no answer. -1 means 'not applicable'."),
    ("unpushed_events", "Fail2Ban AbuseIPDB: unpushed backlog", ">", "500", 3,
     "The follower keeps events that never reached the leader."),
]

MACROS = [
    ("{$ABUSEIPDB.PENDING.MAX}", "200", "Warning threshold for pending events."),
    ("{$ABUSEIPDB.RUN_STALE}", "7200", "Seconds after which a missing run is a problem."),
    ("{$ABUSEIPDB.SYNC_STALE}", "2700", "Follower sync age that counts as stuck."),
]

VALUE_TYPE = {0: "FLOAT", 3: "UNSIGNED"}
PRIORITY = {0: "NOT_CLASSIFIED", 1: "INFO", 2: "WARNING", 3: "AVERAGE", 4: "HIGH", 5: "DISASTER"}


def _uuid(kind: str, name: str) -> str:
    """Deterministic UUIDv4-shaped id (32 hex), so re-import updates, never duplicates.

    Zabbix validates the version and variant bits ("UUIDv4 is expected"), so the
    digest is patched into that shape instead of being used raw - the value stays
    stable for the same name, which is what makes a re-import idempotent.
    """
    digest = bytearray(hashlib.sha256(("%s/%s/%s" % (UUID_NAMESPACE, kind, name)).encode()).digest()[:16])
    digest[6] = (digest[6] & 0x0F) | 0x40  # version 4
    digest[8] = (digest[8] & 0x3F) | 0x80  # variant 10xx
    return digest.hex()


def _q(text: str) -> str:
    """Single-quote a YAML scalar: names and descriptions contain ': '."""
    return "'%s'" % str(text).replace("'", "''")


def prometheus_pattern(metric: str) -> str:
    r"""Preprocessing regex for one metric: ``<metric>\s+(\S+)``."""
    return r"%s\s+(\S+)" % metric


def render_template(version: str = "") -> str:
    """Render the template in the Zabbix 8.0 export layout.

    One agent item per number, keyed ``fail2ban.abuseipdb.metric[<name>]``: the CLI
    answers with a single value read from the snapshot file.  No preprocessing means
    no regex escaping, no ``error_handler`` requirement and no silent "no data" when
    a pattern stops matching - the item either returns a number or is unsupported,
    which is visible.
    """
    version = version or ZABBIX_EXPORT_VERSION
    lines = []
    add = lines.append
    add("# Generated by tools/gen_zabbix_template.py - do not edit by hand.")
    add("# Import: Data collection -> Templates -> Import, then link it to each host.")
    add("zabbix_export:")
    add("  version: '%s'" % version)
    add("  template_groups:")
    add("    - uuid: %s" % _uuid("group", TEMPLATE_GROUP))
    add("      name: %s" % TEMPLATE_GROUP)
    add("  templates:")
    add("    - uuid: %s" % _uuid("template", TEMPLATE_NAME))
    add("      template: %s" % TEMPLATE_NAME)
    add("      name: %s" % _q(TEMPLATE_VISIBLE_NAME))
    add("      vendor:")
    add("        name: paulmann/Fail2Ban_AbuseIPDB")
    add("        version: '%s'" % __version__)
    add("      description: |")
    for line in (
        "Fail2Ban -> AbuseIPDB reporter: queue, budget, cluster role and failover lease.",
        "",
        "Every item is one agent call: `fail2ban.abuseipdb.metric[<name>]` runs",
        "`abuseipdb-report --metric <name>`, which prints one value out of the snapshot",
        "the reporter writes after each run (/var/lib/abuseipdb/metrics.json). No",
        "preprocessing on the server side, so a missing value is visible as 'unsupported'",
        "instead of a silently empty item.",
        "",
        "Requires monitoring/zabbix/userparameter_fail2ban_abuseipdb.conf in",
        "zabbix_agent2.d/ and a `zabbix` user able to run the CLI (see docs/ZABBIX.md).",
        "",
        "Triggers are tagged `server={HOST.HOST}` and `service=%s`, so a Zabbix" % SERVICE_TAG_VALUE,
        "service per server can match them in the Services tree.",
    ):
        add("        %s" % line)
    add("      groups:")
    add("        - name: %s" % TEMPLATE_GROUP)
    add("      items:")

    by_metric = {}
    for metric, name, operator, constant, severity, comment in TRIGGERS:
        by_metric.setdefault(metric, []).append((name, operator, constant, severity, comment))

    for name, metric, value_type, units, description in NUMBER_ITEMS:
        add("        - uuid: %s" % _uuid("item", metric))
        add("          name: %s" % _q(name))
        add("          key: 'fail2ban.abuseipdb.metric[%s]'" % metric)
        add("          delay: %s" % DELAY)
        if value_type != 3:
            add("          value_type: %s" % VALUE_TYPE[value_type])
        if units:
            add("          units: '%s'" % units)
        add("          history: 7d")
        add("          trends: 90d")
        add("          description: %s" % _q(description))
        if metric in by_metric:
            add("          triggers:")
            for tname, operator, constant, severity, comment in by_metric[metric]:
                add("            - uuid: %s" % _uuid("trigger", tname))
                add("              expression: last(/%s/fail2ban.abuseipdb.metric[%s])%s%s"
                    % (TEMPLATE_NAME, metric, operator, constant))
                add("              name: %s" % _q(tname))
                add("              priority: %s" % PRIORITY[severity])
                add("              description: %s" % _q(comment))
                add("              tags:")
                add("                - tag: server")
                add("                  value: '{HOST.HOST}'")
                add("                - tag: service")
                add("                  value: %s" % SERVICE_TAG_VALUE)

    add("      macros:")
    for macro, value, description in MACROS:
        add("        - macro: '%s'" % macro)
        add("          value: '%s'" % value)
        add("          description: %s" % _q(description))
    return "\n".join(lines) + "\n"


def render_userparameter() -> str:
    return """# Fail2Ban_AbuseIPDB -> Zabbix agent (1 or 2)
#
# Install into the include directory of the agent that listens on port 10050:
#   agent 2 (Debian/Ubuntu package): /etc/zabbix/zabbix_agent2.d/
#   agent 1 (/etc/zabbix/zabbix_agentd.conf): /etc/zabbix/zabbix_agentd.d/
#   agent 1 built from source: also /etc/zabbix/zabbix_agentd.d/ (see :env include)
# then restart the agent: systemctl restart zabbix-agent2|zabbix-agent
#
# One key, one number: the CLI prints a value out of the snapshot the reporter
# writes after every run, so a poll costs one command and every item sees the same
# run.
#
# The snapshot is 0600 root:root by design (it lives next to the queue), so the
# agent needs the narrow sudo rule from monitoring/zabbix/abuseipdb-metrics-sudoers.
# Without sudo the item is unsupported - visible, not silently zero.
UserParameter=fail2ban.abuseipdb.metric[*],sudo -n /usr/local/sbin/abuseipdb-report --metric $1 2>/dev/null || echo "unsupported"
"""


def render_sudoers() -> str:
    return """# /etc/sudoers.d/zabbix-abuseipdb   (mode 0440, owner root:root)
# Only needed when the agent should ask the CLI directly instead of reading the
# metrics file, for example when /var/lib/abuseipdb stays 0600 root:root.
zabbix ALL=(root) NOPASSWD: /usr/local/sbin/abuseipdb-report --metric *
zabbix ALL=(root) NOPASSWD: /usr/local/sbin/abuseipdb-report --metrics
zabbix ALL=(root) NOPASSWD: /usr/local/sbin/abuseipdb-report --stats
"""


def render_readme() -> str:
    return """# Zabbix module for Fail2Ban_AbuseIPDB

| File | Goes to | Purpose |
|---|---|---|
| `userparameter_fail2ban_abuseipdb.conf` | `/etc/zabbix/zabbix_agent2.d/` | one `UserParameter` returning the Prometheus snapshot |
| `fail2ban_abuseipdb.yaml` | imported as a template (UI or API) | 22 items, 9 triggers, 3 macros |
| `abuseipdb-metrics-sudoers` | `/etc/sudoers.d/zabbix-abuseipdb` (optional) | lets the agent run the CLI when the metrics file is unreadable |

Regenerate after changing the metric list: `python tools/gen_zabbix_template.py`
(the generator test fails when the checked-in files are stale).

Import (API; the UI path is Data collection -> Templates -> Import):

```bash
python tools/zabbix_template.py import --url https://zabbix.example/api_jsonrpc.php \\
    --user Admin --password-env ZBX_PASSWORD
python tools/zabbix_template.py link --url ... --user Admin --hosts host1,host2
```

Triggers carry `server={HOST.HOST}` and `service=fail2ban-abuseipdb`, so one Zabbix
**service** per server matches them:

| Service | Problem tags |
|---|---|
| `Fail2Ban AbuseIPDB` (parent) | — |
| `Fail2Ban AbuseIPDB / <host>` | `server=<host>` **and** `service=fail2ban-abuseipdb` |

Details and the meaning of every number: `docs/ZABBIX.md`.
"""


FILES = {
    "fail2ban_abuseipdb.yaml": lambda: render_template(),
    "userparameter_fail2ban_abuseipdb.conf": render_userparameter,
    "abuseipdb-metrics-sudoers": render_sudoers,
    "README.md": render_readme,
}


def main(argv=None) -> int:
    global ZABBIX_EXPORT_VERSION
    parser = argparse.ArgumentParser(description="Generate the Zabbix template files.")
    parser.add_argument("--check", action="store_true", help="fail if the files are stale")
    parser.add_argument("--out", default=os.path.join(ROOT, "monitoring", "zabbix"))
    parser.add_argument(
        "--zabbix-version",
        default=ZABBIX_EXPORT_VERSION,
        help="export layout to emit (default %s)" % ZABBIX_EXPORT_VERSION,
    )
    args = parser.parse_args(argv)
    ZABBIX_EXPORT_VERSION = str(args.zabbix_version)

    os.makedirs(args.out, exist_ok=True)
    stale = []
    for name, render in FILES.items():
        path = os.path.join(args.out, name)
        content = render()
        current = ""
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                current = handle.read()
        if current != content:
            stale.append(name)
            if not args.check:
                with open(path, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(content)
    if args.check:
        if stale:
            print("stale: %s" % ", ".join(stale))
            return 1
        print("up to date: %d files" % len(FILES))
        return 0
    print("written: %s" % ", ".join(sorted(FILES)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
