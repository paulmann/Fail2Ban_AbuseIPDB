"""The generated Zabbix module must match the metrics the code emits."""
import os
import subprocess
import sys
import unittest

import yaml

import tests  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZABBIX_DIR = os.path.join(ROOT, "monitoring", "zabbix")
TEMPLATE = os.path.join(ZABBIX_DIR, "fail2ban_abuseipdb.yaml")


class GeneratorTests(unittest.TestCase):
    def test_files_are_up_to_date(self):
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "gen_zabbix_template.py"), "--check"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_template_is_valid_yaml_with_expected_shape(self):
        with open(TEMPLATE, "r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        export = document["zabbix_export"]
        self.assertEqual(export["version"], "8.0")
        template = export["templates"][0]
        self.assertEqual(template["template"], "Fail2Ban AbuseIPDB reporter")
        items = template["items"]
        self.assertEqual(len(items), 21)
        for item in items:
            self.assertTrue(item["key"].startswith("fail2ban.abuseipdb.metric["), item["key"])
            self.assertNotIn("preprocessing", item)  # no server-side parsing at all
            self.assertEqual(item["delay"], "5m")

    def test_every_item_names_a_metric_the_code_produces(self):
        sys.path.insert(0, os.path.join(ROOT, "src"))
        from abuseipdb_reporter import metrics

        with open(TEMPLATE, "r", encoding="utf-8") as handle:
            template = yaml.safe_load(handle)["zabbix_export"]["templates"][0]
        empty = {
            key: 0
            for key in (
                "pending_events", "unpushed_events", "reported_cache_entries", "reports_today",
                "max_per_day", "budget_remaining", "last_run_age_seconds", "last_run_sent",
                "last_run_skipped", "last_run_errors", "cursor_lag_seconds",
                "last_sync_age_seconds", "sync_failures", "leader_up", "lease_held",
                "lease_expires", "accepted_total", "inserted_total", "rejected_total",
                "remote_bans_total", "enabled", "ts", "version", "mode", "node_id",
                "failover", "tls", "sync_bans", "last_run_ts", "last_run_stopped",
                "leader_role", "iso", "last_sync", "cursor", "last_sync_ok", "lease_owner",
            )
        }
        names = set()
        for line in metrics.prometheus(empty).splitlines():
            if line and not line.startswith("#"):
                names.add(line.split("{")[0].split(" ")[0])
        for item in template["items"]:
            metric = item["key"].split("[", 1)[1].rstrip("]")
            self.assertIn("abuseipdb_reporter_%s" % metric, names, metric)

    def test_triggers_carry_the_service_tags(self):
        with open(TEMPLATE, "r", encoding="utf-8") as handle:
            template = yaml.safe_load(handle)["zabbix_export"]["templates"][0]
        triggers = [
            trigger for item in template["items"] for trigger in item.get("triggers", [])
        ]
        self.assertEqual(len(triggers), 8)
        for trigger in triggers:
            tags = {tag["tag"]: tag["value"] for tag in trigger["tags"]}
            self.assertEqual(tags["server"], "{HOST.HOST}")
            self.assertEqual(tags["service"], "fail2ban-abuseipdb")
            self.assertIn("last(/Fail2Ban AbuseIPDB reporter/fail2ban.abuseipdb.metric[",
                          trigger["expression"])
            self.assertNotIn("()", trigger["expression"])

    def test_userparameter_ships_the_single_key(self):
        path = os.path.join(ZABBIX_DIR, "userparameter_fail2ban_abuseipdb.conf")
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("UserParameter=fail2ban.abuseipdb.metric[*]", text)
        self.assertIn("--metric $1", text)


if __name__ == "__main__":
    unittest.main()
