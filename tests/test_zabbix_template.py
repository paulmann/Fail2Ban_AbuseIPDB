"""The generated Zabbix module must match the metrics the code emits."""
import os
import subprocess
import sys
import unittest

import tests  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZABBIX_DIR = os.path.join(ROOT, "monitoring", "zabbix")
TEMPLATE = os.path.join(ZABBIX_DIR, "fail2ban_abuseipdb.yaml")


class GeneratorTests(unittest.TestCase):
    """Text-level checks: the project ships no YAML dependency, not even for tests.

    The generated file is validated for real by importing it into Zabbix (done for
    1.5.0: 21 items, 8 triggers, 3 macros landed), so CI only has to prove that the
    checked-in files match the generator and keep the shape the template needs.
    """

    def test_files_are_up_to_date(self):
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "gen_zabbix_template.py"), "--check"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def _template(self):
        with open(TEMPLATE, "r", encoding="utf-8") as handle:
            return handle.read()

    def test_shape_of_the_template(self):
        text = self._template()
        self.assertIn("zabbix_export:", text)
        self.assertIn("version: '8.0'", text)
        self.assertIn("template: Fail2Ban AbuseIPDB reporter", text)
        self.assertEqual(text.count("key: 'fail2ban.abuseipdb.metric["), 21)
        self.assertEqual(text.count("expression: last(/Fail2Ban AbuseIPDB reporter/"), 8)
        self.assertEqual(text.count("- macro: '{$ABUSEIPDB."), 3)
        self.assertNotIn("type: PROMETHEUS_PATTERN", text)  # no server-side parsing
        self.assertNotIn("\n          preprocessing:", text)

    def test_every_item_names_a_metric_the_code_produces(self):
        sys.path.insert(0, os.path.join(ROOT, "src"))
        from abuseipdb_reporter import metrics

        empty = {key: 0 for key in (
            "pending_events", "unpushed_events", "reported_cache_entries", "reports_today",
            "max_per_day", "budget_remaining", "last_run_age_seconds", "last_run_sent",
            "last_run_skipped", "last_run_errors", "cursor_lag_seconds",
            "last_sync_age_seconds", "sync_failures", "leader_up", "lease_held",
            "lease_expires", "accepted_total", "inserted_total", "rejected_total",
            "remote_bans_total", "enabled",
        )}
        document = metrics.prometheus(empty)
        for line in self._template().splitlines():
            line = line.strip()
            if not line.startswith("key: 'fail2ban.abuseipdb.metric["):
                continue
            metric = line.split("[", 1)[1].rstrip("]'")
            self.assertIn("abuseipdb_reporter_%s " % metric, document, metric)

    def test_triggers_carry_the_service_tags(self):
        text = self._template()
        block = text.split("triggers:")[1] if "triggers:" in text else ""
        self.assertIn("value: '{HOST.HOST}'", text)
        self.assertIn("value: fail2ban-abuseipdb", text)
        self.assertNotIn("()", text)  # no leftover empty function call
        self.assertIn("}", block or text)  # the macro form is used

    def test_userparameter_ships_the_single_key(self):
        path = os.path.join(ZABBIX_DIR, "userparameter_fail2ban_abuseipdb.conf")
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("UserParameter=fail2ban.abuseipdb.metric[*]", text)
        self.assertIn("--metric $1", text)


if __name__ == "__main__":
    unittest.main()
