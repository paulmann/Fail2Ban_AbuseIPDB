"""Configuration loading tests."""
import os
import tempfile
import unittest

import tests  # noqa: F401 - makes the in-tree src/ importable
from abuseipdb_reporter import config as config_module
from abuseipdb_reporter.config import load_config, parse_ranges

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class ConfigTests(unittest.TestCase):
    def test_missing_file_yields_safe_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(os.path.join(tmp, "absent.conf"))
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.db_path, config_module.DEFAULT_DB_PATH)
        self.assertEqual(cfg.min_interval_ip, 1200)
        self.assertIn("recidive", cfg.skip_jails)
        self.assertTrue(cfg.ignore_ranges)
        self.assertEqual(cfg.daily_budget_timezone, "utc")
        self.assertEqual(cfg.request_delay, 1.0)
        self.assertEqual(cfg.retry_after_cap, 60)
        self.assertEqual(cfg.status_path, config_module.DEFAULT_STATUS_PATH)
        self.assertEqual(cfg.prometheus_textfile, "")

    def test_example_config_is_parsable(self):
        path = os.path.join(REPO_ROOT, "config", "reporter.conf.example")
        cfg = load_config(path)
        self.assertEqual(cfg.api_key, "")
        self.assertEqual(cfg.api_key_file, "/etc/abuseipdb/.abuseipdb.key")
        self.assertIn("updater.json", cfg.update_manifest_url)
        self.assertEqual(cfg.categories_for("sshd"), [18, 22])
        self.assertEqual(cfg.categories_for("proftpd"), [5, 18])
        self.assertEqual(cfg.comment_max_bytes, 1000)
        self.assertEqual(cfg.max_reports_per_day, 900)
        self.assertEqual(cfg.retention_days, 30)
        self.assertIn("203.0.113.10", cfg.server_ip)
        self.assertTrue(any(str(network) == "10.0.0.0/8" for network in cfg.ignore_ranges))

    def test_custom_category_map_and_quiet(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "reporter.conf")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "[abuseipdb]\napi_key = k\nmin_interval_ip = 60\n\n"
                    "[category_map]\nmyjail = 15,21\n"
                )
            cfg = load_config(path, quiet=True)
        self.assertEqual(cfg.api_key, "k")
        self.assertEqual(cfg.min_interval_ip, 60)
        self.assertEqual(cfg.categories_for("myjail"), [15, 21])
        self.assertTrue(cfg.quiet)
        # unknown jail falls back to the generic category
        self.assertEqual(cfg.categories_for("unknown-jail"), [21])

    def test_parse_ranges_ignores_garbage(self):
        networks = parse_ranges("10.0.0.0/8, not-a-network, 192.168.0.0/16")
        self.assertEqual(len(networks), 2)

    def test_parse_ranges_drops_inline_comments(self):
        networks = parse_ranges(
            "10.0.0.0/8   # office\n192.168.0.0/16,\n203.0.113.10/32  # mgmt"
        )
        self.assertEqual(
            sorted(str(network) for network in networks),
            ["10.0.0.0/8", "192.168.0.0/16", "203.0.113.10/32"],
        )

    def test_legacy_api_key_is_still_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "reporter.conf")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("[abuseipdb]\napi_key = legacy-key\napi_key_file = %s/key\n" % tmp)
            cfg = load_config(path)
        self.assertEqual(cfg.api_key, "legacy-key")
        self.assertEqual(cfg.api_key_file, "%s/key" % tmp)

    def test_bad_values_fall_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "reporter.conf")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("[abuseipdb]\ntimeout = abc\nmax_reports_per_day = -5\n")
            cfg = load_config(path)
        self.assertEqual(cfg.timeout, 25)
        self.assertEqual(cfg.max_reports_per_day, -5)

    def test_rate_limit_and_status_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "reporter.conf")
            status_path = os.path.join(tmp, "status.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "[abuseipdb]\ndaily_budget_timezone = LOCAL\nrequest_delay = 2.5\n"
                    "retry_after_cap = 15\n"
                    "[logging]\nstatus_path = %s\nprometheus_textfile = %s/prom\n"
                    % (status_path, tmp)
                )
            cfg = load_config(path)
        self.assertEqual(cfg.daily_budget_timezone, "local")
        self.assertEqual(cfg.request_delay, 2.5)
        self.assertEqual(cfg.retry_after_cap, 15)
        self.assertEqual(cfg.status_path, status_path)
        self.assertTrue(cfg.prometheus_textfile.endswith("prom"))

    def test_status_file_can_be_disabled_with_an_empty_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "reporter.conf")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("[logging]\nstatus_path =\n")
            cfg = load_config(path)
        self.assertEqual(cfg.status_path, "")

    def test_budget_timezone_aliases_and_garbage(self):
        for raw, expected in (
            ("utc", "utc"),
            ("GMT", "utc"),
            ("local", "local"),
            ("server", "local"),
            ("yesterday", "utc"),
            ("", "utc"),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "reporter.conf")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("[abuseipdb]\ndaily_budget_timezone = %s\n" % raw)
                cfg = load_config(path)
            self.assertEqual(cfg.daily_budget_timezone, expected, raw)

    def test_new_jail_categories(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(os.path.join(tmp, "absent.conf"))
        self.assertEqual(cfg.categories_for("dovecot"), [18])
        self.assertEqual(cfg.categories_for("vsftpd"), [5, 18])
        self.assertEqual(cfg.categories_for("postfix-sasl"), [18])
        self.assertEqual(cfg.categories_for("nginx-badbots"), [19, 21])
        self.assertEqual(cfg.categories_for("totally-unknown"), [21])


if __name__ == "__main__":
    unittest.main()