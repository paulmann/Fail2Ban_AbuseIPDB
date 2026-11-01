"""The crawler rail: a ban is reversible, an abuse report is not."""
import ipaddress
import os
import sys
import unittest
import unittest.mock

import tests  # noqa: F401
from abuseipdb_reporter import config as config_module
from abuseipdb_reporter import crawler_ranges, crawlers, db, reporter
from tests.helpers import TempDirTestCase, make_config


class RangeTests(unittest.TestCase):
    def test_generated_module_carries_its_sources(self):
        self.assertTrue(crawler_ranges.SOURCES, "no sources recorded")
        for label, meta in crawler_ranges.SOURCES.items():
            self.assertTrue(meta["url"].startswith("https://"), label)
            self.assertTrue(meta["creation_time"], label)
            self.assertEqual(meta["count"], len(crawler_ranges.RANGES[label]), label)
        self.assertGreaterEqual(len(crawler_ranges.RANGES["google"]), 100)

    def test_published_ranges_are_recognised(self):
        for text, label in (
            ("66.249.66.5", "google"),
            ("192.178.4.10", "google"),
            ("20.171.206.7", "openai_gptbot"),
        ):
            found, reason = crawlers.is_crawler(text, use_dns=False)
            self.assertTrue(found, text)
            self.assertIn(label, reason)

    def test_ordinary_addresses_are_not(self):
        for text in ("8.8.8.8", "198.51.100.7", "185.220.101.1"):
            found, reason = crawlers.is_crawler(text, use_dns=False)
            self.assertFalse(found, "%s -> %s" % (text, reason))

    def test_garbage_is_not_a_crawler(self):
        for text in ("", "not-an-ip", "301.1.1.1", None):
            self.assertEqual(crawlers.is_crawler(text, use_dns=False), (False, ""))

    def test_every_published_prefix_parses(self):
        for label, items in crawler_ranges.RANGES.items():
            for item in items:
                import ipaddress

                ipaddress.ip_network(item, strict=False)  # raises when broken


class DnsTests(unittest.TestCase):
    """Reverse DNS is only trusted with forward confirmation."""

    def setUp(self):
        crawlers._dns_cache.clear()
        self.addCleanup(crawlers._dns_cache.clear)

    def _name_is(self, name):
        patcher = unittest.mock.patch.object(crawlers, "_rdns", return_value=name)
        patcher.start()
        self.addCleanup(patcher.stop)
        crawlers._dns_cache.clear()

    def test_forward_confirmation_is_required(self):
        # two addresses, because the answer for one address is cached (and the cache
        # must not hide the difference between "confirmed" and "not confirmed")
        self._name_is("crawl-1-2-3-4.googlebot.com")
        with unittest.mock.patch.object(crawlers, "_forward_matches", return_value=False):
            self.assertIsNone(crawlers.rdns_crawler(ipaddress.ip_address("1.2.3.4")))
        with unittest.mock.patch.object(crawlers, "_forward_matches", return_value=True):
            found = crawlers.rdns_crawler(ipaddress.ip_address("5.6.7.8"))
        self.assertIn("Googlebot", found or "")

    def test_known_suffixes(self):
        address = ipaddress.ip_address("1.2.3.4")
        for name, expected in (
            ("msnbot-1-2-3-4.search.msn.com", "Bingbot"),
            ("crawl-1-2-3-4.googlebot.com", "Googlebot"),
            ("spider.yandex.com", "YandexBot"),
            ("crawl.applebot.apple.com", "Applebot"),
        ):
            self._name_is(name)
            found = crawlers.rdns_crawler(address, forward_check=False)
            self.assertIn(expected, found or "", name)

    def test_lookalike_names_are_rejected(self):
        address = ipaddress.ip_address("1.2.3.4")
        for name in (
            "evil-googlebot.com.example.org",
            "notgooglebot.com",
            "google.com.evil.net",
            "",
        ):
            self._name_is(name)
            self.assertIsNone(crawlers.rdns_crawler(address, forward_check=False), name)


class ConfigTests(TempDirTestCase):
    def test_crawler_rail_is_on_by_default(self):
        self.assertTrue(self.cfg.never_report_crawlers)
        self.assertTrue(self.cfg.crawler_rdns)

    def test_keys_are_read(self):
        path = os.path.join(self.tmp, "reporter.conf")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "[abuseipdb]\napi_key = x\n[report]\nnever_report_crawlers = no\n"
                "crawler_rdns = no\ncrawler_rdns_timeout = 0.5\n"
            )
        cfg = config_module.load_config(path, quiet=True)
        self.assertFalse(cfg.never_report_crawlers)
        self.assertFalse(cfg.crawler_rdns)
        self.assertAlmostEqual(cfg.crawler_rdns_timeout, 0.5)


class ReporterRailTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.cfg.coordination_mode = "none"

    def _queue(self, ip, jail="sshd"):
        conn = db.connect(self.cfg.db_path)
        try:
            db.enqueue(conn, ip, jail)
            conn.commit()
        finally:
            conn.close()

    def test_crawler_is_skipped_and_counted(self):
        self._queue("66.249.66.5")
        calls = []

        class FakeApi:
            def report(self, *args, **kwargs):  # pragma: no cover - must not run
                calls.append(args)
                return 200, "{}"

        result = reporter.run_once(self.cfg, dry_run=True)
        self.assertEqual(calls, [])
        self.assertEqual(result.crawlers_skipped, 1)
        self.assertEqual(result.skipped, 1)

    def test_rail_can_be_turned_off(self):
        self.cfg.never_report_crawlers = False
        self._queue("66.249.66.5")
        # with the rail off the address reaches the reporting path; a dry run prints
        # the payload instead of calling the API
        result = reporter.run_once(self.cfg, dry_run=True)
        self.assertEqual(result.crawlers_skipped, 0)


if __name__ == "__main__":
    unittest.main()
