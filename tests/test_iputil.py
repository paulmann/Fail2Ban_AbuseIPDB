"""IP helper tests."""
import unittest

import tests  # noqa: F401
from abuseipdb_reporter.config import parse_ranges
from abuseipdb_reporter.iputil import is_ignored, parse_ip


class IpUtilTests(unittest.TestCase):
    def test_parse_ip(self):
        self.assertIsNotNone(parse_ip("8.8.8.8"))
        self.assertIsNotNone(parse_ip("2001:4860:4860::8888"))
        self.assertIsNone(parse_ip("not-an-ip"))
        self.assertIsNone(parse_ip(""))

    def test_is_ignored(self):
        networks = parse_ranges("127.0.0.0/8, 10.0.0.0/8, 2001:db8::/32")
        self.assertTrue(is_ignored(parse_ip("10.1.2.3"), networks))
        self.assertTrue(is_ignored(parse_ip("127.0.0.1"), networks))
        self.assertTrue(is_ignored(parse_ip("2001:db8::1"), networks))
        self.assertFalse(is_ignored(parse_ip("8.8.8.8"), networks))


if __name__ == "__main__":
    unittest.main()