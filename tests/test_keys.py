"""API key resolution, storage and migration tests."""
import os
import stat
import tempfile
import unittest
from unittest import mock

import tests  # noqa: F401
from abuseipdb_reporter import keys
from abuseipdb_reporter.config import Config, load_config


class KeyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="f2b-keys-")
        self.tmp = self._tmp.name
        self.key_path = os.path.join(self.tmp, "keys", ".abuseipdb.key")
        self.cfg = Config(
            path=os.path.join(self.tmp, "reporter.conf"),
            api_key="",
            api_key_file=self.key_path,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_normalize_mask_validate(self):
        self.assertEqual(keys.normalize_key(" abc\n def "), "abcdef")
        self.assertTrue(keys.mask_key("a" * 80).endswith("aaaa"))
        self.assertTrue(keys.validate_key("short"))
        self.assertFalse(keys.validate_key("a" * 80))

    def test_save_and_read_key_file(self):
        keys.save_key_file(self.key_path, "b" * 80)
        self.assertEqual(keys.read_key_file(self.key_path), "b" * 80)
        if os.name == "posix":  # Windows has no POSIX permission bits
            mode = os.stat(self.key_path).st_mode & 0o777
            self.assertEqual(mode, 0o600)
            dir_mode = os.stat(os.path.dirname(self.key_path)).st_mode & 0o777
            self.assertEqual(dir_mode, 0o700)

    def test_save_refuses_empty_key(self):
        with self.assertRaises(ValueError):
            keys.save_key_file(self.key_path, "   ")

    def test_resolution_order(self):
        # 1. command line wins over everything
        keys.save_key_file(self.key_path, "f" * 80)
        key, source = keys.resolve_api_key(
            self.cfg, cli_key="c" * 80, env={"ABUSEIPDB_API_KEY": "e" * 80}
        )
        self.assertEqual(key, "c" * 80)
        self.assertIn("command line", source)
        # 2. environment
        key, source = keys.resolve_api_key(self.cfg, env={"ABUSEIPDB_API_KEY": "e" * 80})
        self.assertEqual(key, "e" * 80)
        self.assertIn("environment", source)
        # 3. key file
        key, source = keys.resolve_api_key(self.cfg, env={})
        self.assertEqual(key, "f" * 80)
        self.assertIn("key file", source)

    def test_legacy_config_key_is_last_resort(self):
        cfg = Config(path=self.cfg.path, api_key="d" * 80, api_key_file=self.key_path)
        key, source = keys.resolve_api_key(cfg, env={})
        self.assertEqual(key, "d" * 80)
        self.assertIn("legacy", source)

    def test_missing_key_raises_without_prompt(self):
        with self.assertRaises(keys.ApiKeyMissing):
            keys.resolve_api_key(self.cfg, env={}, prompt=False, interactive=False)
        with self.assertRaises(keys.ApiKeyMissing):
            keys.resolve_api_key(self.cfg, env={}, prompt=True, interactive=False)

    def test_prompt_saves_key(self):
        with mock.patch("abuseipdb_reporter.keys.getpass.getpass", return_value="a" * 80):
            with mock.patch("sys.stderr"):
                key = keys.prompt_and_save(self.key_path)
        self.assertEqual(key, "a" * 80)
        self.assertEqual(keys.read_key_file(self.key_path), "a" * 80)
        # a second resolution finds it in the file
        resolved, source = keys.resolve_api_key(self.cfg, env={})
        self.assertEqual(resolved, "a" * 80)
        self.assertIn("key file", source)

    def test_key_file_env_override(self):
        other = os.path.join(self.tmp, "other.key")
        keys.save_key_file(other, "g" * 80)
        key, _ = keys.resolve_api_key(
            self.cfg, env={"ABUSEIPDB_KEY_FILE": other}
        )
        self.assertEqual(key, "g" * 80)

    def test_migrate_legacy_key(self):
        config_path = os.path.join(self.tmp, "reporter.conf")
        with open(config_path, "w", encoding="utf-8") as handle:
            handle.write("[abuseipdb]\napi_key = %s\napi_key_file = %s\n" % ("h" * 80, self.key_path))
        cfg = load_config(config_path)
        self.assertTrue(keys.migrate_legacy_key(cfg, config_path))
        self.assertEqual(keys.read_key_file(self.key_path), "h" * 80)
        with open(config_path, "r", encoding="utf-8") as handle:
            content = handle.read()
        self.assertIn("api_key =\n", content)
        self.assertNotIn("h" * 80, content)
        self.assertFalse(keys.migrate_legacy_key(load_config(config_path), config_path))

    def test_resolve_does_not_touch_key_file(self):
        keys.save_key_file(self.key_path, "i" * 80)
        before = os.stat(self.key_path).st_mtime_ns
        keys.resolve_api_key(self.cfg, env={})
        self.assertEqual(os.stat(self.key_path).st_mtime_ns, before)


if __name__ == "__main__":
    unittest.main()