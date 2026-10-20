"""Self-update tests (no network: manifest/downloader/installer are injected)."""
import io
import json
import os
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import tests  # noqa: F401
from abuseipdb_reporter import updater


def make_tar(path, files):
    with tarfile.open(path, "w:gz") as tar:
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def fake_fetch(version="1.1.0", **extra):
    manifest = {
        "version": version,
        "tarball": "https://example.invalid/release.tar.gz",
        "sha256": "",
        "release_notes": "https://example.invalid/release",
        "notes": "test release",
    }
    manifest.update(extra)
    return lambda url: manifest


class VersionTests(unittest.TestCase):
    def test_parse_and_compare(self):
        self.assertEqual(updater.parse_version("v1.2.3"), (1, 2, 3))
        self.assertEqual(updater.parse_version("1.0"), (1, 0))
        self.assertTrue(updater.is_newer("1.1.0", "1.0.0"))
        self.assertTrue(updater.is_newer("1.0.1", "1.0"))
        self.assertFalse(updater.is_newer("1.0.0", "1.0.0"))
        self.assertFalse(updater.is_newer("1.0.0", "1.1.0"))
        with self.assertRaises(ValueError):
            updater.parse_version("not-a-version")

    def test_check_reports_update(self):
        info = updater.check("http://example.invalid/updater.json", current="1.0.0",
                             fetch=fake_fetch("1.1.0"))
        self.assertTrue(info["update_available"])
        self.assertEqual(info["latest"], "1.1.0")
        self.assertIn("release", info["release_notes"])

    def test_check_up_to_date(self):
        info = updater.check("http://example.invalid/updater.json", current="1.1.0",
                             fetch=fake_fetch("1.1.0"))
        self.assertFalse(info["update_available"])

    def test_invalid_manifest(self):
        with self.assertRaises(updater.UpdateError):
            updater.check("http://example.invalid/updater.json",
                          current="1.0.0", fetch=lambda url: {"no_version": True})


class ArchiveTests(unittest.TestCase):
    def test_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "file")
            with open(path, "wb") as handle:
                handle.write(b"hello")
            self.assertEqual(
                updater.sha256_file(path),
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            )

    def test_safe_extract(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "ok.tar.gz")
            make_tar(archive, {"pkg/install.sh": "#!/bin/sh\n", "pkg/data.txt": "x"})
            dest = os.path.join(tmp, "out")
            os.makedirs(dest)
            updater._safe_extract(archive, dest)
            self.assertTrue(os.path.isfile(os.path.join(dest, "pkg", "install.sh")))

    def test_safe_extract_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "bad.tar.gz")
            make_tar(archive, {"../evil.sh": "x"})
            dest = os.path.join(tmp, "out")
            os.makedirs(dest)
            with self.assertRaises(updater.UpdateError):
                updater._safe_extract(archive, dest)
            self.assertFalse(os.path.exists(os.path.join(tmp, "evil.sh")))

    def test_find_installer(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "pkg"))
            open(os.path.join(tmp, "pkg", "install.sh"), "w").close()
            self.assertTrue(updater._find_installer(tmp).endswith("install.sh"))
            empty = os.path.join(tmp, "empty")
            os.makedirs(empty)
            with self.assertRaises(updater.UpdateError):
                updater._find_installer(empty)


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="f2b-update-")
        self.tmp = self._tmp.name
        self.key_path = os.path.join(self.tmp, "key")
        with open(self.key_path, "w", encoding="utf-8") as handle:
            handle.write("a" * 80 + "\n")
        os.chmod(self.key_path, 0o600)
        self.archive = os.path.join(self.tmp, "release.tar.gz")
        make_tar(
            self.archive,
            {"pkg/install.sh": "#!/bin/sh\nexit 0\n", "pkg/README.md": "# test"},
        )
        self.manifest = {
            "version": "1.1.0",
            "tarball": "https://example.invalid/release.tar.gz",
            "sha256": updater.sha256_file(self.archive),
        }

    def tearDown(self):
        self._tmp.cleanup()

    def _downloader(self):
        def download(url, destination, timeout=120):
            with open(self.archive, "rb") as src, open(destination, "wb") as dst:
                dst.write(src.read())
            return destination

        return download

    def test_successful_upgrade_preserves_key(self):
        calls = []

        def fake_installer(args):
            calls.append(args)
            return SimpleNamespace(returncode=0)

        with mock.patch.object(updater, "DEFAULT_KEY_FILE", self.key_path):
            rc = updater.upgrade(
                self.manifest,
                downloader=self._downloader(),
                run_installer=fake_installer,
                workdir=os.path.join(self.tmp, "work"),
            )
        self.assertEqual(rc, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "bash")
        self.assertTrue(calls[0][1].endswith("install.sh"))
        with open(self.key_path, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "a" * 80 + "\n")

    def test_checksum_mismatch_aborts(self):
        manifest = dict(self.manifest)
        manifest["sha256"] = "0" * 64
        with mock.patch.object(updater, "DEFAULT_KEY_FILE", self.key_path):
            with self.assertRaises(updater.UpdateError):
                updater.upgrade(
                    manifest,
                    downloader=self._downloader(),
                    run_installer=lambda args: SimpleNamespace(returncode=0),
                    workdir=os.path.join(self.tmp, "work"),
                )

    def test_failed_installer_restores_key(self):
        def bad_installer(args):
            os.unlink(self.key_path)
            return SimpleNamespace(returncode=1)

        with mock.patch.object(updater, "DEFAULT_KEY_FILE", self.key_path):
            with self.assertRaises(updater.UpdateError):
                updater.upgrade(
                    self.manifest,
                    downloader=self._downloader(),
                    run_installer=bad_installer,
                    workdir=os.path.join(self.tmp, "work"),
                )
        with open(self.key_path, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "a" * 80 + "\n")

    def test_dry_run_does_not_download(self):
        called = []
        updater.upgrade(
            self.manifest,
            downloader=lambda *a, **k: called.append(a),
            run_installer=lambda args: SimpleNamespace(returncode=0),
            dry_run=True,
            workdir=os.path.join(self.tmp, "work"),
        )
        self.assertEqual(called, [])

    def test_missing_checksum_refused(self):
        manifest = dict(self.manifest)
        manifest["sha256"] = ""
        with self.assertRaises(updater.UpdateError):
            updater.upgrade(
                manifest,
                downloader=self._downloader(),
                run_installer=lambda args: SimpleNamespace(returncode=0),
                workdir=os.path.join(self.tmp, "work"),
            )


class CliTests(unittest.TestCase):
    def test_check_exit_codes(self):
        with mock.patch.object(updater, "check", return_value={
            "current": "1.0.0", "latest": "1.1.0", "update_available": True,
            "manifest_url": "u", "release_notes": "notes", "tarball": "t", "sha256": "s",
            "notes": "", "requires_python": "",
        }):
            self.assertEqual(updater.main_upgrade(["--check"]), updater.EXIT_UPDATE_AVAILABLE)
        with mock.patch.object(updater, "check", return_value={
            "current": "1.1.0", "latest": "1.1.0", "update_available": False,
            "manifest_url": "u", "release_notes": "", "tarball": "", "sha256": "",
            "notes": "", "requires_python": "",
        }):
            self.assertEqual(updater.main_upgrade(["--check"]), 0)

    def test_check_error(self):
        with mock.patch.object(updater, "check", side_effect=updater.UpdateError("boom")):
            self.assertEqual(updater.main_upgrade(["--check"]), 1)

    def test_upgrade_requires_yes_when_not_tty(self):
        info = {
            "current": "1.0.0", "latest": "1.1.0", "update_available": True,
            "manifest_url": "u", "release_notes": "", "tarball": "t", "sha256": "s",
            "notes": "", "requires_python": "",
        }
        with mock.patch.object(updater, "check", return_value=info), \
                mock.patch.object(updater.sys.stdin, "isatty", return_value=False):
            self.assertEqual(updater.main_upgrade(["--upgrade"]), 1)


if __name__ == "__main__":
    unittest.main()