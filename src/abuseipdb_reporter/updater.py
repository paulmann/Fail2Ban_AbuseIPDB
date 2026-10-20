"""Self-update support.

The installed version is compared with a small JSON manifest published in the
repository (``updater.json``).  ``abuseipdb-upgrade --check`` only reads it;
``abuseipdb-upgrade --upgrade`` downloads the release tarball, verifies its
SHA-256, extracts it safely and runs the project's own installer.

The API key file is never part of the tarball and the installer never rewrites
it on upgrade - the key therefore survives every self-update.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from typing import Callable, Dict, Optional, Tuple

from . import __version__
from .config import DEFAULT_UPDATE_MANIFEST_URL, load_config

USER_AGENT = "fail2ban-abuseipdb-updater/1.1 (+https://github.com/paulmann/Fail2Ban_AbuseIPDB)"
DEFAULT_KEY_FILE = "/etc/abuseipdb/.abuseipdb.key"
EXIT_UPDATE_AVAILABLE = 10


class UpdateError(RuntimeError):
    """Any updater failure that should be reported to the operator."""


def parse_version(value: str) -> Tuple[int, ...]:
    text = str(value or "").strip().lower()
    if text.startswith("v"):
        text = text[1:]
    parts = []
    for chunk in text.split("."):
        number = ""
        for character in chunk:
            if character.isdigit():
                number += character
            else:
                break
        if number == "":
            raise ValueError("invalid version: %r" % value)
        parts.append(int(number))
    if not parts:
        raise ValueError("invalid version: %r" % value)
    return tuple(parts)


def is_newer(remote: str, local: str) -> bool:
    """True when *remote* is a strictly newer version than *local*."""
    remote_parts = list(parse_version(remote))
    local_parts = list(parse_version(local))
    while len(remote_parts) < len(local_parts):
        remote_parts.append(0)
    while len(local_parts) < len(remote_parts):
        local_parts.append(0)
    return tuple(remote_parts) > tuple(local_parts)


def _urlopen(url: str, timeout: int):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(request, timeout=timeout)


def fetch_manifest(url: str, timeout: int = 20, opener: Callable = _urlopen) -> Dict:
    try:
        with opener(url, timeout) as response:
            payload = response.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise UpdateError("cannot fetch update manifest %s: %r" % (url, error))
    try:
        manifest = json.loads(payload)
    except ValueError as error:
        raise UpdateError("invalid update manifest JSON: %r" % (error,))
    if not isinstance(manifest, dict) or not manifest.get("version"):
        raise UpdateError("update manifest has no 'version' field")
    return manifest


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, destination: str, timeout: int = 120, opener: Callable = _urlopen) -> str:
    try:
        with opener(url, timeout) as response, open(destination, "wb") as handle:
            shutil.copyfileobj(response, handle)
    except (urllib.error.URLError, OSError) as error:
        raise UpdateError("cannot download %s: %r" % (url, error))
    return destination


def check(
    manifest_url: Optional[str] = None,
    current: Optional[str] = None,
    fetch: Callable = fetch_manifest,
    config_path: Optional[str] = None,
) -> Dict:
    """Return a dict with current/latest version and update availability."""
    if manifest_url is None:
        try:
            cfg = load_config(config_path)
            manifest_url = cfg.update_manifest_url or DEFAULT_UPDATE_MANIFEST_URL
        except Exception:  # noqa: BLE001 - config problems must not block a check
            manifest_url = DEFAULT_UPDATE_MANIFEST_URL
    manifest = fetch(manifest_url)
    if not isinstance(manifest, dict) or not manifest.get("version"):
        raise UpdateError("update manifest has no 'version' field")
    latest = str(manifest["version"])
    current_version = current or __version__
    try:
        newer = is_newer(latest, current_version)
    except ValueError as error:
        raise UpdateError("cannot compare versions: %r" % (error,))
    result = {
        "current": current_version,
        "latest": latest,
        "update_available": newer,
        "manifest_url": manifest_url,
        "release_notes": manifest.get("release_notes") or manifest.get("changelog") or "",
        "tarball": manifest.get("tarball") or "",
        "sha256": (manifest.get("sha256") or "").lower(),
        "notes": manifest.get("notes") or "",
        "requires_python": manifest.get("requires_python") or "",
    }
    return result


def _safe_extract(archive: str, destination: str) -> None:
    """Extract a tar.gz while refusing path traversal, links and devices."""
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        if not members:
            raise UpdateError("release archive is empty")
        for member in members:
            name = member.name
            if name.startswith(("/", "\\")) or ".." in name.replace("\\", "/").split("/"):
                raise UpdateError("unsafe path in archive: %r" % name)
            if member.issym() or member.islnk() or member.isdev():
                raise UpdateError("unsupported entry in archive: %r" % name)
        try:
            tar.extractall(destination, filter="data")
        except TypeError:  # Python < 3.12 has no extraction filters
            tar.extractall(destination)


def _find_installer(extracted: str) -> str:
    candidate = os.path.join(extracted, "install.sh")
    if os.path.isfile(candidate):
        return candidate
    entries = [
        os.path.join(extracted, name)
        for name in os.listdir(extracted)
        if os.path.isdir(os.path.join(extracted, name))
    ]
    if len(entries) == 1:
        candidate = os.path.join(entries[0], "install.sh")
        if os.path.isfile(candidate):
            return candidate
    raise UpdateError("install.sh not found in the release archive")


def _key_file_guard(path: str = DEFAULT_KEY_FILE):
    """Snapshot the key file so that a broken update cannot destroy it."""
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read()
    mode = os.stat(path).st_mode & 0o777
    return (content, mode)


def _restore_key_file(path: str, snapshot) -> None:
    if snapshot is None:
        return
    content, mode = snapshot
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, mode or 0o600)
    print("Key file restored after an interrupted update: %s" % path, file=sys.stderr)


def upgrade(
    manifest: Dict,
    installer_args: Optional[list] = None,
    dry_run: bool = False,
    timeout: int = 120,
    downloader: Callable = download,
    run_installer: Callable = subprocess.run,
    workdir: Optional[str] = None,
) -> int:
    """Download and apply an update described by *manifest*.

    Returns 0 on success, raises :class:`UpdateError` on any problem.
    """
    tarball_url = manifest.get("tarball") or ""
    expected_sha = (manifest.get("sha256") or "").lower()
    if not tarball_url:
        raise UpdateError("update manifest has no 'tarball' URL")
    if not expected_sha:
        raise UpdateError("update manifest has no 'sha256' checksum; refusing to update")

    directory = workdir or tempfile.mkdtemp(prefix="abuseipdb-update-")
    os.makedirs(directory, exist_ok=True)
    archive = os.path.join(directory, "release.tar.gz")
    try:
        print("Downloading %s" % tarball_url)
        if dry_run:
            print("dry-run: would download and verify %s" % tarball_url)
            return 0
        downloader(tarball_url, archive, timeout)
        actual_sha = sha256_file(archive)
        if actual_sha != expected_sha:
            raise UpdateError(
                "checksum mismatch: expected %s, got %s" % (expected_sha, actual_sha)
            )
        extracted = os.path.join(directory, "extracted")
        os.makedirs(extracted, exist_ok=True)
        _safe_extract(archive, extracted)
        installer = _find_installer(extracted)

        key_snapshot = _key_file_guard(DEFAULT_KEY_FILE)
        args = ["bash", installer] + list(installer_args or [])
        print("Running installer: %s" % " ".join(args))
        result = run_installer(args)
        if result.returncode != 0:
            _restore_key_file(DEFAULT_KEY_FILE, key_snapshot)
            raise UpdateError("installer failed with exit code %d" % result.returncode)
        if key_snapshot is not None and not os.path.isfile(DEFAULT_KEY_FILE):
            _restore_key_file(DEFAULT_KEY_FILE, key_snapshot)
        return 0
    finally:
        if workdir is None:
            shutil.rmtree(directory, ignore_errors=True)


def main_upgrade(argv: Optional[list] = None) -> int:
    """CLI entry point for ``abuseipdb-upgrade``."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="abuseipdb-upgrade",
        description="Check for and install Fail2Ban_AbuseIPDB updates from GitHub.",
    )
    parser.add_argument("--check", action="store_true", help="only check for updates")
    parser.add_argument("--upgrade", action="store_true", help="download and install an update")
    parser.add_argument("--force", action="store_true", help="install even if the version is not newer")
    parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    parser.add_argument("--dry-run", action="store_true", help="print the plan, change nothing")
    parser.add_argument("--manifest-url", default=None, help="override the updater.json URL")
    parser.add_argument("--config", default=None, help="reporter.conf path")
    parser.add_argument("--quiet", action="store_true", help="only exit code and errors")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = parser.parse_args(argv)

    try:
        info = check(args.manifest_url, config_path=args.config)
    except UpdateError as error:
        print("error: %s" % error, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(info, ensure_ascii=False, sort_keys=True))
    elif not args.quiet:
        print("Installed version: %s" % info["current"])
        print("Latest version:    %s" % info["latest"])
        if info["update_available"]:
            print("Update available:  %s" % info["release_notes"])
            if info["notes"]:
                print("Notes:             %s" % info["notes"])
        else:
            print("You are running the latest version.")

    if not args.upgrade:
        return EXIT_UPDATE_AVAILABLE if info["update_available"] else 0

    if not info["update_available"] and not args.force:
        return 0
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        print("error: --upgrade must run as root", file=sys.stderr)
        return 1
    if not args.yes and not args.dry_run:
        if not sys.stdin.isatty():
            print("error: use --yes for a non-interactive upgrade", file=sys.stderr)
            return 1
        answer = input("Upgrade to %s now? [y/N] " % info["latest"])
        if answer.strip().lower() not in ("y", "yes"):
            print("Cancelled.")
            return 1

    manifest = {
        "version": info["latest"],
        "tarball": info["tarball"],
        "sha256": info["sha256"],
    }
    try:
        upgrade(manifest, installer_args=["--yes"] if args.yes else [], dry_run=args.dry_run)
    except UpdateError as error:
        print("error: %s" % error, file=sys.stderr)
        return 1
    if not args.dry_run:
        print("Updated to %s. API key file and configuration were preserved." % info["latest"])
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main_upgrade())