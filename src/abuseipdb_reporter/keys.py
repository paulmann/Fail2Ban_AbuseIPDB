"""API key management.

The key is kept in a dedicated file (default ``/etc/abuseipdb/.abuseipdb.key``)
so that code updates and configuration regeneration can never overwrite it.

Resolution order:

1. ``--api-key`` command line option (one-off);
2. ``ABUSEIPDB_API_KEY`` / ``ABUSEIPDB_KEY`` environment variables;
3. the key file (``api_key_file`` in the config, ``ABUSEIPDB_KEY_FILE`` env,
   default ``/etc/abuseipdb/.abuseipdb.key``);
4. legacy ``api_key`` value in the configuration file (deprecated);
5. interactive prompt on the first run (saved into the key file).
"""
from __future__ import annotations

import getpass
import os
import re
import stat
import sys
import tempfile
from typing import Dict, Optional, Tuple

DEFAULT_KEY_FILE = "/etc/abuseipdb/.abuseipdb.key"
ENV_KEYS = ("ABUSEIPDB_API_KEY", "ABUSEIPDB_KEY")
ENV_KEY_FILE = "ABUSEIPDB_KEY_FILE"
_HEX_KEY_RE = re.compile(r"^[0-9a-fA-F]+$")


class ApiKeyMissing(RuntimeError):
    """Raised when no API key can be found and no prompt is possible."""


def normalize_key(value: Optional[str]) -> str:
    """Strip whitespace/newlines that easily slip in when a key is pasted."""
    return "".join(str(value or "").split())


def validate_key(key: str) -> Tuple[list]:
    """Return a list of human-readable warnings (never raises)."""
    warnings = []
    if len(key) != 80:
        warnings.append("API key length is %d, expected 80 characters" % len(key))
    if not _HEX_KEY_RE.match(key):
        warnings.append("API key contains non-hexadecimal characters")
    return warnings


def mask_key(key: str) -> str:
    if not key:
        return "(empty)"
    if len(key) <= 12:
        return key[:2] + "***"
    return "%s...%s" % (key[:6], key[-4:])


def read_key_file(path: str) -> Optional[str]:
    """Return the first non-empty line of *path*, or ``None``."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                value = normalize_key(line)
                if value:
                    return value
    except OSError:
        return None
    return None


def save_key_file(path: str, key: str) -> None:
    """Atomically write *key* to *path* with mode 600 (parent 700)."""
    key = normalize_key(key)
    if not key:
        raise ValueError("refusing to save an empty API key")
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=parent, prefix=".abuseipdb-key-", delete=False
    )
    try:
        handle.write(key + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        os.chmod(handle.name, stat.S_IRUSR | stat.S_IWUSR)  # 600
        os.replace(handle.name, path)
    finally:
        if not handle.closed:
            handle.close()
        if os.path.exists(handle.name):
            try:
                os.unlink(handle.name)
            except OSError:
                pass


def prompt_and_save(path: str, key_name: str = "AbuseIPDB API key") -> str:
    """Ask the user for the key, validate it lightly and save it."""
    print(
        "No %s found. Get one at https://www.abuseipdb.com/account/api\n"
        "The key is stored in %s (mode 600) and is preserved across updates." % (key_name, path),
        file=sys.stderr,
    )
    try:
        value = getpass.getpass("Enter your %s: " % key_name)
    except (EOFError, KeyboardInterrupt):
        raise ApiKeyMissing("API key input cancelled")
    value = normalize_key(value)
    if not value:
        raise ApiKeyMissing("empty API key")
    for warning in validate_key(value):
        print("Warning: %s (saved anyway)" % warning, file=sys.stderr)
    save_key_file(path, value)
    print("API key saved to %s" % path, file=sys.stderr)
    return value


def key_file_path(cfg, env: Optional[Dict[str, str]] = None) -> str:
    env = os.environ if env is None else env
    return env.get(ENV_KEY_FILE) or getattr(cfg, "api_key_file", "") or DEFAULT_KEY_FILE


def resolve_api_key(
    cfg,
    cli_key: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    prompt: bool = False,
    interactive: Optional[bool] = None,
) -> Tuple[str, str]:
    """Resolve the API key and its source.

    Returns ``(key, source)``; raises :class:`ApiKeyMissing` when no key is
    available (unless *prompt* is enabled and stdin is a terminal).
    """
    env = os.environ if env is None else env
    cli_key = normalize_key(cli_key)
    if cli_key:
        return cli_key, "command line"
    for name in ENV_KEYS:
        value = normalize_key(env.get(name))
        if value:
            return value, "environment %s" % name
    path = key_file_path(cfg, env)
    value = read_key_file(path)
    if value:
        return value, "key file %s" % path
    legacy = normalize_key(getattr(cfg, "api_key", ""))
    if legacy:
        return legacy, "legacy api_key in %s (deprecated; run --migrate-key)" % getattr(
            cfg, "path", "config"
        )
    if interactive is None:
        interactive = sys.stdin.isatty()
    if prompt and interactive:
        return prompt_and_save(path), "key file %s (just saved)" % path
    raise ApiKeyMissing(
        "No AbuseIPDB API key found. Provide --api-key, set ABUSEIPDB_API_KEY, "
        "write %s, or run interactively (or use --setup)." % path
    )


def migrate_legacy_key(cfg, config_path: Optional[str] = None) -> bool:
    """Move a legacy ``api_key`` from the config into the key file.

    Returns True when something was migrated.
    """
    legacy = normalize_key(getattr(cfg, "api_key", ""))
    if not legacy:
        return False
    path = key_file_path(cfg)
    existing = read_key_file(path)
    if existing and existing != legacy:
        raise RuntimeError(
            "key file %s already contains a different key; resolve manually" % path
        )
    save_key_file(path, legacy)
    # blank the legacy value in the config so the secret lives in one place
    target = config_path or getattr(cfg, "path", None)
    if target and os.path.exists(target):
        try:
            with open(target, "r", encoding="utf-8") as handle:
                lines = handle.readlines()
            changed = False
            for index, line in enumerate(lines):
                if re.match(r"^\s*api_key\s*=", line):
                    lines[index] = "api_key =\n"
                    changed = True
            if changed:
                tmp = target + ".tmp"
                with open(tmp, "w", encoding="utf-8") as handle:
                    handle.writelines(lines)
                os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
                os.replace(tmp, target)
        except OSError:
            pass
    return True