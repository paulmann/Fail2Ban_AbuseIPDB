"""Tiny logger: one file plus stdout (systemd journal), quiet mode for dry-run."""
from __future__ import annotations

import time
from typing import Optional

from .config import Config


def log(cfg: Optional[Config], message: str) -> None:
    line = time.strftime("%Y-%m-%dT%H:%M:%S%z") + " " + str(message) + "\n"
    path = cfg.log_path if cfg is not None else "/var/log/abuseipdb-reporter.log"
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass
    if cfg is None or not cfg.quiet:
        try:
            print(line, end="", flush=True)
        except OSError:
            pass