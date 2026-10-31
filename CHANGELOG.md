# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.2.0] - 2026-10-31

### Added

* **Status file and metrics**: every run rewrites
  `/var/lib/abuseipdb/status.json` atomically (counters, budget, stop reason,
  version), `abuseipdb-report --status` prints it, and `prometheus_textfile`
  exports the same numbers for the node_exporter textfile collector. A dry run
  never overwrites the status of the last real run; an unwritable path is logged
  and does not fail the run.
* **`Retry-After` support**: a 429 response is parsed (delta-seconds and
  HTTP-date) and the pause before the next call follows it, capped by
  `retry_after_cap`.
* **Adaptive backoff**: `request_delay` (1.0 s) between calls, doubled for each
  consecutive transient failure up to the cap and reset by one success.
* **UTC-aligned daily budget** (`daily_budget_timezone`, default `utc`): the
  budget day starts when AbuseIPDB resets its quota; `local` keeps the old
  behaviour.
* **Classifier registry** in `evidence.py` with support for `vsftpd`,
  `pure-ftpd`, `postfix`, `postfix-sasl`, `dovecot`, `courier`, `cyrus`,
  `apache-*`, `haproxy`, `lighttpd`, `openresty`, `traefik` and a generic
  fallback; new jails are added by appending one entry.
* **Percent-encoded SQL injection** (`%20UNION%20SELECT`) is now detected: the
  SQLi patterns also run against the URL-decoded line.
* **Default categories** for the new jails (`vsftpd`, `postfix`, `dovecot`,
  `nginx-badbots`, `nginx-botsearch`, `nginx-noscript`, `apache-auth`,
  `apache-badbots`, ...).
* **Queue lock retry**: a locked queue database is retried three times with a
  short exponential backoff instead of dropping the ban event.
* **Release workflow**: tag-driven build of the installer tarball, wheel and
  sdist, with a version-consistency gate and a checksum in the job summary.
* **Hardened systemd unit**: address-family and syscall restrictions, no
  capabilities, `MemoryDenyWriteExecute`, `/run` added to `ReadWritePaths`.

### Changed

* `api.request()` returns `(status, body, retry_after)`; an injected client
  that returns a two-tuple is still accepted and treated as "no Retry-After".
* The package version lives only in `abuseipdb_reporter/__init__.py`;
  `abuseipdb_reporter.cli` re-exports it.
* Tests: **123** (was 88).

## [1.1.1] - 2026-10-20

### Fixed

* **Installer config placement**: when upgrading a configuration that had no
  `api_key_file` line, the installer appended it at the end of the file (inside
  whatever section happened to be last, e.g. `[category_map]`) instead of
  `[abuseipdb]`. It is now inserted at the end of the `[abuseipdb]` section, and
  an existing line is replaced in place. The reporter itself always used the
  documented default, but custom `--key-file` paths were not read from the
  config in that edge case.

## [1.1.0] - 2026-10-20

### Added

* **API key file** `/etc/abuseipdb/.abuseipdb.key` (mode 600): the key is no
  longer stored in `reporter.conf`, so code updates and configuration
  regeneration can never overwrite it; existing key files are kept untouched by
  re-installs and self-updates.
* **First-run key wizard**: when no key is found in `--api-key`, the environment
  or the key file, an interactive run asks for it once and saves it; the
  installer does the same on a terminal. Non-interactive runs fail with a clear
  message instead of hanging.
* **Key migration**: a legacy `api_key` in `reporter.conf` is migrated into the
  key file by the installer or `abuseipdb-report --migrate-key`.
* `abuseipdb-report --setup`, `--migrate-key`, `--key-status` and `--no-prompt`.
* **Self-update**: `abuseipdb-upgrade --check` compares the installed version
  with `updater.json` published on GitHub; `--upgrade` downloads the release
  tarball, verifies its SHA-256, extracts it safely, snapshots/restores the key
  file and runs the project installer. `--json`, `--quiet`, `--force`,
  `--dry-run` are supported; exit code 10 means "update available".
* Optional weekly update check (`install.sh --with-update-check`, systemd timer
  or cron); it only reports availability and never installs automatically.
* Installer upgrades now preserve the existing jail list when `--jails` is not
  passed, and never rewrite an existing key file.
* Documentation: [docs/UPDATE.md](docs/UPDATE.md), key management sections in
  README/INSTALL/CONFIGURATION/ARCHITECTURE/TROUBLESHOOTING/SECURITY.

### Changed

* `reporter.conf` no longer contains a key; `api_key_file` points to the key file.
* The installer installs `/usr/local/sbin/abuseipdb-upgrade`.
* Tests: 88 unit/integration tests (was 57), including key resolution, prompt,
  migration and updater safety (checksum, traversal, key preservation).

## [1.0.0] - 2026-10-20

### Added

* Asynchronous fail2ban → AbuseIPDB reporter:
  * fail2ban action `abuseipdb-async` with `norestored = 1`;
  * local SQLite queue (`events`, `reports`, WAL) with deduplication of repeated
    bans within 5 minutes;
  * worker `abuseipdb-report` with `--stats`, `--dry-run`, `--check-key`;
  * systemd timer (16 minutes, `Persistent=true`) and cron alternative;
  * rate limiting: 20 minutes per IP, 900 reports per day, 25 per run;
  * retry policy for transient errors, invalid-report marking, rate-limit deferral;
  * evidence extraction from fail2ban's `bips.data.matches` - attack type, time,
    ban duration, failure counters, generic patterns, attacker request URLs;
  * per-jail AbuseIPDB category mapping and automatic SQL-injection category;
  * PII-free comments (no attempted usernames, no mail content);
  * configurable attribution footer in every report
    (`Reported via Fail2Ban_AbuseIPDB Monitor: ...`), appended last and never
    truncated;
  * IPv4 and IPv6 support, ignore ranges for private/reserved/CDN networks.
* Production installer `install.sh`:
  * backups of every replaced file, install manifest, idempotent upgrade;
  * `fail2ban-client -t` validation before restart, rollback on failure;
  * generated jail snippet for the selected jails (`--jails`, `--all-jails`);
  * systemd timer or cron (`--cron`), logrotate configuration;
  * staging mode (`--root DIR`) and `--dry-run`;
  * uninstall with restore of previous files, optional `--purge`.
* Documentation: English README, installation, configuration, architecture and
  troubleshooting guides.
* Tests: 57 unit tests (stdlib `unittest`, no network/root) and an end-to-end
  integration test against a bundled mock AbuseIPDB API.
* CI: unit tests on Python 3.9-3.13, shellcheck, staged install/uninstall.

[1.0.0]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.0.0
[1.2.0]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.2.0