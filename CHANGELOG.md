# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

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
* Tests: 52 unit tests (stdlib `unittest`, no network/root) and an end-to-end
  integration test against a bundled mock AbuseIPDB API.
* CI: unit tests on Python 3.9-3.13, shellcheck, staged install/uninstall.

[1.0.0]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.0.0