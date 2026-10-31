## v1.2.0 — observability, adaptive rate limiting, more evidence

This release makes the worker easier to operate (a status file and metrics
instead of log parsing), friendlier to the API (it honours `Retry-After` and
backs off exponentially), and cheaper to extend (a classifier registry with
support for the most common mail and FTP jails).

### Added

* **Status file and metrics.** Every run rewrites
  `/var/lib/abuseipdb/status.json` atomically; `abuseipdb-report --status`
  prints it. With `prometheus_textfile` set, the same numbers are exported for
  the `node_exporter` textfile collector. A dry run never overwrites the status
  of the last real run, and an unwritable path is logged instead of failing the
  run.
* **`Retry-After` support.** HTTP 429 responses are parsed (delta-seconds and
  HTTP-date). The pause is capped by `retry_after_cap` (60 s by default).
* **Adaptive backoff.** `request_delay` (1.0 s by default) between calls,
  doubled after every consecutive transient failure up to the same cap and
  reset by one success.
* **UTC-aligned daily budget.** `daily_budget_timezone = utc` (default) counts
  the budget from 00:00 UTC, which is when AbuseIPDB resets the account quota;
  `local` keeps the previous midnight behaviour.
* **Classifier registry.** `evidence.CLASSIFIERS` maps jail-name prefixes to
  classifiers: SSH, FTP (`proftpd`, `vsftpd`, `pure-ftpd`), SMTP (`exim`,
  `postfix`, `sendmail`, `smtpd`), mailbox (`dovecot`, `courier`, `cyrus`), web
  (`nginx`, `apache`, `haproxy`, `lighttpd`, `openresty`, `traefik`) and a
  generic fallback that still extracts request lines and SQL-injection flags.
* **Percent-encoded SQL injection** (`%20UNION%20SELECT`) is detected: the
  pattern is matched against the URL-decoded line as well.
* **Default categories for more jails**: `vsftpd`, `pure-ftpd`, `postfix`,
  `postfix-sasl`, `dovecot`, `nginx-badbots`, `nginx-botsearch`, `nginx-noscript`,
  `apache-auth`, `apache-badbots`.
* **Queue lock retry.** The fail2ban action retries a locked queue database
  three times with a short exponential backoff (0.2 s, 0.4 s) instead of losing
  the event.
* **Release workflow** (`.github/workflows/release.yml`): on a `v*` tag it
  verifies version consistency, runs the unit tests, builds the release
  tarball, the wheel and the sdist, and creates the GitHub release.
* **Hardened systemd unit**: `RestrictAddressFamilies`, `SystemCallFilter`,
  `MemoryDenyWriteExecute`, empty capability sets and friends, plus `/run` in
  `ReadWritePaths` for the instance lock.

### Changed

* `api.request()` returns `(status, body, retry_after)`. An injected HTTP
  client that still returns a two-tuple keeps working - it is treated as "no
  `Retry-After`".
* `__version__` lives in one place (`abuseipdb_reporter.__version__`); `cli.py`
  re-exports it.
* Tests: **123** (was 88), including `Retry-After` parsing, backoff timing,
  status/metrics files, the classifier registry and queue lock retry.

### Upgrade

```bash
sudo abuseipdb-upgrade --check     # exit 10 = update available
sudo abuseipdb-upgrade --upgrade --yes
```

The key file, configuration, queue and jail list are preserved; the new
configuration keys have safe defaults, so no manual edit is required. To enable
metrics add `prometheus_textfile` to the `[logging]` section.
