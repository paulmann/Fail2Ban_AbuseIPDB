# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

* **A crawler rail: a good bot is never reported.** Before a report is built, the
  address is checked against the publishers' own machine-readable lists (Google 317
  ranges, GPTBot 18, OAI-SearchBot 39, ChatGPT-User 235 - generated into
  `crawler_ranges.py` with each list's `creationTime`) and, in addition, by reverse
  DNS with forward confirmation for Bing, Yandex, Apple, Amazon, Common Crawl,
  ByteDance and Perplexity. A match means no API call: the event is finished locally,
  the skip is counted, logged and exported. A ban can be lifted; an AbuseIPDB report
  cannot be deleted.
* New keys `[report] never_report_crawlers` (default `yes`), `crawler_rdns`
  (default `yes`), `crawler_rdns_timeout`; new CLI `--crawler-status` and
  `--crawler-check IP`; new metric `last_run_crawlers_skipped` and a Zabbix item and
  trigger for it ("a crawler was banned" - it means a jail rule is wrong).
* `tools/update_crawler_ranges.py` regenerates the range module and records the
  publisher's own `creationTime`, so the age of every list is visible;
  `tools/audit-good-bots.sh` is a read-only audit of a host: jails, crawler check for
  every banned address, ignoreip coverage, per-bot status matrix over the access logs
  and any nginx rule that can target a crawler.
* `docs/GOOD-BOTS.md` - the measured answer for the three production hosts.

### Measured on the estate (2026-11-01, 7 days)

5,646 crawler requests across the three hosts (5,404 + 228 + 14), **0 x 403 and 0 x 429**; no banned
address reverse-resolves to a crawler. 39 x 503 came from `limit_req`, which is
throttling, not a ban.

## [1.5.3] - 2026-11-01

### Added

* **The failover arbiter serves `GET /v1/health` too**, so a monitoring host can poll
  the arbiter and the coordinator the same way. Without it the arbiter answered 404 on
  a route the documentation already promised - found by running the end-to-end check
  on a real host, not by a test.
* `tools/verify-failover-tls.sh` - end-to-end check of the arbiter, TLS and the
  follower retry path on a Linux host, in a temporary directory, with the installed
  configuration untouched. `tools/zabbix-drill.ps1` proves the Zabbix service matching
  by firing one tagged problem and watching the service move.
* `tools/zabbix-agent-install.ps1` installs the agent key and the sudo rule per host,
  handling agent 1 and agent 2 include directories and config paths.

### Fixed

* `tools/gen_zabbix_template.py`: the `UserParameter` ships the `sudo -n` form and the
  sudoers rule covers `--metric *`, so the snapshot stays `0600 root:root` and the
  agent can still read a value.

### Verified on real hosts

Three servers (5.35, 192.168.31.31, 199.195.197.95) run 1.5.2 and the Zabbix module
answers 21/21 items on each; the service tree shows the parent and three children, and
a drill fired a tagged problem that moved the service to High. The end-to-end script
measured: lease grant/refuse and its survival across a restart, `403` on a wrong
secret, TLS refusing an untrusted certificate and accepting a trusted one, follower
retries with counters, and `auto` without a witness staying a follower.

Tests: **237**.

## [1.5.2] - 2026-11-01

### Fixed

* **`--metric` rejected nine of the twenty-one names the Zabbix template uses.**
  The snapshot stores short keys (`accepted_total`) while a monitoring agent asks
  with the Prometheus name (`coord_accepted_total`), so those items answered
  `unknown metric`. `metrics.name_candidates()` now accepts both spellings, and a
  test resolves every item name of the generated template against a real snapshot -
  the check that would have caught this before the rollout.

No other change: the template, the agent key and the coordinator behave as in 1.5.1.

## [1.5.1] - 2026-11-01

### Fixed

* The template test needed PyYAML, which the project does not ship - CI failed on
  ModuleNotFoundError: No module named 'yaml'. The test now checks the generated
  file as text (item and trigger counts, the metric names against the collector, the
  tags) and the real validation stays what it always was: importing the template into
  Zabbix.
* `test_broken_queue_does_not_raise` assumed a Windows-only failure (a path with
  ?); it now points the queue at a directory, which fails on every platform.

No runtime change: the code shipped in 1.5.0 is untouched.

## [1.5.0] - 2026-11-01

### Added

* **Optional automatic failover with a witness arbiter.** `mode = auto` plus
  `failover = witness` makes the role depend on a time-limited lease granted by
  `abuseipdb-witness` (stdlib, one file, no state beyond the lease). The arbiter is
  the only writer, it only ever *grants*, and an expired lease means follower - so a
  lost arbiter cannot produce two leaders. A node that cannot reach the arbiter keeps
  a lease it already holds until it expires. New binary, systemd unit
  (`abuseipdb-witness.service`, installed but not enabled), keys `failover`,
  `witness_url`, `witness_timeout`, `lease_ttl`, `lease_state_path`.
* **TLS for the coordinator, from the standard library.** `tls_cert`/`tls_key` switch
  the endpoint to HTTPS (TLS 1.2 floor), `tls_client_ca` requires client certificates,
  and the follower verifies through `tls_ca` (a self-signed certificate works) with
  `tls_client_cert`/`tls_client_key` for mTLS. `tls_verify = no` is for test rigs.
* **`GET /v1/health`** - liveness without the shared secret, so monitoring can poll it
  from an untrusted network. `GET /v1/status` also reports `effective`,
  `reported_cache`, `reports_today`, `accepted_total`, `rejected_total` and `lease`.
* **Metrics.** `abuseipdb-report --metrics` prints a Prometheus document,
  `--metric <name>` prints a single value, and the reporter writes both `metrics.prom`
  and `metrics.json` after every run. New series: coordination counters, cursor lag,
  sync failures, leader reachability, lease state.
* **Ready Zabbix module** (`monitoring/zabbix/`): an 8.0 template with 21 items, 8
  triggers tagged `server={HOST.HOST}` and `service=fail2ban-abuseipdb`, 3 macros, an
  agent 2 `UserParameter`, and `tools/zabbix-import.ps1` plus
  `tools/zabbix-services.ps1` for the per-server service tree. Documented in
  `docs/ZABBIX.md`.

### Changed

* A follower retries a failed sync `sync_attempts` times inside one run with
  exponential backoff (`sync_retry_base`); a 4xx is not retried. Failures are counted
  in `meta` and exported as metrics.
* The declared jail list survives a failed `fail2ban-client status` (valid up to 24 h)
  and an empty answer no longer overwrites a known list.
* `abuseipdb-coord` refuses to serve pushed events in `auto` mode while the node does
  not hold the lease (HTTP 409 with the lease document).
* Tests: **232** (was 193).

## [1.4.4] - 2026-11-01

### Fixed

* **The 1.4.3 fix did not work, and this one does.** Measured after 1.4.3:
  `raw.githubusercontent.com` still served the previous `updater.json` when the URL
  carried a unique query parameter - repeated probes returned the old file from
  most edges, so `--check` could still claim "you are running the latest version"
  right after a release. The manifest is now read from
  `https://api.github.com/repos/<owner>/<repo>/contents/<path>?ref=<ref>` (media
  type `application/vnd.github.raw`), which is not CDN-cached, and the configured
  `raw.githubusercontent.com` URL stays as the **fallback** for a rate limit, a
  blocked egress or a non-GitHub mirror. A host with a custom `[update]
  manifest_url` is requested exactly as configured - one URL, no rewriting.

### Changed

* `cache_busted()` is kept but documented as measured-ineffective; nothing in the
  updater relies on it any more.
* Tests: **193** (was 188): the raw→API mapping (including nested paths and a tag
  ref), API-first order, raw fallback on HTTP 403, a single request for a foreign
  host, both sources failing, and the `Accept` header only for `api.github.com`.

## [1.4.3] - 2026-11-01

### Fixed

* **`--check` kept reporting "you are running the latest version" right after a
  release.** `updater.json` is served by `raw.githubusercontent.com`, whose CDN
  answers `Cache-Control: max-age=300`; for up to five minutes the updater read
  the previous manifest and saw no update. The manifest request now carries a
  unique `_f2b_nocache=<epoch>` parameter, which the CDN keys on and the origin
  ignores, so a fresh release is visible immediately. Only
  `raw.githubusercontent.com` is affected - a self-hosted or signed manifest URL
  is requested unchanged, because a stray parameter could break a signature.

### Changed

* Tests: **188** (was 183) - the cache buster (unique per call, existing query
  preserved, other hosts untouched) and the fact that `fetch_manifest` uses it.

## [1.4.2] - 2026-11-01

### Changed

* **Publishing to PyPI moved to the CI workflow, with Trusted Publishing.**
  `.github/workflows/release.yml` now declares `environment: pypi` and
  `id-token: write` and uploads the wheel and the sdist with
  `pypa/gh-action-pypi-publish`, so no password and no API token is stored in the
  repository or on the runner. GitHub mints a short-lived OIDC token, PyPI
  exchanges it for an upload token scoped to this repository and workflow, and
  the action also attaches PEP 740 attestations to the files.
* New [`docs/RELEASING.md`](docs/RELEASING.md): the maintainer path end to end
  (version bump, changelog, tag, what CI does, `updater.json`, what each upload
  error means).

### Not changed

Runtime code, configuration and the queue schema are identical to 1.4.1: this
release ships the build pipeline, not new behaviour.

## [1.4.1] - 2026-11-01

### Fixed

* **A follower was asked to ban in jails it does not have.** The leader sends my ban
  list to every node, so a host that runs only `sshd` got ban requests for
  `nginx-php-probe` and answered `NOK: unable to find jail` - one logged error per
  address, on every sync, forever. The sync request now declares the jails the node
  can actually ban in (`fail2ban-client status`, cached for an hour), and the leader
  leaves out anything else. An unknown or empty list sends everything, exactly as in
  1.4.0, so a 1.4.0 follower keeps working unchanged.
* The declared list is validated with the same jail-name pattern as the ban command,
  so a garbage entry can never widen what is sent.

### Changed

* `max_sync_bans` is applied **after** the jail filter, so the cap counts bans that
  node can really apply.
* Tests: **183** (was 175).

## [1.4.0] - 2026-11-01

### Added

* **Two-way sync between nodes.** `POST /v1/sync` now answers with
  `recently_reported`, `to_ban` and `next_since` in addition to the counters; the
  follower sends its cursor (`since`) so it receives only what it is missing.
  `POST /v1/push` keeps working, so a 1.3.x follower still syncs.
* **Ban propagation.** A ban seen on one node is applied on the others through
  `fail2ban-client set <jail> banip <address>`, so an attacker who moves between
  hosts meets the same block everywhere. Rails: the address must parse, must not
  be in `[ignore] ranges`, must not be the node's own `server_ip`, the jail name
  must match `^[A-Za-z0-9._@-]{1,64}$`, at most `max_remote_bans_per_run` (20,
  ceiling 200) per run, and nothing can ever be unbanned. `sync_bans = no`
  disables it.
* **Report deduplication across the cluster.** New `reported_cache` table: the
  leader sends the addresses it reported inside `peer_dedupe_window` (900 s), a
  follower merges them, and the reporting path skips an address that is already
  in the cache (events are marked reported, no API call is spent). Timestamps from
  a peer are clamped to now, so a broken clock cannot block an address.
* `events.origin` column (in-place migration): a ban is never echoed back to the
  node that reported it.
* `--stats` prints the `reported cache` size; `--coord-status` on a follower also
  shows the sync cursor and the cache size.
* Config keys: `sync_bans`, `max_remote_bans_per_run`, `peer_dedupe_window`,
  `max_sync_bans`.

### Changed

* The first sync adopts the leader's bans from the **last two hours** (bounded by
  `max_sync_bans`), not its whole queue history - a new node should not replay
  thousands of old bans in one tick.
* `RunResult.banned` reports how many remote bans a follower applied; the status
  file and the log line carry it.
* Docs: `docs/COORDINATION.md` rewritten for the two-way protocol (payloads,
  cursor semantics, rails, failure modes); CONFIGURATION, ARCHITECTURE, README and
  AGENTS updated.
* Tests: **175** (was 152).

## [1.3.0] - 2026-10-31

### Added

* **Leader/follower coordination** for several protected hosts sharing one
  AbuseIPDB account (limits are per account): `[coordination] mode = leader`
  keeps the API key and accepts pushed events, `mode = follower` pushes its queue
  and never calls the API. The default `mode = none` is byte-for-byte the old
  behaviour.
  * new `abuseipdb-coord` entry point (installed by `install.sh`, unit
    `abuseipdb-coord.service` installed but **never enabled**);
  * two routes: `POST /v1/push` (batch of events, `X-Coord-Secret`) and
    `GET /v1/status`; constant-time secret comparison, 1 MiB body cap, 5000
    events per request cap;
  * the leader applies its own filters (valid address, `[ignore] ranges`,
    `skip_jails`) before queueing, and reports through the normal worker, so the
    account-wide budget and the per-IP interval stay exact;
  * `abuseipdb-report --coord-status` shows the role, whether the secret is
    present, and the leader's status from a follower;
  * `--dry-run` on a follower prints the events that would be pushed.
* `events.pushed` column with an in-place migration in `db.connect()` (an old
  queue is upgraded, never rewritten); pushed events are excluded from every
  local reporting query and removed by `retention_days`.
* `docs/COORDINATION.md`: roles, configuration, secret generation, failover,
  security rules and a failure-mode table.

### Changed

* `--stats` prints a `pushed to leader` counter.
* **Published on PyPI** as [`fail2ban-abuseipdb-reporter`](https://pypi.org/project/fail2ban-abuseipdb-reporter/):
  wheel and sdist with PEP 639 license metadata (`license = "MIT"`,
  `license-files`), a `MANIFEST.in` so the sdist carries the tests, the docs and
  the host integration files, and `setuptools>=77` as the build requirement. A pip
  install gives the four CLIs and the library only - the host integration stays
  with `install.sh`.
* Coordination HTTP failures keep events queued: a leader outage delays reports
  and never loses them. A lost acknowledgement is absorbed by the leader's
  5-minute deduplication.
* Tests: **151** (was 124), including the endpoint, the migration, the follower
  path and authentication.

## [1.2.1] - 2026-10-31

### Fixed

* **Inline comments in `[ignore] ranges`**: `10.0.0.0/8   # office` lost the
  whole network, because the parser saw the comment as part of the CIDR. The
  text after `#` is now dropped, so the style shown in the documentation and in
  `config/reporter.conf.example` works as written.
* README: the tests badge and the tracked-file count still said 88 / 66.
* `docs/CONFIGURATION.md`: the opening paragraph still claimed that
  `reporter.conf` holds the API key (untrue since 1.1.0).
* `CHANGELOG.md`: missing link definitions for 1.1.0 and 1.1.1.

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
[1.1.0]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.1.0
[1.1.1]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.1.1
[1.2.0]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.2.0
[1.2.1]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.2.1
[1.3.0]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.3.0
[1.4.0]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.4.0
[1.4.1]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.4.1
[1.4.2]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.4.2
[1.4.3]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.4.3
[1.4.4]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.4.4
[1.5.0]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.5.0
[1.5.1]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.5.1
[1.5.2]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.5.2
[1.5.3]: https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.5.3