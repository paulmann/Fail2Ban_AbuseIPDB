## v1.6.1 - a metric that survives an upgrade

`--metric` reads the snapshot the reporter writes after each run. A file written by the
previous version does not contain a key added by the upgrade, so
`last_run_crawlers_skipped` answered `unknown metric` on every host - for a whole timer
interval, after every release that adds a metric.

### Fixed

* When the snapshot file lacks the requested key, the value is computed live instead of
  being refused. A stale file answering an old key can no longer hide a new one; a test
  covers exactly that (`test_a_key_missing_from_the_file_is_computed_live`).

### Also

`--crawler-status` and `--crawler-check` ship with this release, the Zabbix template
gains the corresponding item and trigger (22 items, 9 triggers), and the documentation
sweep brought every page up to date. Tests: **250**.

### Upgrade

`abuseipdb-upgrade --upgrade --yes`. No configuration change.
