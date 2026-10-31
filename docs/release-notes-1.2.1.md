## v1.2.1 — inline comments in `[ignore] ranges`, documentation corrections

A small correctness release on top of 1.2.0.

### Fixed

* **`[ignore] ranges` with an inline comment.** The documented style
  `ranges = 10.0.0.0/8   # office` silently dropped the whole network: the
  comment became part of the CIDR and the entry was skipped. Text after `#` is
  now discarded before parsing, so the example in the documentation and in
  `config/reporter.conf.example` works as written. A range that is still
  unparsable is skipped as before - a malformed range never stops the reporter.
* README: the tests badge said `88` and the tracked-file count said `66`
  (actual: 124 tests, 74 files).
* `docs/CONFIGURATION.md`: the opening paragraph claimed that `reporter.conf`
  contains the API key, which has not been true since 1.1.0.
* `CHANGELOG.md`: missing comparison-link definitions for 1.1.0 and 1.1.1.

### Upgrade

```bash
sudo abuseipdb-upgrade --check     # exit 10 = update available
sudo abuseipdb-upgrade --upgrade --yes
```

No configuration change is required. If you keep management addresses in
`[ignore] ranges` with a trailing comment, re-run `abuseipdb-report --stats` or
`--dry-run` once and confirm that your addresses are no longer reported.
