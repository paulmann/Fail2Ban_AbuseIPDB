## Fail2Ban_AbuseIPDB v1.1.1

Bug-fix release for the installer configuration handling.

### Fixed

- **`api_key_file` placement on upgrade.** Upgrading a configuration that did
  not yet contain `api_key_file` appended the line to the end of the file
  (inside `[category_map]`) instead of `[abuseipdb]`. The installer now inserts
  it at the end of the `[abuseipdb]` section and replaces an existing line in
  place. Config parsing and the default key path were unaffected, but a custom
  `--key-file` path could be ignored by the reporter in that edge case.
- Re-running the installer over such a configuration repairs it (the stray line
  is removed and the correct one is written into `[abuseipdb]`).

### Upgrade

```bash
sudo abuseipdb-upgrade --check     # 10 = update available
sudo abuseipdb-upgrade --upgrade   # verifies SHA-256, keeps key/config/queue/jails
```

Key file, configuration, queue and jail list are preserved as in v1.1.0.