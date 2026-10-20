## Fail2Ban_AbuseIPDB v1.1.0

Key management and self-update: the project can now update itself from GitHub
without ever losing the AbuseIPDB API key.

### Highlights

- **API key in its own file** - `/etc/abuseipdb/.abuseipdb.key` (mode 600),
  separate from `reporter.conf`, the code and the release tarball. Re-installs
  and self-updates keep an existing key file untouched.
- **First-run wizard** - if no key is configured, an interactive run asks for it
  once, validates it and saves it to the key file. Non-interactive runs
  (systemd/cron) fail with an actionable message instead of hanging.
- **Migration** - a legacy `api_key` in `reporter.conf` is moved into the key
  file automatically (or with `abuseipdb-report --migrate-key`), and the config
  line is blanked.
- **Self-update** - `abuseipdb-upgrade --check` compares the installed version
  with `updater.json` on GitHub (exit 10 = update available).
  `abuseipdb-upgrade --upgrade` downloads the release tarball, **requires and
  verifies its SHA-256**, extracts it with a traversal/link-safe extractor,
  snapshots the key file and runs the bundled installer. On failure the key is
  restored; the config, queue and jail list are preserved.
- **Optional weekly check** - `install.sh --with-update-check` installs a
  systemd timer (or cron job) that only reports availability; it never installs
  in the background.
- **Safer upgrades** - the installer detects the already configured jails on
  upgrade, keeps `reporter.conf`, the queue database and the key file, and still
  backs up every replaced file under `/var/backups/fail2ban-abuseipdb/`.
- **Self-advertising footer** from v1.0.0 stays: every report ends with
  `Reported via Fail2Ban_AbuseIPDB Monitor: https://github.com/paulmann/Fail2Ban_AbuseIPDB`
  (configurable with `attribution = no`).

### Install / upgrade

```bash
git clone https://github.com/paulmann/Fail2Ban_AbuseIPDB.git
cd Fail2Ban_AbuseIPDB
sudo ./install.sh            # asks for the API key once on a terminal

# existing installations:
sudo abuseipdb-upgrade --check
sudo abuseipdb-upgrade --upgrade
```

Full documentation: [README](https://github.com/paulmann/Fail2Ban_AbuseIPDB/blob/main/README.md),
[INSTALL](https://github.com/paulmann/Fail2Ban_AbuseIPDB/blob/main/docs/INSTALL.md),
[UPDATE](https://github.com/paulmann/Fail2Ban_AbuseIPDB/blob/main/docs/UPDATE.md),
[CONFIGURATION](https://github.com/paulmann/Fail2Ban_AbuseIPDB/blob/main/docs/CONFIGURATION.md).