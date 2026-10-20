# Self-update

Fail2Ban_AbuseIPDB can update itself from GitHub without losing its API key,
configuration or queue.

## Commands

```bash
# Is a newer version published?
abuseipdb-upgrade --check
#   0  -> already up to date
#   10 -> update available
#   1  -> error (network, invalid manifest, ...)

# Machine-readable form for scripts
abuseipdb-upgrade --check --json

# Install the update (root required)
sudo abuseipdb-upgrade --upgrade

# Non-interactive (cron, configuration management)
sudo abuseipdb-upgrade --upgrade --yes

# See what would happen without downloading/installing
abuseipdb-upgrade --upgrade --dry-run
```

The updater binary is installed as `/usr/local/sbin/abuseipdb-upgrade`; when the
project is used from a git checkout, `python3 bin/abuseipdb-upgrade` works the
same way.

## Manifest

`updater.json` in the repository root is the single source of truth:

```json
{
  "name": "Fail2Ban_AbuseIPDB",
  "version": "1.1.0",
  "released": "2026-10-20",
  "requires_python": ">=3.9",
  "tarball": "https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/download/v1.1.0/Fail2Ban_AbuseIPDB-1.1.0.tar.gz",
  "sha256": "<sha256 of the tarball>",
  "release_notes": "https://github.com/paulmann/Fail2Ban_AbuseIPDB/releases/tag/v1.1.0",
  "changelog": "https://github.com/paulmann/Fail2Ban_AbuseIPDB/blob/main/CHANGELOG.md",
  "notes": "Short human-readable summary"
}
```

The URL is configurable (`--manifest-url`, or `[update] manifest_url` in
`reporter.conf`) for mirrors and tests.

## What `--upgrade` does

1. Reads the manifest and compares `version` with the installed
   `abuseipdb_reporter.__version__` (semantic version comparison; `--force`
   installs even if the remote version is not newer).
2. Downloads the tarball over HTTPS to a temporary directory.
3. **Requires** `sha256` in the manifest and verifies the archive against it; a
   mismatch aborts before anything is touched.
4. Extracts the archive with a safe extractor that rejects absolute paths,
   `..` traversal, symlinks, hard links and device entries.
5. Takes a snapshot of `/etc/abuseipdb/.abuseipdb.key`.
6. Runs the bundled `install.sh` from the extracted tree. The installer keeps:
   * the API key file (never rewritten if it already exists),
   * `reporter.conf`,
   * the queue database,
   * the list of jails (detected from the existing
     `/etc/fail2ban/jail.d/50-abuseipdb-reporter.local`),
   * a backup of every replaced file under
     `/var/backups/fail2ban-abuseipdb/`.
7. If the installer fails or the key file disappears, the snapshot is restored.

The release archive never contains the key, the config or the queue.

## Weekly availability check

Install the optional timer/cron:

```bash
sudo ./install.sh --with-update-check
```

* systemd: `abuseipdb-upgrade-check.timer` runs every Monday at 04:30 (with
  jitter) and executes `abuseipdb-upgrade --check --quiet`;
* cron: `/etc/cron.d/abuseipdb-upgrade-check`.

The check only reads `updater.json` and writes the result to the journal; it
**never installs** an update automatically. Automatic installation is
deliberately not provided - a production firewall host should decide when to
restart fail2ban.

## Rollback

`install.sh` writes the previous version of every replaced file to
`/var/backups/fail2ban-abuseipdb/pristine-<timestamp>/` and an install state file
to `/var/lib/fail2ban-abuseipdb/install-state`. A normal uninstall restores the
files that existed before the first installation; `--purge` removes the config,
queue and key.

For a manual rollback after a bad release, restore the files from the pristine
directory (or uninstall and reinstall a known-good tag) - the key file, config
and queue are independent of the code and stay in place.

## Security notes

* The manifest is fetched over HTTPS from the repository; the archive is
  additionally pinned by SHA-256.
* The updater must run as root because it executes the installer; `--check`
  and `--dry-run` work as an unprivileged user.
* Only the project's own `install.sh` is executed from the archive; no other
  files are run.
* The key is never sent anywhere by the updater.