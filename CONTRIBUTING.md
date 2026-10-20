# Contributing

Thanks for taking the time to improve the project.

## Development setup

```bash
git clone https://github.com/paulmann/Fail2Ban_AbuseIPDB.git
cd Fail2Ban_AbuseIPDB

python3 --version                  # 3.9+
python -m unittest discover -v -s tests -t .
bash tests/integration/run_integration.sh
shellcheck -x install.sh uninstall.sh tests/integration/run_integration.sh
```

There are no runtime or test dependencies: Python standard library only. The
integration test starts a mock AbuseIPDB API on `127.0.0.1` and never touches the
network or the firewall.

## Project rules

* **Standard library only.** No PyPI dependencies in `src/`, `bin/` or tests.
* **The ban path must stay trivial.** Nothing in the fail2ban action may block
  on the network; reporting happens only in the worker.
* **No attacker-controlled text in a shell.** Values may be added to a comment,
  never to a command line.
* **No PII in reports.** Attempted usernames, mail content and client domains
  must not be sent.
* **Backwards-compatible configuration.** New options get safe defaults; existing
  keys keep working.

## Tests

The test suite is the contract:

| Suite | What it covers |
|---|---|
| `tests/test_config.py` | INI parsing, defaults, category map, ignore ranges |
| `tests/test_db.py` | queue schema, dedupe, state transitions, cleanup |
| `tests/test_evidence.py` | fail2ban evidence reading, log classification |
| `tests/test_comments.py` | comment format, categories, size limit, PII rules |
| `tests/test_reporter.py` | success, throttle, 429/422/500/401, dry-run, budgets |
| `tests/test_api.py` | HTTP client against a local server |
| `tests/test_enqueue.py` | address validation, ignore rules, skipped jails |
| `tests/test_cli.py` | CLI entry points and output |
| `tests/integration/run_integration.sh` | real worker + queue + mock API end-to-end |

Any change in behaviour needs a test. Keep the tests offline and runnable
without root.

## Installer changes

`install.sh` is covered by CI in staging mode:

```bash
sudo bash install.sh --root /tmp/stage --api-key "$(printf 'a%.0s' {1..80})" \
  --jails "sshd" --cron --skip-api-check --no-restart
sudo bash install.sh --root /tmp/stage --uninstall
```

Never let the installer modify files outside the paths it lists in its manifest,
and always keep the `fail2ban-client -t` gate before restarting the service.

## Commit messages

* Use the imperative mood: `Add per-IP throttle test`, not `Added`.
* One logical change per commit.
* Reference an issue when applicable: `Fix #12: ...`.

## Pull requests

1. Fork the repository and create a topic branch.
2. Add tests for the new behaviour.
3. Make sure all gates pass locally (unit tests, integration test, shellcheck).
4. Describe the change, the motivation and the user-visible effect.
5. Keep documentation in sync (`README.md`, `docs/`, `CHANGELOG.md`).

## Reporting bugs

Open an issue with:

* distribution and versions (`python3 --version`, `fail2ban-client --version`);
* the relevant lines from `/var/log/abuseipdb-reporter.log`;
* output of `abuseipdb-report --stats` and `fail2ban-client get <jail> actions`;
* what you expected and what happened.

**Never paste your API key or real collected IP addresses** - redact them.