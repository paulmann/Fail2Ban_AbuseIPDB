## v1.3.0 — several hosts, one AbuseIPDB account

AbuseIPDB limits are **per account**. Until now every protected host needed its
own key and reported on its own, so `n` hosts spent the account budget `n` times
faster and could report the same address twice inside the 15-minute window.

1.3.0 adds an optional leader/follower role. Nothing changes unless you ask for
it: `[coordination] mode = none` is the default and behaves exactly like 1.2.1.

### Added

* **`mode = leader`** — reports as usual and runs `abuseipdb-coord`, a small
  authenticated endpoint (`POST /v1/push`, `GET /v1/status`) that accepts events
  from other hosts. Only the leader holds the API key and owns the account-wide
  budget and per-IP interval.
* **`mode = follower`** — needs no API key and never calls the API: its worker
  pushes queued events in batches, marks them delivered, and retries on the next
  tick if the leader is unreachable. Nothing is lost during an outage.
* **`abuseipdb-coord`** entry point with `--check`, `--bind`, `--port`; the
  systemd unit `abuseipdb-coord.service` is installed by `install.sh` but **never
  enabled** — an endpoint nobody asked for must not open a port.
* **`abuseipdb-report --coord-status`** — role, `node_id`, `secret: present` or
  `MISSING`, and from a follower the leader's own status document.
* `--dry-run` on a follower prints the events that would be pushed.
* `docs/COORDINATION.md` — topology, configuration, secret generation, failover,
  security rules, failure modes.

### Changed

* New `events.pushed` column, added by an in-place migration: an existing queue is
  upgraded on first open, never rewritten. Pushed events stop being "pending" for
  that node and are removed by the normal `retention_days` cleanup.
* `--stats` prints `pushed to leader`.
* The leader applies its own filters to pushed events (valid address,
  `[ignore] ranges`, `skip_jails`), so a misconfigured follower cannot make it
  report something it would never report itself.
* Tests: **151** (was 124), including the endpoint, authentication, the migration
  and the follower path.

### Security notes

* The shared secret is a file (mode 600), compared in constant time; missing or
  wrong values get HTTP 403.
* The endpoint speaks plain HTTP: bind it to a private interface, restrict it with
  a firewall or systemd `IPAddressAllow=`, or terminate TLS in front of it.
* Requests larger than 1 MiB are rejected before the body is read.

### Upgrade

```bash
sudo abuseipdb-upgrade --check     # exit 10 = update available
sudo abuseipdb-upgrade --upgrade --yes
```

The queue is migrated automatically, configuration keys have safe defaults, and
standalone installations keep working without any edit. To use coordination, add
the `[coordination]` section on every node and create the shared secret (see
`docs/COORDINATION.md`).
