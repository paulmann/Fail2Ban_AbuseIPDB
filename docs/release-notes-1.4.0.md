## v1.4.0 — bans travel, reports do not repeat

1.3.0 made one node report for the whole fleet. 1.4.0 closes the two gaps that
left open: an attacker banned on one host was still free to attack the others, and
a role change could produce a second report for an address reported minutes ago.

### Added

* **Two-way sync.** `POST /v1/sync` returns, together with the counters,
  `recently_reported`, `to_ban` and `next_since`. The follower sends its cursor
  (`since`), so answers stay small: only bans created after it, never its own.
  `POST /v1/push` still answers, so a 1.3.x follower keeps working.
* **Ban propagation.** The follower applies `to_ban` with
  `fail2ban-client set <jail> banip <address>` — no shell involved. Rails, in
  order: the address must parse, must not be in `[ignore] ranges`, must not be the
  node's own `server_ip`, the jail name must match `^[A-Za-z0-9._@-]{1,64}$`, at
  most `max_remote_bans_per_run` (20, ceiling 200) per run, and nothing can ever
  be unbanned. `sync_bans = no` turns it off, keeping the rest of the sync.
* **Cluster-wide report deduplication.** New `reported_cache` table and
  `peer_dedupe_window` (900 s): the leader publishes what it reported, followers
  merge it, and the reporting path skips an address that is already in the cache -
  the events are marked reported and no API call is spent. Peer timestamps are
  clamped to now, so a wrong clock cannot silence an address for years.
* `events.origin` (in-place migration) records which node reported a ban, so a
  node never receives its own bans back.
* `--stats` shows the `reported cache` size; `--coord-status` on a follower shows
  the sync cursor and the cache.

### Changed

* The first sync adopts the leader's bans from the **last two hours** (bounded by
  `max_sync_bans`), not the whole queue history.
* `RunResult.banned` counts remote bans applied in a run; it lands in the log line
  and in `status.json`.
* `docs/COORDINATION.md` rewritten around the two-way protocol, with the exact
  request and answer payloads, the rails and the failure table.
* Tests: **175** (was 152), including a fake `fail2ban-client` that asserts the
  exact argv, the caps, the ignore-ranges filter and the "never echo a ban back"
  rule.

### Not included, on purpose

Automatic failover. A lease file on shared storage cannot be made safe without an
atomic compare-and-swap: two nodes renewing it concurrently both think they are
the leader, and a split brain spends the account budget twice while breaking the
per-IP interval. Moving the key and flipping `mode` is slower and always correct;
the procedure is in `docs/COORDINATION.md`.

### Upgrade

```bash
sudo abuseipdb-upgrade --check     # exit 10 = update available
sudo abuseipdb-upgrade --upgrade --yes
```

The queue is migrated in place (`pushed`, `origin`, `reported_cache`), existing
configuration keys keep their defaults, and standalone nodes (`mode = none`) do
not change behaviour. On a follower, `fail2ban-client` must be in `PATH` and the
jails named in `to_ban` must exist locally - a missing jail is logged and skipped,
never retried in a loop.
