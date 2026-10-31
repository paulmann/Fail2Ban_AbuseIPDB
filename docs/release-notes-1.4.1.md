## v1.4.1 — a node is only asked for bans it can actually apply

Found on the live fleet a minute after 1.4.0 went in: the leader sends its whole
ban list to every follower, and a follower that does not run that jail answers
`NOK: unable to find jail`. One error per address, on every sync, forever — the
log of a small host filled with bans it could never apply.

### Fixed

* **The sync request now declares the jails the node can ban in.** The follower
  reads them from `fail2ban-client status` (cached for an hour) and sends the list;
  the leader leaves out any ban for a jail that node does not have. An unknown or
  empty list sends everything, exactly as in 1.4.0 — a 1.4.0 follower keeps
  working, unchanged and unfiltered.
* The declared names are validated with the same pattern as the ban command
  (`^[A-Za-z0-9._@-]{1,64}$`), so a garbage entry can never widen what is sent.

### Changed

* `max_sync_bans` is applied **after** the jail filter, so the cap counts bans the
  node can really apply instead of bans it would refuse.
* Tests: **183** (was 175). The new ones cover the filter, the "unknown list sends
  everything" fallback, the jail-name validation, the TTL of the cached list and
  the missing-`fail2ban-client` case.

### Upgrade

```bash
sudo abuseipdb-upgrade --upgrade --yes
```

No configuration change and no migration: the jail list is discovered and cached
by the follower itself. On a follower, the first sync after the upgrade replaces
the noisy log lines with a shorter `to_ban` list.
