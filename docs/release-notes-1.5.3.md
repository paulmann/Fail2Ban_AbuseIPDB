## v1.5.3 — the arbiter answers `/v1/health`, and two checks that can fail

Two additions that came out of the rollout, not out of a unit test.

### The arbiter serves `/v1/health`

`docs/COORDINATION.md` promised a liveness route without the shared secret, and the
coordinator had one - the arbiter answered `404`. A monitoring host polls both the
same way now:

```bash
curl -s http://arbiter:8765/v1/health
{"ok": true, "role": "witness", "time": 1793532956, "live": false, "persisted": true}
```

`live` says whether a lease is currently held, `persisted` whether the state file is
configured (that is what stops a restart from handing leadership to a second node).
No owner, no deadline: the unauthenticated route stays uninformative on purpose.

### Two scripts that tell "green" from "working"

* **`tools/verify-failover-tls.sh`** exercises the arbiter, TLS and the follower retry
  path on a real Linux host in a temporary directory - the installed configuration is
  never touched. Measured on 5.35:

  | Step | Result |
  |---|---|
  | arbiter health, no secret | `200 {"ok": true, "role": "witness", "persisted": true}` |
  | node-a asks for the lease | `200 {"granted": true, "owner": "node-a", "term": 1}` |
  | node-b asks while held | `409 {"granted": false, "reason": "lease held by node-a ..."}` |
  | wrong secret | `403` |
  | arbiter restart | lease still `node-a`, same term |
  | TLS, certificate untrusted | handshake fails (`http=000`) |
  | TLS, certificate as CA | `200` |
  | follower sync to a closed port | 2 attempts, `coord_sync_failures = 1`, `leader_up = -1` |
  | coordinator `/v1/health` over TLS | `200`, `tls: true` |
  | coordinator `/v1/status`, no secret | `403` |
  | one signed sync | `200 accepted: 1, inserted: 0, rejected: 1` |
  | `auto` without `witness_url` | `effective role: follower` |

  `rejected: 1` is correct: the script pushes `198.51.100.77`, inside the default
  `[ignore] ranges`. The rail works; a documentation address never reaches the API.

* **`tools/zabbix-drill.ps1`** proves the service matching. A green service tree
  proves nothing - a service whose tags match no trigger stays green forever. The
  drill fires one problem with the module's tags and watches the child move:

  ```
  attempt 1: problems=0 service status=-1
  attempt 2: problems=1 service status=4
  result: service matching WORKS
  ```

### Also fixed

The `UserParameter` ships the `sudo -n` form, and the shipped sudoers rule covers
`--metric *` - without that the agent could not run the CLI at all, and the snapshot
can now stay `0600 root:root`.

### Upgrade

`abuseipdb-upgrade --upgrade --yes`. Nothing to reconfigure.
