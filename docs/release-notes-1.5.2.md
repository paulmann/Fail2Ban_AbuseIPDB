## v1.5.2 — nine Zabbix items answered "unknown metric"

Found while installing the module on the three servers: the snapshot stores short
keys (ccepted_total) but a monitoring agent asks with the Prometheus name
(coord_accepted_total), so --metric coord_accepted_total exited 2 and the item
became unsupported.

### Fixed

* metrics.name_candidates() accepts both spellings, so --metric answers for every
  one of the twenty-one item names in the generated template.
* A test now takes those twenty-one names **from the generated template** and resolves
  each against a real snapshot - the check that would have caught this before a
  rollout instead of after it.

Nothing else changed: template, agent key and coordinator behaviour are those of
1.5.1.

### Upgrade

buseipdb-upgrade --upgrade --yes. On a host with the Zabbix module installed, the
items recover on their next poll (5 minutes) without touching the agent.
