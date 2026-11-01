## v1.5.1 — the test that needed a dependency CI does not have

Everything in 1.5.0 works; the release workflow stopped earlier, at the unit tests:

* the generated template test imported PyYAML, and this project ships **no**
  dependencies - CI failed with ModuleNotFoundError: No module named ''yaml''. The
  test now checks the checked-in file as text (item and trigger counts, every item
  name against the collector, the service tags) and the real validation stays what it
  always was: importing the template into Zabbix, which was done against 8.0.0 for
  this release (21 items, 8 triggers, 3 macros).
* 	est_broken_queue_does_not_raise used a path with ?, which only fails on
  Windows; it now points the queue at a directory, so the test means the same thing
  on every platform.

### Upgrade

buseipdb-upgrade --upgrade --yes. No runtime change over 1.5.0 - same code, same
configuration, same behaviour.
