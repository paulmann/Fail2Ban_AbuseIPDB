## v1.4.2 — publishing moved into CI, with attestations

No runtime change: the package, the configuration and the queue schema are
identical to 1.4.1. This release ships the release pipeline itself.

### Changed

* **PyPI uploads happen in the release workflow, using Trusted Publishing.**
  `release.yml` declares `environment: pypi` and `id-token: write` and uploads the
  wheel and the sdist with `pypa/gh-action-pypi-publish`. GitHub mints a
  short-lived OIDC token; PyPI exchanges it for an upload token scoped to this
  repository, this workflow file and that environment. No password, no token in
  the repository, nothing to rotate — and the pushed files now carry **PEP 740
  attestations**, so `pip` can check that the artefact really came out of this
  workflow.
* Publishing runs before the GitHub release is created, so a failed upload leaves
  no release pointing at files that never arrived.
* New maintainer guide `docs/RELEASING.md`: the checklist, why the job repeats
  `contents: write` and `id-token: write`, and what each upload error means
  (`403 invalid-publisher` = the form and the workflow disagree on owner,
  repository, workflow file name or environment; `400 File already exists` = that
  version is already on PyPI).

### Verified before tagging

The OIDC exchange was exercised on the previous tag: the action obtained a token
and reached the upload endpoint, which answered `400 File already exists` for the
already published 1.4.1 files. That error is the proof that the publisher form and
the workflow agree — an unconfigured publisher fails earlier with
`403 invalid-publisher`.

### Upgrade

Nothing to do: an installed host keeps working unchanged. `abuseipdb-upgrade`
sees the new version through `updater.json` as usual.
