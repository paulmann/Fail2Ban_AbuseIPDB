# Releasing (maintainer checklist)

The release path is driven by a tag: CI builds, tests, publishes to PyPI and
creates the GitHub release. Publishing uses **Trusted Publishing (OIDC)** - no
password and no API token is stored in the repository or in the runner.

## How publishing is wired

| Piece | Value |
|---|---|
| PyPI project | `fail2ban-abuseipdb-reporter` |
| Publisher form (PyPI → project → Publishing) | Owner `paulmann`, repository `Fail2Ban_AbuseIPDB`, workflow `release.yml`, environment `pypi` |
| Workflow | `.github/workflows/release.yml`, job `release`, `environment: pypi` |
| Permission that makes it work | `id-token: write` on the **job** (job-level `permissions` replace the file-level ones, so `contents: write` is repeated there) |
| Upload action | `pypa/gh-action-pypi-publish@release/v1`, `packages-dir: dist/` |

GitHub mints a short-lived OIDC token, PyPI exchanges it for an upload token
scoped to this repository, this workflow file and the `pypi` environment, and the
action also attaches PEP 740 attestations to the uploaded files.

Two things must match **exactly**, otherwise the upload ends in
`403 invalid-publisher`:

1. the `workflow` field is the **file name** (`release.yml`), not the `name:` key
   inside it;
2. `environment:` in the job equals the environment field in the form. If the form
   leaves it empty, the job must not declare `environment` at all.

Manual upload with a token is no longer needed. The token that was used before
trusted publishing (`PyPI API token - deynekin (github-agent-cli)` in the vault)
can be revoked; the CI path does not read it.

## Steps

1. **Bump the version in three places** - the release workflow fails if they
   disagree with the tag:

   ```bash
   python tools/bump_string.py src/abuseipdb_reporter/__init__.py '__version__ = "1.4.1"' '__version__ = "1.4.2"'
   python tools/bump_string.py pyproject.toml 'version = "1.4.1"' 'version = "1.4.2"'
   python tools/bump_string.py install.sh 'VERSION="1.4.1"' 'VERSION="1.4.2"'
   ```

2. **Write the changelog entry** in `CHANGELOG.md` (Keep a Changelog sections,
   plus the comparison link at the bottom) and a `docs/release-notes-<version>.md`.
   The release workflow uses that file as the release body when it exists and
   falls back to generated notes when it does not.

3. **Run the checks locally** - the same ones CI runs:

   ```bash
   python -m compileall -q src tests tools
   python -m unittest discover -s tests -t .
   python tools/e2e_local.py
   shellcheck -x install.sh uninstall.sh tests/integration/run_integration.sh
   python -m build --no-isolation && python -m twine check dist/*
   ```

4. **Commit and tag**. The tag must contain the workflow that publishes, so the
   `release.yml` change and the version bump go into the same commit:

   ```bash
   git add -A
   git -c 'user.name=<owner>' -c 'user.email=<owner@mail>' commit -m 'release: v1.4.2'
   git tag -a v1.4.2 -m 'v1.4.2: <one line>'
   git push origin main && git push origin v1.4.2
   ```

5. **Watch the run**. `Release` builds the tarball, the wheel and the sdist, runs
   the unit tests, publishes to PyPI, then creates the GitHub release with the
   three assets:

   ```bash
   gh run list -L 2
   gh run watch <id>
   gh release view v1.4.2 --json assets -q '.assets[].name'
   ```

6. **Update `updater.json`** with the checksum the workflow printed in its
   summary (`Show the checksum for updater.json`), then commit and push. The
   self-updater reads this file, so it is what makes `abuseipdb-upgrade --check`
   see the new version. Since 1.4.4 the updater reads the manifest through
   `api.github.com/repos/<owner>/<repo>/contents/updater.json?ref=main` (media type
   `application/vnd.github.raw`) and keeps `raw.githubusercontent.com` as the
   fallback - the raw host sits behind a CDN with `max-age=300` and will happily
   serve the previous manifest for minutes, which made `--check` claim "you are
   running the latest version" right after a release. A host still running 1.4.3
   or older may need that window once.

7. **Update the wiki** (`Home` badges, `17-Development-and-Testing`,
   `18-Multi-Host-Coordination` when the feature changed) and the `AGENTS.md`
   header version.

## What to check when the publish step fails

| Message | Cause |
|---|---|
| `403 invalid-publisher` / `Trusted publishing exchange failure` | the form and the workflow disagree on owner, repository, workflow file name or environment |
| `400 File already exists` | that version is already on PyPI; the version was not bumped, or the tag points at an already released commit |
| `Metadata is not valid` | `pyproject.toml` is wrong - run `python -m twine check dist/*` locally first |
| Step skipped with a permissions error | `id-token: write` missing from the **job** (`permissions` does not merge with the file-level block) |

`400 File already exists` is also the harmless result of re-running the Release
workflow on a tag that was already published - the OIDC exchange still worked,
which is what that re-run actually proves.
