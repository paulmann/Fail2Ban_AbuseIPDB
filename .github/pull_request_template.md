## Summary

<!-- What does this change and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Tests / CI
- [ ] Installer / packaging

## Checklist

- [ ] Unit tests pass: `python -m unittest discover -v -s tests -t .`
- [ ] Integration test passes: `bash tests/integration/run_integration.sh`
- [ ] `shellcheck -x install.sh uninstall.sh tests/integration/run_integration.sh` is clean
- [ ] Documentation updated (README / docs / CHANGELOG)
- [ ] No secrets, real IP addresses or client data added
- [ ] The ban path stays free of network calls