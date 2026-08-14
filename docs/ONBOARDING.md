# Secrets Onboarding

`analytics-secrets` is a **library**, not a service — there's nothing to run.
It is the shared crypto dependency consumed by `analytics-client`,
`analytics-hub`, `analytics-edge`, and `analytics-spoke`.

## Install (as a consumer)

```bash
pip install "analytics-secrets @ git+https://github.com/Semantic-Automation/analytics-secrets.git@v0.6.0"
```

Public repo — no auth needed. Consumers pin the tag (the Containerfiles use
`SECRETS_PIN=v0.6.0`).

## For local development of the library itself

```bash
pip install -e ".[dev]"
pytest tests
```

## Dependencies

- Python >= 3.11
- `cryptography >= 50`
- No runtime services — it is pure code.

## Release discipline

- Bump the version in `pyproject.toml` for behavior changes.
- Tag (`v0.7.0` etc.) — consumers pin the tag and upgrade deliberately.
- Add a CHANGELOG entry per release.
