# Secrets Onboarding

`analytics-secrets` is a **library**, not a service — there's nothing to run.
It is the shared crypto dependency consumed by `analytics-client`,
`analytics-hub`, `analytics-edge`, `analytics-builder`, and `analytics-spoke`
(`analytics-tunnels` is transport-only and does not use it).

## Install (as a consumer)

```bash
pip install "analytics-secrets @ git+https://github.com/Semantic-Automation/analytics-secrets.git@v0.7.10"
```

Public repo — no auth needed. Consumers pin a tag: Containerfiles use a
`SECRETS_PIN` build arg (e.g. `ARG SECRETS_PIN=v0.7.8` in `analytics-spoke` /
`analytics-hub`), requirements files pin the tag directly. Current release is
**v0.7.10**.

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

- Bump the version in **both** `pyproject.toml` and `src/secretskit/__init__.py`
  (`__version__`) for behavior changes.
- Tag (`v0.7.10`) — consumers pin the tag and upgrade deliberately.
