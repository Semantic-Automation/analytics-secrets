# Analytics Secrets

Shared **post-quantum E2EE crypto library** for the analytics hub-and-spoke
stack. **Public by design** (Kerckhoffs): the security rests entirely on the
private keys, never on algorithm secrecy. It contains no keys, no secrets, and
no credentials — only the crypto construction.

## What it does

- **Hybrid post-quantum envelopes:** ML-KEM-768 + X25519 → HKDF-SHA256 →
  AES-256-GCM, per-message ephemeral keys → forward secrecy and
  harvest-now/decrypt-later resistance.
- **ML-DSA-65 request signing** with canonical JSON, timestamp freshness, and
  replay protection.
- **Signed manifests** (ops-signed entity lists with TTL) + a single pinned
  trust anchor — no TOFU on key distribution.
- **Key providers:** file / env / registry / boot (keyhub-released, RAM-only,
  mlock'd, wiped on shutdown).
- **Memory hygiene:** mlock, wipe, no core dumps.

## Architecture

The library is the shared crypto layer of a hub-and-spoke analytics system:

```
app ──► server (encryptor) ──► content-blind proxy ──► spoke (decryptor) ──► llama
          sign + fan-out           (routing only)        verify sig vs registry
```

Each edge imports this library; no edge trusts the transport, only the
envelopes and the registry. Consumed by `analytics-client`, `analytics-hub`,
`analytics-edge`, and `analytics-spoke`. See
[docs/ONBOARDING.md](docs/ONBOARDING.md) for install + release notes.

## Install

```bash
pip install "analytics-secrets @ git+https://github.com/Semantic-Automation/analytics-secrets.git@v0.6.0"
```

## Test

```bash
pip install -e ".[dev]"
pytest tests
```

## Release

Tag versions (`v0.6.0`); consumer repos pin the tag.
