# Analytics Secrets

Shared **post-quantum crypto library** for the Semantic-Automation analytics
stack. **Public by design** (Kerckhoffs): the security rests entirely on the
private keys, never on algorithm secrecy. The library contains no keys, no
secrets, and no credentials — only the crypto construction and the protocols
that use it. It is pip-installed by every service repo (`analytics-client`,
`analytics-hub`, `analytics-edge`, `analytics-builder`, `analytics-spoke`);
`analytics-tunnels` deliberately does **not** depend on it (transport-only, no
crypto — auth is injected by consumers).

## What it does

- **Hybrid post-quantum envelopes:** ML-KEM-768 + X25519 → HKDF-SHA256 →
  AES-256-GCM, with per-message ephemeral keys → forward secrecy and
  harvest-now/decrypt-later resistance.
- **ML-DSA-65 request signing:** canonical JSON + timestamp freshness + replay
  window + seen `request_id` tracking (`secretskit.signing`).
- **Transport auth:** sign each HTTP request with the caller's ML-DSA-65 key
  (identity + timestamp + signature headers) instead of static bearer tokens —
  used for manifest fetches and path-scoped proxy endpoints
  (`secretskit.transport_auth`).
- **Role-split signed manifests:** ops-signed, **role-tagged** entity lists
  (`role=builder` / `role=llm` / clients), each with a **monotonic version** and
  TTL freshness, verified against a single pre-provisioned ML-DSA-65 anchor — no
  TOFU on key distribution (`secretskit.manifest`, `analytics-manifest` CLI).
- **Key providers:** `FileKeyProvider` / `EnvKeyProvider` (dev), the
  manifest-backed `RegistryKeyProvider` (peers + roles + per-peer signing keys
  from a signed manifest), `RegistryUserProvider` (user registry), and
  `BootKeyProvider` — a keyhub **boot release** held RAM-only (mlock'd, wiped on
  shutdown) that also hands over the hub-released registry anchor, the
  cloudflared tunnel token, and the acceptor hostname.
- **Logging edge** (`secretskit.log_edge`): E2EE capture of plaintext
  prompt/response/endpoint records to the trusted logger — the only party that
  materialises plaintext.
- **Memory hygiene:** mlock, wipe, no core dumps.

## Architecture

Every edge imports this library; no edge trusts the transport — only the
envelopes, signatures, and the pinned manifest anchor.

```
app (E2EE shim) ──► content-blind proxy ──► builder ──► mesh ──► spoke ──► llama
 sign + fan-out        transport-auth        prompt IP +       verify a
                       only, blind to        LLM fan-out       role=builder
                       spokes                + ALL logging     signer
```

## Install

```bash
pip install "analytics-secrets @ git+https://github.com/Semantic-Automation/analytics-secrets.git@v0.7.10"
```

Consumer Containerfiles pin via `SECRETS_PIN` (e.g. `ARG SECRETS_PIN=v0.7.8` in
`analytics-spoke` / `analytics-hub`) and upgrade deliberately.

## Test

```bash
pip install -e ".[dev]"
pytest tests
```

## Release

Bump `version` in `pyproject.toml` **and** `secretskit.__version__`, tag
(`v0.7.10`), and let consumers bump their pin when they want the change.
