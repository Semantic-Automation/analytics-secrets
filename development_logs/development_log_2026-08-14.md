# Development Log — 2026-08-14

Session title for analytics-secrets: initial split from the monorepo + the
hardening that motivated it (key hygiene, token-set auth, user-id SSRF guard).

This session's goals, in order:
1. Extract the shared PQ crypto library into its own repo.
2. Carry over the hardening that lives in this library (H3 perms/mlock,
   H5 overlap token-sets, H8 user-id validation).

---

## 1. Split from the monorepo

Created as a standalone repo from `analyticsproject@8b1a19e` (main), tagged
`v0.6.0`, published **public** under `Semantic-Automation`. Public by design
(Kerckhoffs): the library holds no keys or secrets; security rests on the
private keys only. See `docs/repo-split.md` in analytics-hub for the full split
plan.

## 2. Key hygiene (H3) — very detailed (no dedicated doc)

- `_keys.py`: added `_write_private_pem()` — writes private-key PEMs with mode
  `0600` set **at open time** (never world-readable transiently), plus a
  belt-and-braces `chmod`. `save_identity()` and `ensure_keyring()` use it.
- `FileKeyProvider._load_identity()` now **mlock-pins** the raw `kem`/`x` PEM
  bytes into RAM (`_hygiene.mlock_memory`) so a swap-out / core-dump can't spill
  the decrypt keys to disk; `_wipe_pinned()` zeroes them on shutdown.
- **Landmine:** mlock is a no-op in rootless-podman / constrained envs
  (`CAP_IPC_LOCK` absent → `errno 12`); it engages only on hosts with the
  capability — best-effort by design, mirroring `BootKeyProvider`.
- Tests: `test_saved_keys_are_owner_only`, `test_ensure_keyring_signing_owner_only`.

## 3. Overlap token-set auth (H5) — summarized, linked

Verifiers accept a token set (current + previous) so credentials can rotate
with zero downtime. See `docs/network-hardening.md` §H5 (hub) for the full
rotation design. The library side is `valid_user_id()` + `_fetch_user` guard.

## 4. User-id SSRF guard (H8) — very detailed (no dedicated doc)

`RegistryUserProvider._fetch_user` now rejects any `user_id` that fails
`valid_user_id()` (regex `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`) **before** a URL
is built or a fetch is attempted — closing an authenticated SSRF + user-
enumeration vector through the proxy's `X-LLM-Metadata` verification.
Tests: `test_invalid_user_id_never_fetches` (asserts the fetcher is never
invoked), `test_valid_user_id_predicate`.

---

## Files Changed

- `src/secretskit/_keys.py` — `_write_private_pem`, mlock pinning, `valid_user_id`, `_fetch_user` guard
- `src/secretskit/__init__.py` — export `valid_user_id`
- `tests/test_keys.py`, `tests/test_registry_user_provider.py` — +4 tests

## Notes / Follow-ups

- Versioning: future changes bump to `v0.7.0` etc. with a CHANGELOG; consumers
  pin the tag via `SECRETS_PIN` in their Containerfiles.
- No `docs/` in this repo by design — the architectural context lives in the
  consuming repos' docs (hub carries the master hardening/ops docs).

## Session wrap

The shared crypto library is extracted, public, and carries the H3/H5/H8
hardening that makes it safe to consume across all four service repos.
