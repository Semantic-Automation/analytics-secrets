"""Access-token (JWT) verification against a cached JWKS.

Keycloak (the issuer) signs RS256 tokens the proxy and builder verify
**offline** — JWKS is fetched and cached, never in the request hot path. Unknown
``kid`` triggers a single refresh to survive key rotation.

See ``analytics-wiki/architecture/user-platform/01-contract-token-dpop.md`` §2/§4
and ``11-resource-server-auth.md`` §3.
"""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Callable, Mapping

from joserfc import jwt as _jwt
from joserfc.errors import (
    InvalidKeyIdError,
    JoseError,
    MissingKeyError,
)
from joserfc.jwk import KeySet

from ._errors import AuthError

DEFAULT_ALGS: tuple[str, ...] = ("RS256",)

Fetch = Callable[[str, float], dict]


def _http_fetch(url: str, timeout_s: float) -> dict:
    with urllib.request.urlopen(url, timeout=timeout_s) as resp:
        return json.loads(resp.read())


class JWKSCache:
    """Caches a realm JWKS, refreshing by TTL (and on demand)."""

    def __init__(
        self,
        url: str,
        *,
        ttl_s: float = 300,
        timeout_s: float = 5,
        fetch: Fetch | None = None,
    ):
        self.url = url
        self.ttl_s = ttl_s
        self.timeout_s = timeout_s
        self._fetch = fetch or _http_fetch
        self._key_set: KeySet | None = None
        self._fetched_at = 0.0

    def refresh(self) -> KeySet:
        self._key_set = KeySet.import_key_set(self._fetch(self.url, self.timeout_s))
        self._fetched_at = time.time()
        return self._key_set

    def key_set(self) -> KeySet:
        if self._key_set is None or (time.time() - self._fetched_at) > self.ttl_s:
            return self.refresh()
        return self._key_set


def _audience_ok(aud, audience) -> bool:
    if aud is None:
        return False
    if isinstance(aud, (list, tuple, set)):
        return audience in aud
    return aud == audience


def _claims_ok(claims: Mapping, issuer: str, audience: str, require_dpop: bool) -> dict:
    if claims.get("iss") != issuer:
        raise AuthError("invalid_token", "issuer mismatch")
    if not _audience_ok(claims.get("aud"), audience):
        raise AuthError("invalid_token", "audience mismatch")
    now = time.time()
    exp = claims.get("exp")
    if exp is not None and now > float(exp):
        raise AuthError("invalid_token", "token expired")
    nbf = claims.get("nbf")
    if nbf is not None and now < float(nbf):
        raise AuthError("invalid_token", "token not yet valid")
    if require_dpop:
        cnf = claims.get("cnf")
        if not isinstance(cnf, Mapping) or not cnf.get("jkt"):
            raise AuthError("invalid_token", "token is not DPoP-bound (missing cnf.jkt)")
    return dict(claims)


def decode_token(token: str, key_set, algorithms=DEFAULT_ALGS) -> dict:
    """Decode+verify a JWT; return claims. Raises :class:`AuthError`."""
    try:
        parsed = _jwt.decode(token, key_set, algorithms=list(algorithms))
    except JoseError as exc:
        raise AuthError("invalid_token", f"access token rejected: {exc}")
    return dict(parsed.claims)


def verify_access_token(
    token: str,
    *,
    key_set,
    issuer: str,
    audience: str,
    algorithms=DEFAULT_ALGS,
    require_dpop: bool = True,
) -> dict:
    claims = decode_token(token, key_set, algorithms)
    return _claims_ok(claims, issuer, audience, require_dpop)


class OIDCVerifier:
    """Bundles a :class:`JWKSCache` with claim checks and rotation handling."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str | None = None,
        cache: JWKSCache | None = None,
        algorithms=DEFAULT_ALGS,
        require_dpop: bool = True,
        ttl_s: float = 300,
        fetch: Fetch | None = None,
    ):
        if cache is None:
            if jwks_url is None:
                raise ValueError("provide jwks_url or cache")
            cache = JWKSCache(jwks_url, ttl_s=ttl_s, fetch=fetch)
        self.issuer = issuer
        self.audience = audience
        self.algorithms = tuple(algorithms)
        self.require_dpop = require_dpop
        self.cache = cache

    def verify(self, token: str) -> dict:
        try:
            parsed = _jwt.decode(token, self.cache.key_set(), algorithms=list(self.algorithms))
        except (InvalidKeyIdError, MissingKeyError):
            parsed = _jwt.decode(token, self.cache.refresh(), algorithms=list(self.algorithms))
        except JoseError as exc:
            raise AuthError("invalid_token", f"access token rejected: {exc}")
        return _claims_ok(parsed.claims, self.issuer, self.audience, self.require_dpop)
