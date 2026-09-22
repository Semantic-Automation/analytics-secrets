"""DPoP proof verification (RFC 9449).

The only small custom module in the human-auth path: JOSE parsing/signature
verification is delegated to :mod:`joserfc`; the DPoP claim rules (``htm``,
``htu``, ``ath``, freshness, replay) are checked here.

See ``analytics-wiki/architecture/user-platform/01-contract-token-dpop.md`` §5-6
and ``11-resource-server-auth.md`` §4.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

from joserfc import jwt as _jwt
from joserfc.errors import JoseError
from joserfc.jwk import ECKey

from ._errors import AuthError

DEFAULT_ALLOWED_ALGS: tuple[str, ...] = ("ES256",)


@dataclass(frozen=True)
class DPoPProof:
    """A verified DPoP proof. ``jkt`` is the RFC 7638 key thumbprint."""

    jkt: str
    jti: str
    claims: dict


def _err(description: str, error: str = "invalid_dpop_proof") -> AuthError:
    return AuthError(error, description)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def access_token_hash(access_token: str) -> str:
    """The ``ath`` value for ``access_token`` (base64url SHA-256)."""
    return _b64url(hashlib.sha256(access_token.encode("ascii")).digest())


def canonical_url(url: str) -> str:
    """Normalize a URL for ``htu`` comparison.

    Lowercases scheme/host, drops default ports, forces a path, drops the
    fragment. Query is preserved (part of the HTTP target).
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        host = f"{host}:{port}"
    return urlunsplit((scheme, host, parts.path or "/", parts.query, ""))


def verify(
    proof: str,
    *,
    method: str,
    url: str,
    access_token: str | None = None,
    replay_guard=None,
    expected_nonce: str | None = None,
    allowed_algs: Iterable[str] = DEFAULT_ALLOWED_ALGS,
    max_age_s: int = 30,
    skew_s: int = 30,
) -> DPoPProof:
    """Verify a DPoP proof bound to ``method`` + ``url`` (and ``access_token``).

    Raises :class:`AuthError` (``invalid_dpop_proof``) on any failure. The
    proof is a JWT; its embedded ``jwk`` is the verification key.
    """
    algs = list(allowed_algs)
    if not proof:
        raise _err("missing DPoP proof")

    try:
        header = json.loads(_b64url_decode(proof.split(".")[0]))
    except (ValueError, UnicodeDecodeError, IndexError):
        raise _err("malformed DPoP proof")
    if not isinstance(header, dict):
        raise _err("malformed DPoP proof header")
    if header.get("typ") != "dpop+jwt":
        raise _err("proof typ must be dpop+jwt")
    if header.get("alg") not in algs:
        raise _err(f"proof alg must be one of {algs}")
    embedded_jwk = header.get("jwk")
    if not isinstance(embedded_jwk, Mapping):
        raise _err("proof missing embedded jwk")

    try:
        key = ECKey.import_key(dict(embedded_jwk))
        token = _jwt.decode(proof, key, algorithms=algs)
    except JoseError as exc:
        raise _err(f"proof signature invalid: {exc}")

    claims = token.claims
    if claims.get("htm") != method:
        raise _err("proof htm does not match request method")
    if canonical_url(str(claims.get("htu", ""))) != canonical_url(url):
        raise _err("proof htu does not match request url")

    iat = claims.get("iat")
    if not isinstance(iat, (int, float)):
        raise _err("proof missing iat")
    now = time.time()
    if iat > now + skew_s:
        raise _err("proof iat is in the future")
    if now - iat > max_age_s:
        raise _err("proof is stale")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise _err("proof missing jti")

    if access_token is not None and claims.get("ath") != access_token_hash(access_token):
        raise _err("proof ath does not match access token")
    if expected_nonce is not None and claims.get("nonce") != expected_nonce:
        raise _err("proof nonce mismatch")

    if replay_guard is not None and not replay_guard.check(jti):
        raise _err("proof jti has been seen (replay)")

    try:
        jkt = key.thumbprint()
    except JoseError as exc:  # pragma: no cover - defensive
        raise _err(f"could not compute jwk thumbprint: {exc}")
    return DPoPProof(jkt=jkt, jti=jti, claims=claims)
