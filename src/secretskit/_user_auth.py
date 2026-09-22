"""Unified human-request verification: token + DPoP + tier gate.

One entry point used by both legs (``11-resource-server-auth.md`` §6): the proxy
passes headers, the builder passes the auth bundle it decrypted from inside the
E2EE envelope. Either way the sequence is identical.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from . import _dpop
from ._errors import AuthError
from ._oidc import OIDCVerifier
from ._tiers import has_tier_floor, realm_roles, tier_of


@dataclass(frozen=True)
class VerifiedIdentity:
    """The verified caller. ``user_id`` (``sub``) is used downstream."""

    user_id: str
    tier: str | None
    roles: frozenset[str]
    jkt: str
    jti: str
    claims: dict


def _get(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def builder_htu(builder_id: str, path: str) -> str:
    """The synthetic ``htu`` for the builder leg of a request.

    The builder is dial-out with no public URL, so the client and builder agree
    on a logical URI derived from the builder id + request path. Both sides must
    call this helper so the DPoP ``htu`` matches.
    """
    return f"https://builder/{builder_id}/{path.lstrip('/')}"


def extract_bearer(headers: Mapping[str, str]) -> tuple[str | None, str | None]:
    """Pull ``(access_token, dpop_proof)`` from ``Authorization: DPoP`` + ``DPoP``."""
    auth = _get(headers, "authorization") or ""
    scheme, _, token = auth.partition(" ")
    token = token if scheme.lower() == "dpop" and token else None
    return token, _get(headers, "dpop")


def verify_dpop(
    *,
    token: str | None,
    proof: str | None,
    method: str,
    url: str,
    verifier: OIDCVerifier,
    replay_guard=None,
    nonce: str | None = None,
    require_tier_floor: bool = True,
    allowed_algs=("ES256",),
    max_age_s: int = 30,
    skew_s: int = 30,
) -> VerifiedIdentity:
    """Verify an access token + its DPoP proof and enforce the tier floor.

    Raises :class:`AuthError` (carrying the HTTP status + ``WWW-Authenticate``
    challenge) on any failure.
    """
    if not token:
        raise AuthError("invalid_token", "missing access token")

    claims = verifier.verify(token)

    bound_jkt = (claims.get("cnf") or {}).get("jkt")
    proof_result = _dpop.verify(
        proof or "",
        method=method,
        url=url,
        access_token=token,
        replay_guard=replay_guard,
        expected_nonce=nonce,
        allowed_algs=allowed_algs,
        max_age_s=max_age_s,
        skew_s=skew_s,
    )
    if proof_result.jkt != bound_jkt:
        raise AuthError("invalid_dpop_proof", "proof key does not match token cnf.jkt")

    if require_tier_floor and not has_tier_floor(claims):
        raise AuthError("pending_approval", "account is not yet approved", status=403)

    return VerifiedIdentity(
        user_id=str(claims.get("sub", "")),
        tier=tier_of(claims),
        roles=realm_roles(claims),
        jkt=proof_result.jkt,
        jti=proof_result.jti,
        claims=claims,
    )


def verify_bundle(
    bundle: Mapping,
    *,
    method: str,
    url: str,
    verifier: OIDCVerifier,
    **kwargs,
) -> VerifiedIdentity:
    """Verify the builder-leg auth bundle (``11`` §8).

    The bundle rides inside the decrypted E2EE envelope and carries the access
    token and a builder-bound DPoP proof.
    """
    token = bundle.get("access_token")
    proof = bundle.get("dpop_proof") or bundle.get("builder_dpop_proof")
    return verify_dpop(
        token=token, proof=proof, method=method, url=url, verifier=verifier, **kwargs
    )
