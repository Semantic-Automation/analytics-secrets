"""Tests for the human-auth verifier (tokens + DPoP + tier gate)."""

from __future__ import annotations

import time
import uuid

import pytest
from joserfc import jwt
from joserfc.jwk import ECKey, RSAKey

from secretskit import AuthError, dpop, oidc, tiers, user_auth
from secretskit._signing import ReplayGuard

ISS = "https://auth.example/realms/users"
AUD = "analytics-api"
URL = "https://api.example/chat"


def _rsa(kid: str) -> RSAKey:
    key = RSAKey.generate_key(2048, private=True)
    key.ensure_kid()
    key_dict = key.as_dict(private=True)
    key_dict["kid"] = kid
    return RSAKey.import_key(key_dict)


def _jwk(key: RSAKey) -> dict:
    pub = key.as_dict(private=False)
    pub["kid"] = key.kid
    return pub


def _make_token(key: RSAKey, *, jkt=None, sub="user-1", roles=("active",),
                iss=ISS, aud=AUD, exp_delta=300, include_cnf=True) -> str:
    now = int(time.time())
    claims = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "azp": "analytics-sidecar",
        "iat": now,
        "exp": now + exp_delta,
        "jti": uuid.uuid4().hex,
        "realm_access": {"roles": list(roles)},
    }
    if include_cnf:
        claims["cnf"] = {"jkt": jkt}
    return jwt.encode({"alg": "RS256", "kid": key.kid}, claims, key)


def _thumbprint(key: ECKey) -> str:
    return key.thumbprint()


def _make_proof(key: ECKey, *, htm="POST", htu=URL, ath=None, jti=None,
                iat=None, typ="dpop+jwt", jwk=None) -> str:
    payload = {
        "htm": htm,
        "htu": htu,
        "jti": jti or uuid.uuid4().hex,
        "iat": int(time.time()) if iat is None else iat,
    }
    if ath is not None:
        payload["ath"] = ath
    header = {"typ": typ, "alg": "ES256", "jwk": jwk or key.as_dict(private=False)}
    return jwt.encode(header, payload, key)


def _verifier(key: RSAKey, **kwargs) -> oidc.OIDCVerifier:
    jwks = {"keys": [_jwk(key)]}
    return oidc.OIDCVerifier(
        issuer=ISS, audience=AUD, jwks_url="memory", fetch=lambda url, t: jwks, **kwargs
    )


def _verify(token, proof, verifier, **kwargs):
    return user_auth.verify_dpop(
        token=token, proof=proof, method="POST", url=URL, verifier=verifier, **kwargs
    )


def test_happy_path():
    rsa, ec = _rsa("k1"), ECKey.generate_key("P-256", private=True)
    jkt = _thumbprint(ec)
    token = _make_token(rsa, jkt=jkt)
    proof = _make_proof(ec, ath=dpop.access_token_hash(token))
    ident = _verify(token, proof, _verifier(rsa))
    assert ident.user_id == "user-1"
    assert ident.tier == "active"
    assert "active" in ident.roles
    assert ident.jkt == jkt


def test_pending_tier_rejected_with_403():
    rsa, ec = _rsa("k1"), ECKey.generate_key("P-256", private=True)
    token = _make_token(rsa, jkt=_thumbprint(ec), roles=("pending",))
    proof = _make_proof(ec, ath=dpop.access_token_hash(token))
    with pytest.raises(AuthError) as exc:
        _verify(token, proof, _verifier(rsa))
    assert exc.value.error == "pending_approval"
    assert exc.value.status == 403


def test_pending_allowed_when_floor_waived():
    rsa, ec = _rsa("k1"), ECKey.generate_key("P-256", private=True)
    token = _make_token(rsa, jkt=_thumbprint(ec), roles=("pending",))
    proof = _make_proof(ec, ath=dpop.access_token_hash(token))
    ident = _verify(token, proof, _verifier(rsa), require_tier_floor=False)
    assert ident.tier == "pending"


def test_missing_token_and_proof():
    rsa = _rsa("k1")
    with pytest.raises(AuthError) as exc:
        _verify(None, None, _verifier(rsa))
    assert exc.value.error == "invalid_token"


def test_token_without_cnf_rejected():
    rsa, ec = _rsa("k1"), ECKey.generate_key("P-256", private=True)
    token = _make_token(rsa, include_cnf=False)
    proof = _make_proof(ec, ath=dpop.access_token_hash(token))
    with pytest.raises(AuthError) as exc:
        _verify(token, proof, _verifier(rsa))
    assert exc.value.error == "invalid_token"


def test_proof_key_mismatch():
    rsa = _rsa("k1")
    ec_bound = ECKey.generate_key("P-256", private=True)
    ec_other = ECKey.generate_key("P-256", private=True)
    token = _make_token(rsa, jkt=_thumbprint(ec_bound))
    proof = _make_proof(ec_other, ath=dpop.access_token_hash(token))
    with pytest.raises(AuthError) as exc:
        _verify(token, proof, _verifier(rsa))
    assert exc.value.error == "invalid_dpop_proof"


@pytest.mark.parametrize("bad", ["ath", "htm", "htu", "iat_stale", "iat_future"])
def test_bad_proof_claims(bad):
    rsa, ec = _rsa("k1"), ECKey.generate_key("P-256", private=True)
    token = _make_token(rsa, jkt=_thumbprint(ec))
    ath = dpop.access_token_hash(token)
    kwargs = {}
    if bad == "ath":
        kwargs["ath"] = dpop.access_token_hash("other-token")
    elif bad == "htm":
        kwargs["htm"] = "GET"
    elif bad == "htu":
        kwargs["htu"] = "https://api.example/other"
    elif bad == "iat_stale":
        kwargs["iat"] = int(time.time()) - 3600
    elif bad == "iat_future":
        kwargs["iat"] = int(time.time()) + 3600
    proof_kwargs = {"ath": ath, **kwargs}
    proof = _make_proof(ec, **proof_kwargs)
    with pytest.raises(AuthError) as exc:
        _verify(token, proof, _verifier(rsa))
    assert exc.value.error == "invalid_dpop_proof"


def test_replay_rejected():
    rsa, ec = _rsa("k1"), ECKey.generate_key("P-256", private=True)
    token = _make_token(rsa, jkt=_thumbprint(ec))
    jti = uuid.uuid4().hex
    proof = _make_proof(ec, ath=dpop.access_token_hash(token), jti=jti)
    guard = ReplayGuard()
    _verify(token, proof, _verifier(rsa), replay_guard=guard)
    with pytest.raises(AuthError) as exc:
        _verify(token, proof, _verifier(rsa), replay_guard=guard)
    assert "replay" in exc.value.description


def test_expired_token():
    rsa, ec = _rsa("k1"), ECKey.generate_key("P-256", private=True)
    token = _make_token(rsa, jkt=_thumbprint(ec), exp_delta=-10)
    proof = _make_proof(ec, ath=dpop.access_token_hash(token))
    with pytest.raises(AuthError) as exc:
        _verify(token, proof, _verifier(rsa))
    assert exc.value.error == "invalid_token"


def test_wrong_issuer_and_audience():
    rsa, ec = _rsa("k1"), ECKey.generate_key("P-256", private=True)
    for kwargs in ({"iss": "https://evil/realms/users"}, {"aud": "other-api"}):
        token = _make_token(rsa, jkt=_thumbprint(ec), **kwargs)
        proof = _make_proof(ec, ath=dpop.access_token_hash(token))
        with pytest.raises(AuthError) as exc:
            _verify(token, proof, _verifier(rsa))
        assert exc.value.error == "invalid_token"


def test_bad_signature():
    signer, other, ec = _rsa("k1"), _rsa("k1"), ECKey.generate_key("P-256", private=True)
    token = _make_token(other, jkt=_thumbprint(ec))
    proof = _make_proof(ec, ath=dpop.access_token_hash(token))
    with pytest.raises(AuthError) as exc:
        _verify(token, proof, _verifier(signer))
    assert exc.value.error == "invalid_token"


def test_jwks_rotation_refresh():
    current = {"key": _rsa("k1")}
    jwks = lambda url, t: {"keys": [_jwk(current["key"])]}  # noqa: E731
    verifier = oidc.OIDCVerifier(issuer=ISS, audience=AUD, jwks_url="memory", fetch=jwks)
    ec = ECKey.generate_key("P-256", private=True)
    # warm the cache with k1
    t1 = _make_token(current["key"], jkt=_thumbprint(ec))
    _verify(t1, _make_proof(ec, ath=dpop.access_token_hash(t1)), verifier)
    # rotate to k2; the token's kid is unknown until the cache refreshes
    current["key"] = _rsa("k2")
    t2 = _make_token(current["key"], jkt=_thumbprint(ec))
    ident = _verify(t2, _make_proof(ec, ath=dpop.access_token_hash(t2)), verifier)
    assert ident.user_id == "user-1"


def test_builder_bundle():
    rsa, ec = _rsa("k1"), ECKey.generate_key("P-256", private=True)
    token = _make_token(rsa, jkt=_thumbprint(ec))
    proof = _make_proof(ec, ath=dpop.access_token_hash(token))
    ident = user_auth.verify_bundle(
        {"access_token": token, "dpop_proof": proof},
        method="POST", url=URL, verifier=_verifier(rsa),
    )
    assert ident.tier == "active"


def test_extract_bearer_case_insensitive():
    token, proof = user_auth.extract_bearer(
        {"AUTHORIZATION": "DPoP abc.def.ghi", "Dpop": "proof.jwt.here"}
    )
    assert token == "abc.def.ghi"
    assert proof == "proof.jwt.here"


def test_canonical_url():
    assert dpop.canonical_url("HTTPS://API.Example:443/chat?x=1") == "https://api.example/chat?x=1"
    assert dpop.canonical_url("http://api.example:80") == "http://api.example/"
    assert dpop.canonical_url("https://api.example:8443/chat#frag") == "https://api.example:8443/chat"


def test_tier_helpers():
    assert tiers.tier_of({"realm_access": {"roles": ["pending"]}}) == "pending"
    assert tiers.tier_of({"realm_access": {"roles": ["active", "pending"]}}) == "active"
    assert tiers.tier_of({"realm_access": {"roles": []}}) is None
    assert tiers.has_tier_floor({"realm_access": {"roles": ["active"]}})
    assert not tiers.has_tier_floor({"realm_access": {"roles": ["pending"]}})
