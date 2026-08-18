"""Overlay-join handoff tests (EnrollFront underlay)."""

import pytest
from cryptography.hazmat.primitives import serialization

from secretskit import generate_identity, load_peer_public
from secretskit._errors import DecryptError
from secretskit._handoff import build_handoff, unwrap_handoff
from secretskit._manifest import generate_signing_key

_PEM = serialization.Encoding.PEM
_SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


def _peer_for(identity):
    return load_peer_public(
        peer_id=identity.id,
        kem_pub=identity.kem.public_key().public_bytes(_PEM, _SPKI),
        x_pub=identity.x.public_key().public_bytes(_PEM, _SPKI),
    )


def _roundtrip(spoke_id="spoke-9", ttl_s=900, expires_delta=None):
    spoke = generate_identity(spoke_id)          # enrollment keypair (at rest on spoke)
    ops = generate_signing_key()                  # ops ML-DSA key (anchor public half)
    handoff = build_handoff(
        spoke_id=spoke_id,
        overlay_url="https://overlay:18080",
        preauth_key="hskey-auth-XXXX",
        ca_cert_pem="-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
        dns_search="ts.analytics.internal",
        ops_signing_key=ops,
        enrollment_peer=_peer_for(spoke),
        ttl_s=ttl_s,
    )
    if expires_delta is not None:
        import json
        from secretskit._handoff import _api, _canonical, _now_iso, _parse_utc
        from datetime import timedelta

        # not used in normal flow; kept for future expiry tests
        return handoff
    doc = unwrap_handoff(
        handoff,
        enrollment_identity=spoke,
        ops_verify_key=ops.public_key(),
        expected_spoke_id=spoke_id,
        max_age_s=ttl_s,
    )
    return handoff, doc, spoke, ops


def test_handoff_roundtrip():
    _, doc, _, _ = _roundtrip()
    assert doc["spoke_id"] == "spoke-9"
    assert doc["overlay"]["headscale_url"] == "https://overlay:18080"
    assert doc["overlay"]["preauth_key"] == "hskey-auth-XXXX"
    assert doc["overlay"]["dns_search"] == "ts.analytics.internal"
    import base64

    ca = base64.b64decode(doc["overlay"]["ca_cert_pem"]).decode()
    assert "BEGIN CERTIFICATE" in ca


def test_handoff_wrong_recipient_fails():
    spoke = generate_identity("spoke-9")
    attacker = generate_identity("spoke-9")
    ops = generate_signing_key()
    handoff = build_handoff(
        spoke_id="spoke-9", overlay_url="u", preauth_key="k",
        ca_cert_pem="c", dns_search="d", ops_signing_key=ops,
        enrollment_peer=_peer_for(spoke),
    )
    with pytest.raises(DecryptError):
        unwrap_handoff(
            handoff, enrollment_identity=attacker,  # wrong enrollment key
            ops_verify_key=ops.public_key(), expected_spoke_id="spoke-9",
        )


def test_handoff_tampered_signature_fails():
    spoke = generate_identity("spoke-9")
    ops = generate_signing_key()
    handoff = build_handoff(
        spoke_id="spoke-9", overlay_url="u", preauth_key="k",
        ca_cert_pem="c", dns_search="d", ops_signing_key=ops,
        enrollment_peer=_peer_for(spoke),
    )
    # flip a byte in the envelope (would change plaintext -> sig mismatch)
    import base64

    env = bytearray(base64.b64decode(handoff["envelope"]))
    env[10] ^= 0xFF
    handoff["envelope"] = base64.b64encode(bytes(env)).decode()
    with pytest.raises(DecryptError):
        unwrap_handoff(
            handoff, enrollment_identity=spoke,
            ops_verify_key=ops.public_key(), expected_spoke_id="spoke-9",
        )


def test_handoff_wrong_ops_key_fails():
    spoke = generate_identity("spoke-9")
    ops = generate_signing_key()
    other_ops = generate_signing_key()
    handoff = build_handoff(
        spoke_id="spoke-9", overlay_url="u", preauth_key="k",
        ca_cert_pem="c", dns_search="d", ops_signing_key=ops,
        enrollment_peer=_peer_for(spoke),
    )
    with pytest.raises(DecryptError):
        unwrap_handoff(
            handoff, enrollment_identity=spoke,
            ops_verify_key=other_ops.public_key(),  # not the signing ops key
            expected_spoke_id="spoke-9",
        )


def test_handoff_wrong_spoke_id_fails():
    spoke = generate_identity("spoke-9")
    ops = generate_signing_key()
    handoff = build_handoff(
        spoke_id="spoke-9", overlay_url="u", preauth_key="k",
        ca_cert_pem="c", dns_search="d", ops_signing_key=ops,
        enrollment_peer=_peer_for(spoke),
    )
    with pytest.raises(DecryptError):
        unwrap_handoff(
            handoff, enrollment_identity=spoke,
            ops_verify_key=ops.public_key(), expected_spoke_id="spoke-9-BOGUS",
        )
