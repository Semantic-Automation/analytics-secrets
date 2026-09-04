"""Tests for the signed manifest module."""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from secretskit import _manifest
from secretskit._errors import ConfigurationError


def _entities():
    return {
        "spoke-1": {"kem_pub": base64.b64encode(b"KEM1").decode(), "x_pub": base64.b64encode(b"X1").decode()},
        "spoke-2": {"kem_pub": base64.b64encode(b"KEM2").decode(), "x_pub": base64.b64encode(b"X2").decode()},
    }


def _make(key, *, issued=None, expires=None):
    now = datetime.now(timezone.utc)
    issued = issued or now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = expires or (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return _manifest.sign(_entities(), issued_at=issued, expires_at=expires, signing_key=key)


def test_keypair_roundtrip():
    key = _manifest.generate_signing_key()
    sk_pem = _manifest.serialize_signing_key(key)
    vk_pem = _manifest.serialize_verification_key(key.public_key())
    sk2 = _manifest.load_signing_key(sk_pem)
    vk2 = _manifest.load_verification_key(vk_pem)
    sig = sk2.sign(b"msg")
    vk2.verify(sig, b"msg")
    assert _manifest.serialize_verification_key(sk2.public_key()) == vk_pem


def test_sign_verify_roundtrip():
    key = _manifest.generate_signing_key()
    payload = _manifest.serialize(_make(key))
    doc = _manifest.verify(payload, key.public_key())
    assert set(doc["entities"]) == {"spoke-1", "spoke-2"}
    assert "signature" not in doc


def test_tampered_signature_rejected():
    key = _manifest.generate_signing_key()
    payload = bytearray(_manifest.serialize(_make(key)))
    payload[-1] ^= 0x01  # flip a bit in the signature (or trailing whitespace)
    with pytest.raises(ConfigurationError):
        _manifest.verify(bytes(payload), key.public_key())


def test_tampered_entities_rejected():
    key = _manifest.generate_signing_key()
    doc = _make(key)
    doc["entities"]["spoke-1"]["kem_pub"] = base64.b64encode(b"EVIL").decode()
    payload = _manifest.serialize(doc)
    with pytest.raises(ConfigurationError):
        _manifest.verify(payload, key.public_key())


def test_wrong_key_rejected():
    key = _manifest.generate_signing_key()
    other = _manifest.generate_signing_key()
    payload = _manifest.serialize(_make(key))
    with pytest.raises(ConfigurationError):
        _manifest.verify(payload, other.public_key())


def test_expired_rejected():
    key = _manifest.generate_signing_key()
    past = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = _manifest.serialize(_make(key, expires=past))
    with pytest.raises(ConfigurationError):
        _manifest.verify(payload, key.public_key())


def test_stale_rejected_by_max_age():
    key = _manifest.generate_signing_key()
    old_issued = (datetime.now(timezone.utc) - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = _manifest.serialize(_make(key, issued=old_issued, expires=expires))
    with pytest.raises(ConfigurationError):
        _manifest.verify(payload, key.public_key(), max_age_s=10800)


def test_future_dated_rejected_within_skew():
    key = _manifest.generate_signing_key()
    future = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = _manifest.serialize(_make(key, issued=future))
    with pytest.raises(ConfigurationError):
        _manifest.verify(payload, key.public_key(), skew_s=60)


def test_within_skew_accepted():
    key = _manifest.generate_signing_key()
    future = (datetime.now(timezone.utc) + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = _manifest.serialize(_make(key, issued=future))
    _manifest.verify(payload, key.public_key(), skew_s=60)


def test_missing_signature_rejected():
    key = _manifest.generate_signing_key()
    doc = _make(key)
    del doc["signature"]
    with pytest.raises(ConfigurationError):
        _manifest.verify(_manifest.serialize(doc), key.public_key())


def test_malformed_payload_rejected():
    key = _manifest.generate_signing_key()
    with pytest.raises(ConfigurationError):
        _manifest.verify(b"not json", key.public_key())
    with pytest.raises(ConfigurationError):
        _manifest.verify(b"[1,2,3]", key.public_key())


def test_canonical_stable():
    a = {"b": 1, "a": [3, 1], "c": {"z": 1, "y": 2}}
    b = json.loads(_manifest.canonical(a).decode())
    assert _manifest.canonical(a) == _manifest.canonical(b)
    assert _manifest.canonical(a) == _manifest.canonical(json.loads(json.dumps(a, sort_keys=True)))


def test_version_is_signed_and_readable():
    key = _manifest.generate_signing_key()
    m = _manifest.sign(
        _entities(), issued_at=_make(key)["issued_at"],
        expires_at=_make(key)["expires_at"], signing_key=key, version=7,
    )
    doc = _manifest.verify(_manifest.serialize(m), key.public_key())
    # The monotonic version rides inside the signed payload.
    assert doc["version"] == 7


def test_version_tamper_rejected():
    key = _manifest.generate_signing_key()
    m = _manifest.sign(
        _entities(), issued_at=_make(key)["issued_at"],
        expires_at=_make(key)["expires_at"], signing_key=key, version=7,
    )
    m["version"] = 8  # forged bump — must break the signature
    with pytest.raises(ConfigurationError):
        _manifest.verify(_manifest.serialize(m), key.public_key())
