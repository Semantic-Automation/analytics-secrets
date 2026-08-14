"""Tests for ML-DSA-65 request signing and replay protection."""

from datetime import datetime, timedelta, timezone

import pytest

from secretskit import _signing
from secretskit._errors import DecryptError
from secretskit._manifest import generate_signing_key


def test_sign_verify_roundtrip():
    key = generate_signing_key()
    signed = _signing.sign(b"total revenue per product", key, user_id="user-1")
    out = _signing.verify(signed, key.public_key())
    assert out["user_id"] == "user-1"
    assert out["data"] == b"total revenue per product"
    assert out["request_id"]


def test_unique_request_ids():
    key = generate_signing_key()
    s1 = _signing.verify(_signing.sign(b"a", key, user_id="u"), key.public_key())
    s2 = _signing.verify(_signing.sign(b"a", key, user_id="u"), key.public_key())
    assert s1["request_id"] != s2["request_id"]


def test_explicit_request_id():
    key = generate_signing_key()
    signed = _signing.sign(b"x", key, user_id="u", request_id="fixed-1")
    out = _signing.verify(signed, key.public_key())
    assert out["request_id"] == "fixed-1"


def test_wrong_key_rejected():
    key = generate_signing_key()
    other = generate_signing_key()
    signed = _signing.sign(b"secret", key, user_id="u")
    with pytest.raises(DecryptError):
        _signing.verify(signed, other.public_key())


def test_tampered_data_rejected():
    key = generate_signing_key()
    signed = bytearray(_signing.sign(b"secret", key, user_id="u"))
    signed[-1] ^= 0x01  # flip a byte in the base64 signature
    with pytest.raises(DecryptError):
        _signing.verify(bytes(signed), key.public_key())


def test_wrong_user_signature_rejected():
    key = generate_signing_key()
    other = generate_signing_key()
    signed = _signing.sign(b"secret", other, user_id="u")  # signed by a different key
    with pytest.raises(DecryptError):
        _signing.verify(signed, key.public_key())


def test_stale_rejected():
    key = generate_signing_key()
    old = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    signed = _signing.sign(b"secret", key, user_id="u", timestamp=old)
    with pytest.raises(DecryptError):
        _signing.verify(signed, key.public_key(), max_age_s=300)


def test_future_timestamp_rejected():
    key = generate_signing_key()
    future = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    signed = _signing.sign(b"secret", key, user_id="u", timestamp=future)
    with pytest.raises(DecryptError):
        _signing.verify(signed, key.public_key(), skew_s=60)


def test_malformed_payload_rejected():
    key = generate_signing_key()
    with pytest.raises(DecryptError):
        _signing.verify(b"garbage", key.public_key())


def test_replay_guard():
    guard = _signing.ReplayGuard(ttl_s=100)
    assert guard.check("req-1")
    assert not guard.check("req-1")
    assert guard.check("req-2")
    # expired entries are pruned and can repeat
    assert guard.check("req-old", now=1000.0)
    assert not guard.check("req-old", now=1000.0)
    assert guard.check("req-old", now=1200.0)  # outside ttl (ttl 100)
