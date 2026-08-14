"""Clean-room onboarding tests: ensure_keyring, wrap/unwrap, envelope key release."""

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization

from secretskit import (
    BootKeyProvider,
    FileKeyProvider,
    RegistryUserProvider,
    ensure_keyring,
    generate_identity,
    load_peer_public,
    unwrap_bytes,
    wrap_bytes,
)
from secretskit._manifest import generate_signing_key, load_signing_key

_PEM = serialization.Encoding.PEM
_SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
_PKCS8 = serialization.PrivateFormat.PKCS8


def _b64_pem(key, public=True):
    if public:
        return base64.b64encode(key.public_bytes(_PEM, _SPKI)).decode()
    return base64.b64encode(key.private_bytes(_PEM, _PKCS8, serialization.NoEncryption())).decode()


def _pem_bytes(key, public=True):
    return (_b64_pem(key, public=public)).encode()


def _peer_for(identity):
    return load_peer_public(
        peer_id=identity.id,
        kem_pub=identity.kem.public_key().public_bytes(_PEM, _SPKI),
        x_pub=identity.x.public_key().public_bytes(_PEM, _SPKI),
    )


def test_generates_identity_when_empty(tmp_path):
    kd = tmp_path / "keyring"
    ensure_keyring(kd, "server-1", signing=True)
    assert (kd / "server-1.kem.pem").exists()
    assert (kd / "server-1.x.pem").exists()
    assert (kd / "server-1.sign.pem").exists()
    ident = FileKeyProvider(kd, "server-1").identity_keys()
    assert ident.id == "server-1"


def test_idempotent_no_overwrite(tmp_path):
    kd = tmp_path / "keyring"
    ensure_keyring(kd, "spoke-1", signing=True)
    first_kem = (kd / "spoke-1.kem.pem").read_bytes()
    ensure_keyring(kd, "spoke-1", signing=True)
    assert (kd / "spoke-1.kem.pem").read_bytes() == first_kem


def test_signing_optional(tmp_path):
    kd = tmp_path / "keyring"
    ensure_keyring(kd, "logsink-1", signing=False)
    assert (kd / "logsink-1.kem.pem").exists()
    assert not (kd / "logsink-1.sign.pem").exists()


def test_generated_signing_key_loads(tmp_path):
    kd = tmp_path / "keyring"
    ensure_keyring(kd, "server-1", signing=True)
    key = load_signing_key((kd / "server-1.sign.pem").read_bytes())
    assert key.public_key() is not None


def test_wrap_unwrap_roundtrip():
    spoke = generate_identity("spoke-1")
    env = wrap_bytes(_peer_for(spoke), b"secret-identity")
    assert unwrap_bytes(spoke, env) == b"secret-identity"


def test_wrap_unwrap_wrong_key_fails():
    spoke = generate_identity("spoke-1")
    other = generate_identity("spoke-1")
    env = wrap_bytes(_peer_for(spoke), b"secret")
    with pytest.raises(Exception):
        unwrap_bytes(other, env)


def _fake_registry_peers():
    return RegistryUserProvider(
        "http://reg:8085", token="reg-tok",
        fetcher=lambda u, t: json.dumps({"user_id": "u", "signing_pub": "", "kem_pub": "", "x_pub": ""}).encode(),
    )


def test_boot_provider_envelope_release(tmp_path):
    """BootKeyProvider unwraps an ML-KEM release envelope with its enrollment key."""
    spoke = generate_identity("spoke-1")
    signing = generate_signing_key()
    enroll_kd = tmp_path / "enroll"
    ensure_keyring(enroll_kd, "spoke-1")  # the spoke's enrollment private key

    payload = json.dumps({
        "id": "spoke-1",
        "kem_pem": _b64_pem(spoke.kem, public=False),
        "x_pem": _b64_pem(spoke.x, public=False),
        "sign_pem": _b64_pem(signing, public=False),
    }).encode()
    enroll_ident = FileKeyProvider(enroll_kd, "spoke-1").identity_keys()
    envelope = base64.b64encode(wrap_bytes(_peer_for(enroll_ident), payload)).decode()

    def hub(url, token):
        assert token == "hub-tok"
        return json.dumps({"id": "spoke-1", "envelope": envelope}).encode()

    provider = BootKeyProvider(
        "http://keyhub:8087", "hub-tok", "spoke-1",
        peers=_fake_registry_peers(), fetcher=hub, enroll_keydir=str(enroll_kd),
    )
    assert provider.identity_keys().id == "spoke-1"
    assert provider.signing_key().public_key() is not None


def test_boot_provider_envelope_without_enroll_key_fails(tmp_path):
    def hub(url, token):
        return json.dumps({"id": "spoke-1", "envelope": "AAAB"}).encode()

    provider = BootKeyProvider(
        "http://keyhub:8087", "hub-tok", "spoke-1",
        peers=_fake_registry_peers(), fetcher=hub,  # no enroll_keydir
    )
    with pytest.raises(Exception):
        provider.identity_keys()


def test_boot_provider_plaintext_release_without_enroll(tmp_path):
    """Without an enrollment key, the plaintext release path still works (compat)."""
    spoke = generate_identity("spoke-1")
    signing = generate_signing_key()

    def hub(url, token):
        return json.dumps({
            "id": "spoke-1",
            "kem_pem": _b64_pem(spoke.kem, public=False),
            "x_pem": _b64_pem(spoke.x, public=False),
            "sign_pem": _b64_pem(signing, public=False),
        }).encode()

    provider = BootKeyProvider(
        "http://keyhub:8087", "hub-tok", "spoke-1",
        peers=_fake_registry_peers(), fetcher=hub,
    )
    assert provider.identity_keys().id == "spoke-1"
