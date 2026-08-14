"""Public API tests: roundtrips, wrong-key isolation, tamper, AAD."""

import json
import os

import pytest

from secretskit import (
    DecryptError,
    Decryptor,
    Encryptor,
    FileKeyProvider,
    UnknownPeerError,
    generate_identity,
    save_identity,
    save_peer,
)


@pytest.fixture()
def keyrings(tmp_path):
    """Hub and spoke keyrings built from the SAME keypairs."""
    hub_dir = tmp_path / "hub"
    spoke_dir = tmp_path / "spoke"
    hub = generate_identity("hub")
    spoke = generate_identity("spoke-1")
    save_identity(hub, hub_dir)
    save_peer(spoke, hub_dir)
    save_identity(spoke, spoke_dir)
    save_peer(hub, spoke_dir)
    return hub_dir, spoke_dir


@pytest.fixture()
def hub_keyring(keyrings):
    return keyrings[0]


@pytest.fixture()
def spoke_keyring(keyrings):
    return keyrings[1]


@pytest.fixture()
def other_keyring(tmp_path):
    """A third party that is NOT a peer of 'hub'."""
    keydir = tmp_path / "other"
    other = generate_identity("other")
    save_identity(other, keydir)
    return keydir


def make_enc(hub_keyring):
    return Encryptor(provider=FileKeyProvider(hub_keyring, "hub"))


def make_dec(spoke_keyring):
    return Decryptor(provider=FileKeyProvider(spoke_keyring, "spoke-1"))


def test_roundtrip_str(hub_keyring, spoke_keyring):
    enc, dec = make_enc(hub_keyring), make_dec(spoke_keyring)
    blob = enc.encrypt({"prompt": "total revenue per product category"})
    assert isinstance(blob, bytes)
    assert dec.decrypt(blob) == {"prompt": "total revenue per product category"}


def test_roundtrip_bytes_rejected(hub_keyring, spoke_keyring):
    enc = make_enc(hub_keyring)
    with pytest.raises(TypeError):
        enc.encrypt(b"raw bytes")
    with pytest.raises(TypeError):
        enc.encrypt({"bad": b"nested bytes"})


def test_roundtrip_non_serialisable_rejected(hub_keyring):
    enc = make_enc(hub_keyring)
    with pytest.raises(TypeError):
        enc.encrypt(object())


def test_roundtrip_json(hub_keyring, spoke_keyring):
    enc, dec = make_enc(hub_keyring), make_dec(spoke_keyring)
    payload = {"question": "total revenue", "tables": [{"name": "orders", "rows": 10}]}
    blob = enc.encrypt(payload)
    assert dec.decrypt(blob) == payload


def test_roundtrip_scalar_json_types(hub_keyring, spoke_keyring):
    enc, dec = make_enc(hub_keyring), make_dec(spoke_keyring)
    for payload in ([1, 2, 3], {"a": 1}, 42, 3.5, True, None):
        assert dec.decrypt(enc.encrypt(payload)) == payload


def test_explicit_to(hub_keyring, spoke_keyring, tmp_path):
    enc, dec = make_enc(hub_keyring), make_dec(spoke_keyring)
    blob = enc.encrypt("x", to="spoke-1")
    assert dec.decrypt(blob) == "x"


def test_unknown_peer(hub_keyring):
    enc = make_enc(hub_keyring)
    with pytest.raises(UnknownPeerError):
        enc.encrypt("x", to="nope")


def test_wrong_key_cannot_decrypt(hub_keyring, other_keyring):
    enc = make_enc(hub_keyring)
    blob = enc.encrypt("secret prompt")
    evil = Decryptor(provider=FileKeyProvider(other_keyring, "other"))
    with pytest.raises(DecryptError):
        evil.decrypt(blob)


def test_tamper_detected(hub_keyring, spoke_keyring):
    enc, dec = make_enc(hub_keyring), make_dec(spoke_keyring)
    blob = bytearray(enc.encrypt("secret prompt"))
    blob[-1] ^= 0x01
    with pytest.raises(DecryptError):
        dec.decrypt(bytes(blob))


def test_aad_mismatch_fails(hub_keyring, spoke_keyring):
    enc, dec = make_enc(hub_keyring), make_dec(spoke_keyring)
    blob = enc.encrypt("secret", aad=b"request-123")
    assert dec.decrypt(blob, aad=b"request-123") == "secret"
    with pytest.raises(DecryptError):
        dec.decrypt(blob, aad=b"request-456")


def test_ambiguous_recipient(tmp_path):
    keydir = tmp_path / "hub"
    hub = generate_identity("hub")
    a = generate_identity("a")
    b = generate_identity("b")
    save_identity(hub, keydir)
    save_peer(a, keydir)
    save_peer(b, keydir)
    enc = Encryptor(provider=FileKeyProvider(keydir, "hub"))
    with pytest.raises(Exception):
        enc.encrypt("x")  # must pass 'to' with 2+ peers


def test_peers_and_identity(hub_keyring):
    enc = make_enc(hub_keyring)
    assert enc.identity == "hub"
    assert enc.peers == ["spoke-1"]


def test_env_provider_roundtrip(hub_keyring, spoke_keyring):
    import base64

    from secretskit import EnvKeyProvider

    hub = FileKeyProvider(hub_keyring, "hub").identity_keys()
    spoke = FileKeyProvider(spoke_keyring, "spoke-1").identity_keys()
    # env provider stands in for the HUB side: hub's private keys, spoke peer
    enc_env = Encryptor(provider=EnvKeyProvider(
        identity="hub",
        kem_private_pem=_b64_priv(hub.kem),
        x_private_pem=_b64_priv(hub.x),
        peers={
            "spoke-1": {
                "kem_pub": _b64(spoke.kem.public_key()),
                "x_pub": _b64(spoke.x.public_key()),
            }
        },
    ))
    blob = enc_env.encrypt("hello from env provider")
    dec_file = make_dec(spoke_keyring)
    assert dec_file.decrypt(blob) == "hello from env provider"


def _b64(key):
    import base64

    from cryptography.hazmat.primitives import serialization

    return base64.b64encode(
        key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode()


def _b64_priv(key):
    import base64

    from cryptography.hazmat.primitives import serialization

    return base64.b64encode(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    ).decode()


def test_config_from_env_file_provider(hub_keyring):
    from secretskit import SecretsConfig

    cfg = SecretsConfig.from_env({"SECRETS_PROVIDER": "file", "SECRETS_KEYDIR": str(hub_keyring), "SECRETS_IDENTITY": "hub"})
    enc = Encryptor(config=cfg)
    assert enc.identity == "hub"
