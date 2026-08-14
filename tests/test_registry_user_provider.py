"""Tests for the user-registry-backed provider (spoke side)."""

import base64
import json
import urllib.error

import pytest

from secretskit import (
    Decryptor,
    Encryptor,
    FileKeyProvider,
    RegistryUserProvider,
    UnknownPeerError,
    generate_identity,
    save_identity,
    save_peer,
    valid_user_id,
)
from secretskit._errors import ConfigurationError
from secretskit._manifest import generate_signing_key, serialize_verification_key


def _b64_pem(key, public=True):
    from cryptography.hazmat.primitives import serialization

    if public:
        return base64.b64encode(
            key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        ).decode()
    return base64.b64encode(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    ).decode()


def _user_record(user_kemx, user_signing):
    return {
        "user_id": "user-1",
        "signing_pub": _b64_pem(user_signing.public_key()),
        "kem_pub": _b64_pem(user_kemx.kem.public_key()),
        "x_pub": _b64_pem(user_kemx.x.public_key()),
    }


def _fetcher(record, *, calls=None):
    def fetcher(url, token):
        if calls is not None:
            calls.append(url)
        if url.endswith("/users/user-1"):
            return json.dumps(record).encode()
        raise urllib.error.HTTPError(url, 404, "Not Found", None, None)

    return fetcher


def test_provider_serves_user_publics():
    spoke = generate_identity("spoke-1")
    user = generate_identity("user-1")
    user_signing = generate_signing_key()
    prov = RegistryUserProvider(
        "http://reg:8085", identity=spoke, token="t", fetcher=_fetcher(_user_record(user, user_signing))
    )
    peer = prov.peer_public("user-1")
    assert peer.id == "user-1"
    prov.signing_public("user-1")  # must not raise
    assert prov.identity_keys().id == "spoke-1"
    assert prov.peer_ids() == ["user-1"]


def test_invalid_user_id_never_fetches():
    """H8 SSRF guard: a hostile user_id must raise before any registry fetch."""
    spoke = generate_identity("spoke-1")
    user = generate_identity("user-1")
    user_signing = generate_signing_key()
    calls = []
    prov = RegistryUserProvider(
        "http://reg:8085", identity=spoke, token="t",
        fetcher=_fetcher(_user_record(user, user_signing), calls=calls),
    )
    for hostile in ("../admin/users", "..%2F..%2Fadmin", "user/../../x", "a b", "user\nx", "😀"):
        with pytest.raises(UnknownPeerError):
            prov.signing_public(hostile)
    assert calls == [], "the registry fetcher must never be invoked for an invalid id"


def test_valid_user_id_predicate():
    for ok in ("server-1", "spoke_2", "a", "user", "UPPER-lower_9", "a" * 64):
        assert valid_user_id(ok), f"{ok!r} should be valid"
    for bad in ("", "..", "../x", "a b", "a/b", "x" * 65, "a\nb", "😀", "-lead", "a..b"):
        assert not valid_user_id(bad), f"{bad!r} should be rejected"


def test_provider_caches_fetches():
    spoke = generate_identity("spoke-1")
    user = generate_identity("user-1")
    user_signing = generate_signing_key()
    calls = []
    prov = RegistryUserProvider(
        "http://reg:8085", identity=spoke, token="t", fetcher=_fetcher(_user_record(user, user_signing), calls=calls)
    )
    prov.peer_public("user-1")
    prov.signing_public("user-1")
    prov.peer_public("user-1")
    assert len(calls) == 1  # cached


def test_unknown_user_raises():
    spoke = generate_identity("spoke-1")
    user = generate_identity("user-1")
    user_signing = generate_signing_key()
    prov = RegistryUserProvider(
        "http://reg:8085", identity=spoke, token="t", fetcher=_fetcher(_user_record(user, user_signing))
    )
    with pytest.raises(UnknownPeerError):
        prov.peer_public("ghost")


def test_missing_identity_raises():
    user = generate_identity("user-1")
    user_signing = generate_signing_key()
    prov = RegistryUserProvider(
        "http://reg:8085", fetcher=_fetcher(_user_record(user, user_signing))
    )
    with pytest.raises(ConfigurationError):
        prov.identity_keys()


def test_full_spoke_roundtrip_via_registry(tmp_path):
    """Hub (user) encrypts to the spoke; the spoke fetches the user's keys
    from the registry to verify + respond, exactly as the wrapper does."""
    spoke = generate_identity("spoke-1")
    user = generate_identity("user-1")
    user_signing = generate_signing_key()

    spoke_prov = RegistryUserProvider(
        "http://reg:8085", identity=spoke, token="t",
        fetcher=_fetcher(_user_record(user, user_signing)),
    )
    spoke_dec = Decryptor(provider=spoke_prov)
    spoke_enc = Encryptor(provider=spoke_prov)

    # hub side: identity = user-1 (kem+x), peer = spoke
    hub_dir = tmp_path / "hub"
    save_identity(user, hub_dir)
    save_peer(spoke, hub_dir)
    hub_enc = Encryptor(provider=FileKeyProvider(hub_dir, "user-1"))
    hub_dec = Decryptor(provider=FileKeyProvider(hub_dir, "user-1"))

    from secretskit import _signing

    request = json.dumps({"prompt": "hello"}).encode()
    signed = _signing.sign(request, user_signing, user_id="user-1")
    envelope = hub_enc.encrypt_chunk(signed, to="spoke-1")

    # spoke verifies + "responds"
    signed_doc = spoke_dec.decrypt_chunk(envelope)
    user_id = _signing.extract_user_id(signed_doc)
    result = _signing.verify(signed_doc, spoke_prov.signing_public(user_id))
    assert result["data"] == request

    response = spoke_enc.encrypt_chunk(b'{"content":"answer"}', to=user_id)
    assert hub_dec.decrypt_chunk(response) == b'{"content":"answer"}'
