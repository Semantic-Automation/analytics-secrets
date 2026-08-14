"""Tests for BootKeyProvider — hub-released, RAM-only spoke identity (§9.4)."""

import base64
import json
import urllib.error

import pytest

from secretskit import (
    BootKeyProvider,
    FileKeyProvider,
    RegistryUserProvider,
    _signing,
    generate_identity,
    save_identity,
    save_peer,
)
from secretskit._manifest import generate_signing_key, serialize_verification_key


def _b64_pem(key, public=False):
    from cryptography.hazmat.primitives import serialization

    if public:
        data = key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        data = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    return base64.b64encode(data).decode("ascii")


class _FakeHub:
    """Serves one identity's keys; asserts the bearer token."""

    def __init__(self, spoke, spoke_signing):
        self._spoke = spoke
        self._signing = spoke_signing

    def __call__(self, url, token):
        assert token == "hub-tok"
        assert url.endswith("/keys/identities/spoke-1")
        return json.dumps({
            "id": "spoke-1",
            "kem_pem": _b64_pem(self._spoke.kem),
            "x_pem": _b64_pem(self._spoke.x),
            "sign_pem": _b64_pem(self._signing),
        }).encode()


class _FakeRegistry:
    def __init__(self, user):
        self._user = user

    def __call__(self, url, token):
        assert token == "reg-tok"
        user_id = url.rsplit("/", 1)[-1]
        if user_id != "user-1":
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
        return json.dumps({
            "user_id": "user-1",
            "signing_pub": _b64_pem(self._user.signing.public_key(), public=True),
            "kem_pub": _b64_pem(self._user.kem.public_key(), public=True),
            "x_pub": _b64_pem(self._user.x.public_key(), public=True),
        }).encode()


def _make_provider(tmp_path):
    spoke = generate_identity("spoke-1")
    spoke_signing = generate_signing_key()
    user = _SimpleUser(generate_identity("user-1"), generate_signing_key())

    peers = RegistryUserProvider(
        "http://reg:8085", token="reg-tok", fetcher=_FakeRegistry(user)
    )
    provider = BootKeyProvider(
        "http://keyhub:8087", "hub-tok", "spoke-1",
        peers=peers, fetcher=_FakeHub(spoke, spoke_signing),
    )
    return provider, spoke, spoke_signing, user


class _SimpleUser:
    def __init__(self, identity, signing):
        self.id = identity.id
        self.kem = identity.kem
        self.x = identity.x
        self.signing = signing


def test_boot_identity_and_signing(tmp_path):
    provider, spoke, spoke_signing, _ = _make_provider(tmp_path)
    ident = provider.identity_keys()
    assert ident.id == "spoke-1"
    # same key material as the hub served (round-trip a signature)
    signed = _signing.sign(b"boot", provider.signing_key(), user_id="spoke-1")
    out = _signing.verify(signed, spoke_signing.public_key())
    assert out["data"] == b"boot"


def test_boot_provider_delegates_peers_and_signing_public(tmp_path):
    provider, _, _, user = _make_provider(tmp_path)
    assert provider.peer_ids() == []
    pub = provider.signing_public("user-1")
    assert pub is not None
    # delegates encryption targets via the same provider the wrapper uses
    assert provider.peer_public("user-1").id == "user-1"


def test_boot_provider_fetches_once_and_wipes(tmp_path):
    hub = None
    calls = {"n": 0}

    def hub_fetch(url, token):
        calls["n"] += 1
        assert hub is not None
        return hub(url, token)

    spoke = generate_identity("spoke-1")
    spoke_signing = generate_signing_key()
    hub = _FakeHub(spoke, spoke_signing)
    user = _SimpleUser(generate_identity("user-1"), generate_signing_key())
    peers = RegistryUserProvider("http://reg:8085", token="reg-tok",
                                 fetcher=_FakeRegistry(user))
    provider = BootKeyProvider("http://keyhub:8087", "hub-tok", "spoke-1",
                               peers=peers, fetcher=hub_fetch)
    provider.identity_keys()
    provider.signing_key()
    assert calls["n"] == 1  # cached after first fetch
    provider.wipe()
    provider.identity_keys()
    assert calls["n"] == 2  # re-fetched after wipe


def test_boot_provider_bad_material(tmp_path):
    def bad(url, token):
        return b"not json"

    user = _SimpleUser(generate_identity("user-1"), generate_signing_key())
    peers = RegistryUserProvider("http://reg:8085", token="reg-tok",
                                 fetcher=_FakeRegistry(user))
    provider = BootKeyProvider("http://keyhub:8087", "hub-tok", "spoke-1",
                               peers=peers, fetcher=bad)
    with pytest.raises(Exception):
        provider.identity_keys()


# ── Onboarding approval handshake ────────────────────────────────────────────

def _err(status, msg):
    import io

    import urllib.error

    return urllib.error.HTTPError("http://keyhub", status, msg, None, io.BytesIO(msg.encode()))


def _envelope_payload(spoke, spoke_signing, enroll_ident):
    from cryptography.hazmat.primitives import serialization

    from secretskit._hybrid import PeerPublic
    from secretskit._api import wrap_bytes

    def _priv_b64(key):
        return base64.b64encode(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )).decode()

    payload = json.dumps({
        "id": "spoke-1",
        "kem_pem": _priv_b64(spoke.kem),
        "x_pem": _priv_b64(spoke.x),
        "sign_pem": _priv_b64(spoke_signing),
    }).encode()
    peer = PeerPublic(
        id="spoke-1",
        kem=enroll_ident.kem.public_key(),
        x=enroll_ident.x.public_key(),
    )
    return wrap_bytes(peer, payload)


class _PendingHub:
    """Returns 403 'pending approval' until approved, then an envelope release."""

    def __init__(self, spoke, spoke_signing, enroll_ident, pending_then_approve):
        self._spoke = spoke
        self._signing = spoke_signing
        self._enroll_ident = enroll_ident
        self._remaining = pending_then_approve

    def __call__(self, url, token):
        assert url.endswith("/keys/identities/spoke-1")
        if self._remaining > 0:
            self._remaining -= 1
            raise _err(403, "enrollment xyz pending approval")
        return json.dumps({
            "id": "spoke-1",
            "envelope": base64.b64encode(_envelope_payload(self._spoke, self._signing, self._enroll_ident)).decode(),
        }).encode()


def test_boot_waits_for_approval_then_unwraps(tmp_path):
    spoke = generate_identity("spoke-1")
    spoke_signing = generate_signing_key()
    enroll = generate_identity("spoke-1")
    user = _SimpleUser(generate_identity("user-1"), generate_signing_key())
    peers = RegistryUserProvider("http://reg:8085", token="reg-tok",
                                 fetcher=_FakeRegistry(user))

    enroll_dir = tmp_path / "enroll"
    from secretskit import save_identity

    save_identity(enroll, enroll_dir)  # the spoke's enrollment keypair

    submitted = []

    def submit(url, body):
        submitted.append((url, body))

    hub = _PendingHub(spoke, spoke_signing, enroll, pending_then_approve=2)
    provider = BootKeyProvider(
        "http://keyhub:8087", "", "spoke-1",
        peers=peers, fetcher=hub, enroll_keydir=str(enroll_dir),
        label="gpu-nyc-01", approve_url="http://approve:8088", backoff_s=0.0,
        submitter=submit,
    )
    ident = provider.identity_keys()
    assert ident.id == "spoke-1"
    assert provider.signing_key() is not None
    # no bearer token was used and the release unwrapped with the enroll key


def test_boot_submits_pending_when_none_then_waits(tmp_path):
    import io

    import urllib.error

    calls = {"n": 0}
    spoke = generate_identity("spoke-1")
    spoke_signing = generate_signing_key()
    enroll = generate_identity("spoke-1")
    user = _SimpleUser(generate_identity("user-1"), generate_signing_key())
    peers = RegistryUserProvider("http://reg:8085", token="reg-tok",
                                 fetcher=_FakeRegistry(user))

    enroll_dir = tmp_path / "enroll"
    from secretskit import save_identity

    save_identity(enroll, enroll_dir)

    def hub(url, token):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _err(403, "no enrollment request for 'spoke-1'; submit one via POST /keys/enrollments")
        if calls["n"] == 2:
            raise _err(403, "enrollment xyz pending approval")
        return json.dumps({
            "id": "spoke-1",
            "envelope": base64.b64encode(_envelope_payload(spoke, spoke_signing, enroll)).decode(),
        }).encode()

    submitted = []

    provider = BootKeyProvider(
        "http://keyhub:8087", "", "spoke-1",
        peers=peers, fetcher=hub, enroll_keydir=str(enroll_dir),
        label="gpu-nyc-01", backoff_s=0.0, submitter=lambda u, b: submitted.append((u, b)),
    )
    ident = provider.identity_keys()
    assert ident.id == "spoke-1"
    assert len(submitted) == 1
    url, body = submitted[0]
    assert url.endswith("/keys/enrollments")
    payload = json.loads(body)
    assert payload["id"] == "spoke-1"
    assert payload["label"] == "gpu-nyc-01"
    assert payload["kem_pub"] and payload["x_pub"]


def test_boot_rejected_fails_fast(tmp_path):
    import pytest as _pytest

    user = _SimpleUser(generate_identity("user-1"), generate_signing_key())
    peers = RegistryUserProvider("http://reg:8085", token="reg-tok",
                                 fetcher=_FakeRegistry(user))

    def hub(url, token):
        raise _err(403, "enrollment xyz rejected")

    provider = BootKeyProvider(
        "http://keyhub:8087", "", "spoke-1",
        peers=peers, fetcher=hub, enroll_keydir=str(tmp_path / "enroll"),
        backoff_s=0.0, submitter=lambda u, b: None,
    )
    with _pytest.raises(Exception, match="rejected"):
        provider.identity_keys()


def test_boot_no_enroll_keydir_errors(tmp_path):
    user = _SimpleUser(generate_identity("user-1"), generate_signing_key())
    peers = RegistryUserProvider("http://reg:8085", token="reg-tok",
                                 fetcher=_FakeRegistry(user))

    def hub(url, token):
        raise _err(403, "no enrollment request for 'spoke-1'")

    provider = BootKeyProvider(
        "http://keyhub:8087", "", "spoke-1",
        peers=peers, fetcher=hub, backoff_s=0.0,
    )
    with pytest.raises(Exception, match="BOOT_ENROLL_KEYDIR"):
        provider.identity_keys()
