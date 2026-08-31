"""Tests for the manifest-backed RegistryKeyProvider."""

import base64
import http.server
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from secretskit import (
    Decryptor,
    Encryptor,
    RegistryKeyProvider,
    SecretsConfig,
    UnknownPeerError,
    generate_identity,
    save_identity,
)
from secretskit._errors import ConfigurationError
from secretskit._manifest import generate_signing_key, serialize, sign
from secretskit._manifest import serialize_verification_key


def _b64_pem(key, public=True):
    from cryptography.hazmat.primitives import serialization

    if public:
        return base64.b64encode(
            key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        ).decode()
    return base64.b64encode(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    ).decode()


def _make_manifest(signing_key, spokes, *, ttl_h=1, roles=None):
    now = datetime.now(timezone.utc)
    entities = {}
    for sid in spokes:
        s = _identity(sid)
        entity = {
            "kem_pub": _b64_pem(s.kem.public_key()),
            "x_pub": _b64_pem(s.x.public_key()),
        }
        if roles and sid in roles:
            entity["role"] = roles[sid]
        entities[sid] = entity
    return sign(
        entities,
        issued_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(now + timedelta(hours=ttl_h)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        signing_key=signing_key,
    )


identities = {}


def _identity(name):
    if name not in identities:
        identities[name] = generate_identity(name)
    return identities[name]


def _hub_identity():
    return _identity("hub")


def _spoke_identity(sid):
    return _identity(sid)


@pytest.fixture()
def manifest_env(tmp_path):
    """Signing key + anchor + a manifest for spokes spoke-1/spoke-2."""
    signing = generate_signing_key()
    anchor = tmp_path / "registry.pub.pem"
    anchor.write_bytes(serialize_verification_key(signing.public_key()))
    manifest_doc = _make_manifest(signing, ["spoke-1", "spoke-2"])
    return {
        "signing": signing,
        "anchor": anchor,
        "manifest_bytes": serialize(manifest_doc),
    }


def _fetcher(manifest_bytes):
    def fetcher(url, token):
        assert url == "http://registry.test/keys/manifest"
        if token is not None:
            assert token == "tok-123"
        return manifest_bytes

    return fetcher


def test_provider_roundtrip(manifest_env):
    hub = _hub_identity()
    prov = RegistryKeyProvider(
        "http://registry.test/keys/manifest",
        load_anchor(manifest_env["anchor"]),
        identity=hub,
        token="tok-123",
        fetcher=_fetcher(manifest_env["manifest_bytes"]),
    )
    assert prov.peer_ids() == ["spoke-1", "spoke-2"]
    assert prov.identity_keys().id == "hub"

    # full roundtrip: hub encrypts to a manifest spoke; spoke decrypts
    enc = Encryptor(provider=prov)
    spoke = _spoke_identity("spoke-1")
    dec = Decryptor(provider=RegistryKeyProvider(
        "http://registry.test/keys/manifest",
        load_anchor(manifest_env["anchor"]),
        identity=spoke,
        token="tok-123",
        fetcher=_fetcher(manifest_env["manifest_bytes"]),
    ))
    blob = enc.encrypt({"prompt": "hello"}, to="spoke-1")
    assert dec.decrypt(blob) == {"prompt": "hello"}


def test_peer_roles(manifest_env):
    """Roles come from the signed manifest; absent role defaults to llm."""
    hub = _hub_identity()
    doc = _make_manifest(
        manifest_env["signing"],
        ["spoke-1", "spoke-2", "builder-1"],
        roles={"spoke-1": "llm", "builder-1": "builder"},
    )
    prov = RegistryKeyProvider(
        "http://registry.test/keys/manifest",
        load_anchor(manifest_env["anchor"]),
        identity=hub,
        fetcher=_fetcher(serialize(doc)),
    )
    assert prov.peer_roles() == {"spoke-1": "llm", "spoke-2": "llm", "builder-1": "builder"}
    assert [p for p in prov.peer_ids() if prov.peer_roles()[p] == "builder"] == ["builder-1"]


def test_peer_roles_rejects_unknown_tag(manifest_env):
    """An unknown/self-declared role tag is coerced to llm (trusted source)."""
    hub = _hub_identity()
    doc = _make_manifest(
        manifest_env["signing"],
        ["spoke-1"],
        roles={"spoke-1": "sudo"},
    )
    prov = RegistryKeyProvider(
        "http://registry.test/keys/manifest",
        load_anchor(manifest_env["anchor"]),
        identity=hub,
        fetcher=_fetcher(serialize(doc)),
    )
    assert prov.peer_roles() == {"spoke-1": "llm"}


def test_unknown_peer(manifest_env):
    hub = _hub_identity()
    prov = RegistryKeyProvider(
        "http://registry.test/keys/manifest",
        load_anchor(manifest_env["anchor"]),
        identity=hub,
        fetcher=_fetcher(manifest_env["manifest_bytes"]),
    )
    with pytest.raises(UnknownPeerError):
        prov.peer_public("ghost")


def test_tampered_manifest_rejected(manifest_env):
    hub = _hub_identity()
    tampered = bytearray(manifest_env["manifest_bytes"])
    tampered[-5] ^= 0x01
    with pytest.raises(ConfigurationError):
        RegistryKeyProvider(
            "http://registry.test/keys/manifest",
            load_anchor(manifest_env["anchor"]),
            identity=hub,
            fetcher=_fetcher(bytes(tampered)),
        )


def test_wrong_anchor_rejected(manifest_env):
    hub = _hub_identity()
    other_signing = generate_signing_key()
    from secretskit._manifest import serialize_verification_key as svk
    from secretskit._manifest import load_verification_key

    wrong_anchor = load_verification_key(svk(other_signing.public_key()))
    with pytest.raises(ConfigurationError):
        RegistryKeyProvider(
            "http://registry.test/keys/manifest",
            wrong_anchor,
            identity=hub,
            fetcher=_fetcher(manifest_env["manifest_bytes"]),
        )


def test_expired_manifest_rejected(manifest_env):
    hub = _hub_identity()
    expired = _make_manifest(manifest_env["signing"], ["spoke-1"], ttl_h=-1)
    with pytest.raises(ConfigurationError):
        RegistryKeyProvider(
            "http://registry.test/keys/manifest",
            load_anchor(manifest_env["anchor"]),
            identity=hub,
            fetcher=_fetcher(serialize(expired)),
        )


def test_no_identity_raises(manifest_env):
    prov = RegistryKeyProvider(
        "http://registry.test/keys/manifest",
        load_anchor(manifest_env["anchor"]),
        fetcher=_fetcher(manifest_env["manifest_bytes"]),
    )
    with pytest.raises(ConfigurationError):
        prov.identity_keys()


@pytest.fixture()
def local_registry(manifest_env):
    """Serve the manifest over a real local HTTP endpoint (exercises urllib)."""
    import functools
    import http.server
    import threading

    handler = functools.partial(_ManifestHandler, manifest_env["manifest_bytes"])
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/keys/manifest"
    yield url
    server.shutdown()
    thread.join()


class _ManifestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, payload, *args, **kwargs):
        self._payload = payload
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path != "/keys/manifest":
            self.send_error(404)
            return
        body = self._payload
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_config_build_registry_provider(tmp_path, manifest_env, local_registry):
    hub = _hub_identity()
    keydir = tmp_path / "hub"
    save_identity(hub, keydir)
    env = {
        "SECRETS_PROVIDER": "registry",
        "SECRETS_KEYDIR": str(keydir),
        "SECRETS_IDENTITY": "hub",
        "SECRETS_REGISTRY_URL": local_registry,
        "SECRETS_REGISTRY_PUB": str(manifest_env["anchor"]),
        "SECRETS_REGISTRY_TOKEN": "tok-123",
    }
    cfg = SecretsConfig.from_env(env)
    prov = cfg.build_provider()
    assert isinstance(prov, RegistryKeyProvider)
    assert prov.identity_keys().id == "hub"
    assert prov.peer_ids() == ["spoke-1", "spoke-2"]


def test_config_registry_requires_fields(tmp_path):
    hub = _hub_identity()
    keydir = tmp_path / "hub"
    save_identity(hub, keydir)
    with pytest.raises(ConfigurationError):
        SecretsConfig.from_env({
            "SECRETS_PROVIDER": "registry",
            "SECRETS_KEYDIR": str(keydir),
            "SECRETS_IDENTITY": "hub",
        }).build_provider()


def load_anchor(path):
    from secretskit._manifest import load_verification_key

    return load_verification_key(Path(path).read_bytes())


def _load_from_pem(pem):
    from secretskit._manifest import load_verification_key

    return load_verification_key(pem)
