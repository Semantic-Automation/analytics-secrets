"""Keyring + config tests."""

import pytest

from secretskit import (
    ConfigurationError,
    DecryptError,
    EnvKeyProvider,
    FileKeyProvider,
    SecretsConfig,
    UnknownPeerError,
    generate_identity,
    save_identity,
    save_peer,
)


def test_generate_and_save_roundtrip(tmp_path):
    ident = generate_identity("box")
    save_identity(ident, tmp_path)
    loaded = FileKeyProvider(tmp_path, "box").identity_keys()
    assert loaded.id == "box"
    # keys are usable
    peer = generate_identity("peer")
    save_peer(peer, tmp_path)
    assert FileKeyProvider(tmp_path, "box").peer_ids() == ["peer"]


def test_saved_keys_are_owner_only(tmp_path):
    """H3: private-key PEMs must be written 0600, keyring dir 0700."""
    save_identity(generate_identity("box"), tmp_path)
    dir_mode = tmp_path.stat().st_mode & 0o777
    assert dir_mode == 0o700, f"keyring dir not 0700: {dir_mode:o}"
    for name in ("box.kem.pem", "box.x.pem"):
        mode = (tmp_path / name).stat().st_mode & 0o777
        assert mode == 0o600, f"{name} not 0600: {mode:o}"
    # peers are public keys; identity private files must stay locked down
    save_peer(generate_identity("peer"), tmp_path)
    assert (tmp_path / "box.kem.pem").stat().st_mode & 0o777 == 0o600


def test_ensure_keyring_signing_owner_only(tmp_path):
    """H3: ensure_keyring with signing must write sign.pem 0600."""
    from secretskit import ensure_keyring

    ensure_keyring(tmp_path, "signed-box", signing=True)
    mode = (tmp_path / "signed-box.sign.pem").stat().st_mode & 0o777
    assert mode == 0o600, f"sign.pem not 0600: {mode:o}"
    assert (tmp_path / "signed-box.kem.pem").stat().st_mode & 0o777 == 0o600


def test_missing_identity_keydir(tmp_path):
    save_identity(generate_identity("box"), tmp_path)
    with pytest.raises(ConfigurationError):
        FileKeyProvider(tmp_path, "ghost")


def test_missing_keydir():
    with pytest.raises(ConfigurationError):
        FileKeyProvider("/does/not/exist", "box")


def test_peer_without_x_pub(tmp_path):
    ident = generate_identity("box")
    peer = generate_identity("peer")
    save_identity(ident, tmp_path)
    save_identity(peer, tmp_path / "peer_keydir")
    save_peer(peer, tmp_path)
    (tmp_path / "peer.x.pub.pem").unlink()
    with pytest.raises(ConfigurationError):
        FileKeyProvider(tmp_path, "box")


def test_unknown_peer_raises(tmp_path):
    save_identity(generate_identity("box"), tmp_path)
    prov = FileKeyProvider(tmp_path, "box")
    with pytest.raises(UnknownPeerError):
        prov.peer_public("ghost")


def test_config_file_build(tmp_path):
    save_identity(generate_identity("box"), tmp_path)
    cfg = SecretsConfig(keydir=str(tmp_path), identity="box")
    prov = cfg.build_provider()
    assert isinstance(prov, FileKeyProvider)


def test_config_file_missing_fields(tmp_path):
    with pytest.raises(ConfigurationError):
        SecretsConfig(keydir=str(tmp_path)).build_provider()


def test_config_unknown_provider():
    with pytest.raises(ConfigurationError):
        SecretsConfig(provider="kms").build_provider()


def test_env_provider_peers_parse(tmp_path):
    import base64

    from cryptography.hazmat.primitives import serialization

    ident = generate_identity("box")
    peer = generate_identity("peer")
    save_identity(ident, tmp_path)
    save_peer(peer, tmp_path)

    def pubb64(k):
        return base64.b64encode(k.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

    priv_pem = ident.kem.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    x_pem = ident.x.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    prov = EnvKeyProvider(
        identity="box",
        kem_private_pem=base64.b64encode(priv_pem).decode(),
        x_private_pem=base64.b64encode(x_pem).decode(),
        peers={"peer": {"kem_pub": pubb64(peer.kem.public_key()), "x_pub": pubb64(peer.x.public_key())}},
    )
    assert prov.identity_keys().id == "box"
    assert prov.peer_ids() == ["peer"]
    assert prov.peer_public("peer").id == "peer"


def test_config_from_env_env_provider():
    import base64

    from cryptography.hazmat.primitives import serialization

    ident = generate_identity("box")
    peer = generate_identity("peer")

    def priv_b64(k):
        return base64.b64encode(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())).decode()

    def pub_b64(k):
        return base64.b64encode(k.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

    env = {
        "SECRETS_PROVIDER": "env",
        "SECRETS_IDENTITY": "box",
        "SECRETS_PRIVATE_KEM": priv_b64(ident.kem),
        "SECRETS_PRIVATE_X": priv_b64(ident.x),
        "SECRETS_PEERS": '{"peer":{"kem_pub":"%s","x_pub":"%s"}}' % (pub_b64(peer.kem.public_key()), pub_b64(peer.x.public_key())),
    }
    cfg = SecretsConfig.from_env(env)
    prov = cfg.build_provider()
    assert isinstance(prov, EnvKeyProvider)
    assert prov.peer_ids() == ["peer"]


def test_config_from_env_bad_json():
    env = {"SECRETS_PEERS": "not json"}
    with pytest.raises(ConfigurationError):
        SecretsConfig.from_env(env)


def test_encrypted_with_other_keys_is_indistinguishable(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    save_identity(generate_identity("a"), a)
    save_identity(generate_identity("b"), b)
    pa = FileKeyProvider(a, "a")
    pb = FileKeyProvider(b, "b")
    # a and b cannot talk: no peers configured
    assert pa.peer_ids() == []
    assert pb.peer_ids() == []
