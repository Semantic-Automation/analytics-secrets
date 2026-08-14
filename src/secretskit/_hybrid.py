"""Hybrid post-quantum cryptography primitives.

Encryption is performed with a stateless hybrid KEM, mirroring the
X25519MLKEM768 hybrid used in TLS 1.3:

* an ephemeral ML-KEM-768 keypair is used to encapsulate a shared secret
  to the recipient's ML-KEM-768 public key (NIST PQ standard),
* an ephemeral X25519 keypair contributes an ECDH shared secret bound to
  the same recipient,
* both shared secrets are combined with HKDF-SHA256 to derive a single
  AES-256-GCM data key.

Because the KEM is performed per message with ephemeral keys, a new
sender key is used every time and the long-term identity keys of both
parties never appear in the ciphertext, giving forward secrecy and
harvest-now/decrypt-later resistance without any session state.
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEM_ALG = "mlkem768"
X_ALG = "x25519"
KEY_LEN = 32
NONCE_LEN = 12
AES_ALG = "aes-256-gcm"

_HKDF_INFO = b"analytics-secrets/v1-hybrid"


@dataclass(frozen=True)
class PrivateKeys:
    """A party's long-term identity keys."""

    id: str
    kem: mlkem.MLKEM768PrivateKey
    x: x25519.X25519PrivateKey


@dataclass(frozen=True)
class PeerPublic:
    """A recipient's long-term public keys."""

    id: str
    kem: mlkem.MLKEM768PublicKey
    x: x25519.X25519PublicKey


@dataclass(frozen=True)
class KEMSecret:
    """Result of encapsulation against a peer."""

    key: bytes
    kem_ct: bytes
    eph_x_pub: bytes


def _derive_key(kem_shared: bytes, x_shared: bytes, kem_ct: bytes, eph_x_pub: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=kem_ct,
        info=_HKDF_INFO + eph_x_pub,
    )
    return hkdf.derive(kem_shared + x_shared)


def encapsulate(peer: PeerPublic) -> KEMSecret:
    """Encrypt to ``peer``: returns the data key and the values a
    recipient needs to recover it."""
    eph_x = X25519PrivateKey.generate()

    kem_shared, kem_ct = peer.kem.encapsulate()
    x_shared = eph_x.exchange(peer.x)
    eph_x_pub = eph_x.public_key().public_bytes_raw()

    key = _derive_key(kem_shared, x_shared, kem_ct, eph_x_pub)
    return KEMSecret(key=key, kem_ct=kem_ct, eph_x_pub=eph_x_pub)


def decapsulate(priv: PrivateKeys, kem_ct: bytes, eph_x_pub: bytes) -> bytes:
    """Recover the data key from an envelope produced by :func:`encapsulate`."""
    kem_shared = priv.kem.decapsulate(kem_ct)
    x_shared = priv.x.exchange(X25519PublicKey.from_public_bytes(eph_x_pub))
    return _derive_key(kem_shared, x_shared, kem_ct, eph_x_pub)


def encrypt_data(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).encrypt(nonce, data, aad)


def decrypt_data(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
