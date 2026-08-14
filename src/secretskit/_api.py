"""Public, stable encryption API.

This is the only module application and server code are expected to
import (besides :mod:`secretskit` itself).  Signatures here are frozen:

* ``Encryptor.encrypt(payload, *, to=None, aad=b"") -> bytes``
* ``Encryptor.encrypt_chunk(data, *, to=None, aad=b"") -> bytes``
* ``Decryptor.decrypt(blob, *, aad=b"") -> Any``
* ``Decryptor.decrypt_chunk(blob, *, aad=b"") -> bytes``
* ``Decryptor.iter_chunks(stream, *, aad=b"") -> Iterator[bytes]``

Payloads are JSON: ``encrypt`` accepts any JSON-serialisable value and
``decrypt`` returns the reconstructed JSON value.  The dev prompt is
passed as ``{"prompt": "..."}``; in prod the app's structured data is
passed directly.  Raw byte streaming (each LLM ``yield``) is handled by
``encrypt_chunk`` / ``decrypt_chunk``.

Everything below this module (hybrid KEM, envelope layout, key storage)
may be swapped without touching callers.

``to`` selects which configured peer the envelope is encrypted to; the
matching peer's private key is the only one that can decrypt it.  When
exactly one peer is configured it may be omitted.

``aad`` is optional associated data bound into the AES-GCM tag.  Routing
metadata that the proxy must be able to read (spoke id, request id)
belongs in transport headers, but values that must be tamper-evident
(and are already known to the sender and recipient) can be supplied here.

Streaming: each ``encrypt_chunk`` produces one self-delimiting envelope,
so a sequence of yields concatenates into a stream that
``Decryptor.iter_chunks`` parses in order.
"""

import json
import os
from collections.abc import Iterable, Iterator
from typing import Any, BinaryIO

from . import _envelope, _hybrid
from ._config import SecretsConfig
from ._errors import ConfigurationError, DecryptError, UnknownPeerError
from ._hybrid import NONCE_LEN, PeerPublic, PrivateKeys
from ._keys import KeyProvider


class _Base:
    def __init__(self, *, config: SecretsConfig | None = None, provider: KeyProvider | None = None):
        if provider is None:
            provider = config.build_provider() if config is not None else SecretsConfig.from_env().build_provider()
        self._provider = provider

    def _resolve_peer(self, to: str | None) -> _hybrid.PeerPublic:
        if to is not None:
            return self._provider.peer_public(to)
        peers = self._provider.peer_ids()
        if len(peers) != 1:
            raise ConfigurationError(
                "ambiguous recipient: specify 'to' when more than one peer is configured"
            )
        return self._provider.peer_public(peers[0])

    @property
    def identity(self) -> str:
        return self._provider.identity_keys().id

    @property
    def peers(self) -> list[str]:
        return self._provider.peer_ids()


class Encryptor(_Base):
    """Encrypts JSON payloads into opaque envelopes."""

    def encrypt(self, payload, *, to: str | None = None, aad: bytes = b"") -> bytes:
        """Encrypt a JSON-serialisable ``payload`` to a peer and return the
        opaque envelope bytes.  The dev prompt is passed as a dict, e.g.
        ``{"prompt": "..."}``; ``bytes`` must go through ``encrypt_chunk``."""
        if isinstance(payload, bytes):
            raise TypeError("encrypt expects a JSON-serialisable value; use encrypt_chunk for bytes")
        try:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise TypeError(f"payload is not JSON-serialisable: {type(payload).__name__}") from exc
        return self._encrypt(self._resolve_peer(to), data, aad)

    def encrypt_chunk(self, data: bytes, *, to: str | None = None, aad: bytes = b"") -> bytes:
        """Encrypt one raw chunk (e.g. a single LLM response ``yield``) into
        a standalone envelope.  Chunks encrypted with the same arguments
        concatenate into a parseable stream."""
        if not isinstance(data, bytes):
            raise TypeError("encrypt_chunk expects bytes")
        return self._encrypt(self._resolve_peer(to), data, aad)

    def _encrypt(self, peer: _hybrid.PeerPublic, data: bytes, aad: bytes) -> bytes:
        secret = _hybrid.encapsulate(peer)
        nonce = os.urandom(NONCE_LEN)
        ciphertext = _hybrid.encrypt_data(secret.key, nonce, data, aad)
        return _envelope.pack(secret.kem_ct, secret.eph_x_pub, nonce, ciphertext)


class Decryptor(_Base):
    """Decrypts envelopes produced by :class:`Encryptor`."""

    def decrypt(self, blob: bytes, *, aad: bytes = b"") -> Any:
        """Decrypt an envelope and return the reconstructed JSON payload."""
        plaintext = self._decrypt(blob, aad)
        try:
            return json.loads(plaintext.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise DecryptError("plaintext is not valid JSON") from exc

    def decrypt_chunk(self, blob: bytes, *, aad: bytes = b"") -> bytes:
        """Decrypt exactly one envelope, returning raw chunk bytes."""
        if not isinstance(blob, bytes):
            raise TypeError("decrypt_chunk expects bytes")
        return self._decrypt(blob, aad)

    def iter_chunks(self, stream: Iterable[bytes] | BinaryIO, *, aad: bytes = b"") -> Iterator[bytes]:
        """Yield the plaintext of each envelope in a stream of concatenated
        envelopes, preserving order.  ``stream`` may be an iterable of byte
        fragments (e.g. network chunks) or a binary file-like object."""
        reader = _StreamReader(stream)
        while True:
            header = reader.read(_envelope.HEADER_SIZE)
            if header == b"":
                return
            if len(header) < _envelope.HEADER_SIZE:
                raise DecryptError("stream ended inside an envelope header")
            meta = _envelope.unpack_header(header)
            body_len = (
                meta["kem_ct_len"]
                + meta["eph_x_len"]
                + meta["nonce_len"]
                + meta["ct_len"]
            )
            body = reader.read(body_len)
            if len(body) < body_len:
                raise DecryptError("stream ended inside an envelope body")
            yield self.decrypt_chunk(header + body, aad=aad)

    def _decrypt(self, blob: bytes, aad: bytes) -> bytes:
        if not isinstance(blob, bytes):
            raise TypeError("decrypt expects bytes")
        env = _envelope.unpack(blob)
        priv = self._provider.identity_keys()
        key = _hybrid.decapsulate(priv, env["kem_ct"], env["eph_x_pub"])
        try:
            return _hybrid.decrypt_data(key, env["nonce"], env["ciphertext"], aad)
        except Exception as exc:  # cryptography raises InvalidTag
            raise DecryptError("decryption failed (wrong key or tampered data)") from exc


class _SinglePeerProvider(KeyProvider):
    """Encrypt-only provider wrapping one peer (used by :func:`wrap_bytes`)."""

    def __init__(self, peer: PeerPublic):
        self._peer = peer

    def identity_keys(self):
        raise ConfigurationError("single-peer provider has no identity (encrypt-only)")

    def peer_public(self, peer_id: str) -> PeerPublic:
        if peer_id != self._peer.id:
            raise UnknownPeerError(f"unknown peer {peer_id!r}")
        return self._peer

    def peer_ids(self) -> list[str]:
        return [self._peer.id]


class _SingleIdentityProvider(KeyProvider):
    """Decrypt-only provider holding one identity (used by :func:`unwrap_bytes`)."""

    def __init__(self, identity: PrivateKeys):
        self._identity = identity

    def identity_keys(self) -> PrivateKeys:
        return self._identity

    def peer_public(self, peer_id: str) -> PeerPublic:
        raise ConfigurationError("single-identity provider has no peers (decrypt-only)")

    def peer_ids(self) -> list[str]:
        return []


def wrap_bytes(peer: PeerPublic, data: bytes, *, aad: bytes = b"") -> bytes:
    """Encrypt ``data`` to a single peer's public keys (ML-KEM + X25519).

    Used for the app-layer PQ key-release: keyhub wraps the spoke's identity
    material to the spoke's enrollment public key.  Returns a standalone
    envelope (:func:`unwrap_bytes` is the matching recipient).
    """
    return Encryptor(provider=_SinglePeerProvider(peer)).encrypt_chunk(data, aad=aad)


def unwrap_bytes(identity: PrivateKeys, blob: bytes, *, aad: bytes = b"") -> bytes:
    """Decrypt an envelope produced by :func:`wrap_bytes` with the private keys."""
    return Decryptor(provider=_SingleIdentityProvider(identity)).decrypt_chunk(blob, aad=aad)


class _StreamReader:
    """Buffered reader over an iterable of byte fragments."""
    def __init__(self, src: Iterable[bytes] | BinaryIO):
        self._src = src
        self._buffer = b""
        self._iter = None
        self._done = False

    def read(self, n: int) -> bytes:
        while len(self._buffer) < n and not self._done:
            chunk = self._next()
            if chunk is None:
                break
            self._buffer += chunk
        out, self._buffer = self._buffer[:n], self._buffer[n:]
        return out

    def _next(self) -> bytes | None:
        if self._iter is None:
            if hasattr(self._src, "read"):
                chunk = self._src.read(65536)
                return chunk if chunk else None
            self._iter = iter(self._src)
        try:
            return next(self._iter)
        except StopIteration:
            self._done = True
            return None
