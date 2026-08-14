"""Signed-manifest signing and verification.

The manifest is an ops-signed list of server-side entities (the spokes,
or the LLM servers in dev). It is served by the proxy and verified by
encryptors and spokes against a pre-provisioned ML-DSA-65 verification
key — the *single* trust anchor shipped out of band.

A signed manifest removes trust-on-first-use from key distribution: a
key that is not in a manifest signed by the pinned key is never used.

Freshness: a manifest is rejected if ``expires_at`` has passed, if
``issued_at`` is in the future (beyond ``skew_s``), or if ``issued_at``
is older than ``max_age_s``.
"""

import base64
import json
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from ._errors import ConfigurationError

VERSION = 1

_JSON_KWARGS = {"sort_keys": True, "separators": (",", ":")}

_PEM = serialization.Encoding.PEM
_PKCS8 = serialization.PrivateFormat.PKCS8
_SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


def generate_signing_key() -> mldsa.MLDSA65PrivateKey:
    """Create a fresh ML-DSA-65 manifest signing key."""
    return mldsa.MLDSA65PrivateKey.generate()


def load_signing_key(data: bytes) -> mldsa.MLDSA65PrivateKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, mldsa.MLDSA65PrivateKey):
        raise ConfigurationError("expected an ML-DSA-65 private key")
    return key


def load_verification_key(data: bytes) -> mldsa.MLDSA65PublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, mldsa.MLDSA65PublicKey):
        raise ConfigurationError("expected an ML-DSA-65 public key")
    return key


def serialize_signing_key(key: mldsa.MLDSA65PrivateKey) -> bytes:
    return key.private_bytes(_PEM, _PKCS8, serialization.NoEncryption())


def serialize_verification_key(key: mldsa.MLDSA65PublicKey) -> bytes:
    return key.public_bytes(_PEM, _SPKI)


def canonical(doc: dict) -> bytes:
    """Canonical UTF-8 JSON encoding used for signing/verification."""
    return json.dumps(doc, **_JSON_KWARGS).encode("utf-8")


def _parse_utc(value: str) -> datetime:
    try:
        ts = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ConfigurationError(f"invalid manifest timestamp {value!r}") from exc
    if ts.tzinfo is None:
        raise ConfigurationError("manifest timestamps must carry a timezone (UTC)")
    return ts.astimezone(timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def sign(
    entities: dict,
    *,
    issued_at: str,
    expires_at: str,
    signing_key: mldsa.MLDSA65PrivateKey,
    version: int = VERSION,
) -> dict:
    """Build a manifest dict signed by ``signing_key``.

    ``entities`` maps an entity id (e.g. ``"spoke-1"``) to a dict holding
    ``kem_pub``/``x_pub`` (and optional ``role``).
    """
    doc = {
        "version": version,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "entities": entities,
    }
    signature = signing_key.sign(canonical(doc))
    doc["signature"] = base64.b64encode(signature).decode("ascii")
    return doc


def serialize(manifest: dict) -> bytes:
    """Encode a signed manifest to bytes for storage/serving."""
    return json.dumps(manifest, **_JSON_KWARGS).encode("utf-8")


def deserialize(payload: bytes) -> dict:
    """Decode a serialized manifest; raises :class:`ConfigurationError` if malformed."""
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ConfigurationError("manifest is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise ConfigurationError("manifest must be a JSON object")
    return doc


def verify(
    payload: bytes,
    verify_key: mldsa.MLDSA65PublicKey,
    *,
    max_age_s: int = 10800,
    skew_s: int = 60,
) -> dict:
    """Verify a serialized manifest's signature and freshness.

    Returns the manifest dict (with ``signature`` removed) or raises
    :class:`ConfigurationError`.
    """
    doc = deserialize(payload)
    if "signature" not in doc:
        raise ConfigurationError("manifest has no signature")
    try:
        signature = base64.b64decode(doc.pop("signature"), validate=True)
    except Exception as exc:
        raise ConfigurationError("manifest signature is not valid base64") from exc
    try:
        verify_key.verify(signature, canonical(doc))
    except InvalidSignature as exc:
        raise ConfigurationError("manifest signature verification failed") from exc
    return _check_freshness(doc, max_age_s=max_age_s, skew_s=skew_s)


def _check_freshness(doc: dict, *, max_age_s: int, skew_s: int) -> dict:
    now = _now()
    try:
        issued = _parse_utc(doc["issued_at"])
        expires = _parse_utc(doc["expires_at"])
    except KeyError as exc:
        raise ConfigurationError("manifest missing issued_at/expires_at") from exc
    if now > expires + timedelta(seconds=skew_s):
        raise ConfigurationError("manifest is expired")
    if issued > now + timedelta(seconds=skew_s):
        raise ConfigurationError("manifest is issued in the future")
    if (now - issued).total_seconds() > max_age_s:
        raise ConfigurationError(f"manifest is stale (older than {max_age_s}s)")
    return doc
