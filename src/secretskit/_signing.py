"""Request authentication via ML-DSA-65 signatures.

Authorization ("who is allowed to send") cannot come from a public key in
the request — anyone can mint a keypair. Instead, every encrypted request
from an encryptor to a spoke is **signed** with the encryptor's ML-DSA-65
identity key, and the spoke verifies the signature against the registered
key for ``user_id`` (the user registry). A self-enrolled or forged key is
rejected.

The signed document carries ``timestamp`` and ``request_id`` so the spoke
can enforce a replay window (freshness) and track seen request ids.
"""

import base64
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa

from ._errors import DecryptError
from ._manifest import _now, _parse_utc, canonical


def _now_iso() -> str:
    return _now().strftime("%Y-%m-%dT%H:%M:%SZ")


def sign(
    data: bytes,
    signing_key: mldsa.MLDSA65PrivateKey,
    *,
    user_id: str,
    request_id: str | None = None,
    timestamp: str | None = None,
) -> bytes:
    """Sign ``data`` with ``signing_key``; returns the serialized signed
    document (JSON bytes). ``request_id``/``timestamp`` default to fresh
    values.
    """
    doc = {
        "user_id": user_id,
        "request_id": request_id or str(uuid.uuid4()),
        "timestamp": timestamp or _now_iso(),
        "data": base64.b64encode(data).decode("ascii"),
    }
    doc["signature"] = base64.b64encode(signing_key.sign(canonical(doc))).decode("ascii")
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def extract_user_id(payload: bytes) -> str:
    """Read ``user_id`` from a serialized signed request without verifying.

    The spoke needs the user id to fetch the user's verification key from
    the registry before it can verify the signature.
    """
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DecryptError("signed request is not valid JSON") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("user_id"), str):
        raise DecryptError("signed request missing user_id")
    return doc["user_id"]


def verify(
    payload: bytes,
    verify_key: mldsa.MLDSA65PublicKey,
    *,
    max_age_s: int = 300,
    skew_s: int = 60,
) -> dict:
    """Verify a signed request. Returns ``{"user_id", "request_id", "data"}``
    or raises :class:`DecryptError`.
    """
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DecryptError("signed request is not valid JSON") from exc
    if not isinstance(doc, dict) or "signature" not in doc:
        raise DecryptError("signed request missing signature")
    try:
        signature = base64.b64decode(doc.pop("signature"), validate=True)
    except Exception as exc:
        raise DecryptError("signed request signature is not valid base64") from exc
    try:
        verify_key.verify(signature, canonical(doc))
    except InvalidSignature as exc:
        raise DecryptError("signed request signature verification failed") from exc

    now = _now()
    ts = _parse_utc(doc["timestamp"])
    if ts > now + timedelta(seconds=skew_s):
        raise DecryptError("signed request timestamp is in the future")
    if (now - ts).total_seconds() > max_age_s:
        raise DecryptError(f"signed request is stale (older than {max_age_s}s)")

    try:
        data = base64.b64decode(doc["data"], validate=True)
    except Exception as exc:
        raise DecryptError("signed request data is not valid base64") from exc
    return {"user_id": doc["user_id"], "request_id": doc["request_id"], "data": data}


class ReplayGuard:
    """Rejects replayed ``request_id``s within a TTL window.

    The spoke holds one instance and calls :meth:`check` after a successful
    signature verification. Not thread-safe; guard externally if needed.
    """

    def __init__(self, ttl_s: int = 3600):
        self._ttl_s = ttl_s
        self._seen: dict[str, float] = {}

    def check(self, request_id: str, *, now: float | None = None) -> bool:
        """Return True if ``request_id`` has not been seen; records it."""
        now = time.time() if now is None else now
        for seen_id in [rid for rid, exp in self._seen.items() if exp < now]:
            del self._seen[seen_id]
        if request_id in self._seen:
            return False
        self._seen[request_id] = now + self._ttl_s
        return True
