"""Transport-layer authentication via ML-DSA-65 signatures.

Instead of static bearer tokens, requesters sign each HTTP request with their
ML-DSA-65 signing key.  The server verifies the signature against the
requester's registered public key, checks timestamp freshness, and rejects
replay via a nonce cache.

Header contract (requester sends)::

    X-Spoke-ID:   <identity_id>
    X-Timestamp:  <unix_seconds>
    X-Nonce:      <32-hex-chars>
    X-Signature:  <base64 ML-DSA-65 signature>

Signed message (canonical)::

    {spoke_id}.{timestamp}.{nonce}.{METHOD}.{path}

Server verification::

    1. Extract headers.
    2. Check timestamp is within ``max_age_s`` of server time.
    3. Check nonce hasn't been seen (cache for ``max_age_s * 2``).
    4. Look up spoke's ML-DSA-65 public key from the registry.
    5. Verify the signature.
"""

import hashlib
import secrets
import time
from functools import lru_cache

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa


def _canonical(spoke_id: str, timestamp: str, nonce: str, method: str, path: str) -> bytes:
    """Build the canonical signed message."""
    return f"{spoke_id}.{timestamp}.{nonce}.{method}.{path}".encode("utf-8")


def sign_request(
    signing_key: mldsa.MLDSA65PrivateKey,
    *,
    spoke_id: str,
    method: str,
    path: str,
) -> dict[str, str]:
    """Sign an HTTP request; returns a dict of headers to add."""
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    msg = _canonical(spoke_id, timestamp, nonce, method.upper(), path)
    signature = signing_key.sign(msg)
    return {
        "X-Spoke-ID": spoke_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": __import__("base64").b64encode(signature).decode("ascii"),
    }


def verify_request(
    headers: dict,
    *,
    verify_key: mldsa.MLDSA65PublicKey,
    method: str,
    path: str,
    max_age_s: int = 30,
    _nonce_cache: dict | None = None,
) -> str:
    """Verify a signed request.  Returns the ``spoke_id`` or raises.

    Parameters
    ----------
    headers : dict
        Request headers (case-insensitive lookup).
    verify_key : MLDSA65PublicKey
        The spoke's registered public signing key.
    method : str
        HTTP method (GET, POST, ...).
    path : str
        Request path (e.g. ``/users/spoke-1``).
    max_age_s : int
        Maximum age of the request in seconds (default 30).
    _nonce_cache : dict, optional
        Shared nonce cache ``{nonce: expiry_timestamp}``.  Created if None.
    """
    import base64

    # 1. Extract headers (case-insensitive).
    def _h(name: str) -> str:
        for k, v in headers.items():
            if k.lower() == name.lower():
                return v
        return ""

    spoke_id = _h("X-Spoke-ID")
    timestamp_str = _h("X-Timestamp")
    nonce = _h("X-Nonce")
    sig_b64 = _h("X-Signature")

    if not all([spoke_id, timestamp_str, nonce, sig_b64]):
        raise ValueError("missing required auth headers (X-Spoke-ID, X-Timestamp, X-Nonce, X-Signature)")

    # 2. Check timestamp freshness.
    try:
        ts = int(timestamp_str)
    except ValueError:
        raise ValueError("X-Timestamp must be an integer")
    now = int(time.time())
    if abs(now - ts) > max_age_s:
        raise ValueError(f"request timestamp expired (age={abs(now - ts)}s, max={max_age_s}s)")

    # 3. Check nonce (replay guard).
    if _nonce_cache is None:
        _nonce_cache = _VerifiedNonces._cache
    if nonce in _nonce_cache:
        if _nonce_cache[nonce] > now:
            raise ValueError(f"replay detected: nonce {nonce!r} already seen")
        # Expired nonce entry — fall through (will be re-added below).
    _nonce_cache[nonce] = now + max_age_s * 2

    # 4. Verify signature.
    msg = _canonical(spoke_id, timestamp_str, nonce, method.upper(), path)
    try:
        sig = base64.b64decode(sig_b64)
        verify_key.verify(sig, msg)
    except (InvalidSignature, Exception) as exc:
        raise ValueError(f"signature verification failed: {exc}") from exc

    return spoke_id


class _VerifiedNonces:
    """Singleton nonce cache shared across requests."""

    _cache: dict[str, int] = {}


def get_nonce_cache() -> dict[str, int]:
    """Return the shared nonce cache."""
    return _VerifiedNonces._cache


def _cleanup_nonce_cache(max_age_s: int = 30) -> None:
    """Remove expired entries from the nonce cache."""
    now = int(time.time())
    cache = _VerifiedNonces._cache
    expired = [k for k, v in cache.items() if v <= now]
    for k in expired:
        del cache[k]
