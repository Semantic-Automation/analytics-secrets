"""Overlay-join handoff for the EnrollFront underlay.

A rented spoke bootstraps by submitting a signed enrollment to the hub's
public EnrollFront (plain HTTPS behind a Cloudflare tunnel — see
analytics-wiki/architecture/underlay-overlay-plan.md §11.3). Once a human
approves, the hub mints a **one-time** overlay preauth key and returns it to
the spoke inside an ML-KEM envelope wrapped to the spoke's *enrollment* key.

This module builds and unwraps that handoff.

Security properties (all provided by existing secretskit primitives):
- Confidentiality + recipient-binding: ``wrap_bytes``/``unwrap_bytes`` (ML-KEM-768
  + X25519 -> AES-256-GCM) to the enrollment key. Only the approved spoke's
  enrollment **private** key can open it. A MITM on the public underlay sees
  only ciphertext.
- Authenticity + tamper-evidence: an ML-DSA-65 ``signature`` over the handoff
  JSON by the ops key, verified by the spoke against the pinned ops anchor.
- Freshness + single-use: ``expires_at`` is short (the one-time overlay preauth
  key lives only a few minutes); the preauth key itself is single-use in
  headscale. A relayed/replayed handoff is useless.

Wire format (the value of ``GET /handoff/{id}``)::

    {
      "spoke_id": "spoke-9",
      "envelope": "<base64 ML-KEM envelope to the enrollment key>",
      "signature": "<base64 ML-DSA-65 ops signature over the canonical JSON>"
    }

``build_handoff`` produces that; ``unwrap_handoff`` consumes it.
"""

import base64
import json
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa

from . import _manifest, _signing, _api

_DEFAULT_TTL_S = 900  # 15 min; the overlay preauth key must not outlive this


def _now_iso() -> str:
    return _manifest._now().strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(s: str) -> datetime:
    return _manifest._parse_utc(s)


def _canonical(payload: dict) -> bytes:
    return _manifest.canonical(payload)


def build_handoff(
    *,
    spoke_id: str,
    overlay_url: str,
    preauth_key: str,
    ca_cert_pem: bytes | str,
    dns_search: str,
    ops_signing_key: mldsa.MLDSA65PrivateKey,
    enrollment_peer,
    ttl_s: int = _DEFAULT_TTL_S,
) -> dict:
    """Build the handoff response for an approved spoke.

    ``enrollment_peer`` is the spoke's enrollment ``PeerPublic`` (the keys
    installed on keyhub at approval). ``ops_signing_key`` is the ML-DSA-65 ops
    key whose public half is the spoke's pinned anchor.

    Returns the JSON-serialisable handoff dict (``envelope`` + ``signature``).
    """
    now = _manifest._now()
    expires = now + timedelta(seconds=ttl_s)
    doc = {
        "version": 1,
        "spoke_id": spoke_id,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "overlay": {
            "headscale_url": overlay_url,
            "preauth_key": preauth_key,
            "ca_cert_pem": base64.b64encode(
                ca_cert_pem.encode() if isinstance(ca_cert_pem, str) else ca_cert_pem
            ).decode("ascii"),
            "dns_search": dns_search,
        },
    }
    plain = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    envelope = _api.wrap_bytes(enrollment_peer, plain)
    signature = ops_signing_key.sign(_canonical(doc))
    return {
        "spoke_id": spoke_id,
        "envelope": base64.b64encode(envelope).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def unwrap_handoff(
    handoff: dict,
    *,
    enrollment_identity,
    ops_verify_key: mldsa.MLDSA65PublicKey,
    expected_spoke_id: str,
    max_age_s: int = _DEFAULT_TTL_S,
    skew_s: int = 60,
) -> dict:
    """Verify + decrypt a handoff response on the spoke.

    ``enrollment_identity`` is the spoke's enrollment ``PrivateKeys`` (the one
    credential at rest on the spoke). ``ops_verify_key`` is the pinned ops
    anchor. Returns the inner handoff ``doc`` dict.

    Raises :class:`secretskit.DecryptError` on any tampering / expiry / key
    mismatch / wrong recipient.
    """
    from ._errors import DecryptError

    try:
        envelope = base64.b64decode(handoff["envelope"], validate=True)
        signature = base64.b64decode(handoff["signature"], validate=True)
    except (KeyError, ValueError, TypeError) as exc:
        raise DecryptError("handoff missing envelope/signature") from exc

    # Authenticate: the ops signature is over the plaintext doc, but we must
    # first recover the plaintext (envelope) to know what the signature covers.
    plain = _api.unwrap_bytes(enrollment_identity, envelope)
    try:
        doc = json.loads(plain.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DecryptError("handoff plaintext is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise DecryptError("handoff plaintext is not an object")

    # Verify the ops signature over the canonical doc (tamper-evidence).
    try:
        ops_verify_key.verify(signature, _canonical(doc))
    except InvalidSignature as exc:
        raise DecryptError("handoff ops signature verification failed") from exc

    # Freshness / recipient binding.
    if doc.get("spoke_id") != expected_spoke_id:
        raise DecryptError(
            f"handoff for {doc.get('spoke_id')!r} does not match {expected_spoke_id!r}"
        )
    now = _manifest._now()
    try:
        issued = _parse_utc(doc["issued_at"])
        expires = _parse_utc(doc["expires_at"])
    except (KeyError, ValueError, TypeError) as exc:
        raise DecryptError("handoff missing/invalid timestamps") from exc
    if issued > now + timedelta(seconds=skew_s):
        raise DecryptError("handoff issued in the future")
    if expires < now:
        raise DecryptError("handoff has expired")
    if (now - issued).total_seconds() > max_age_s + skew_s:
        raise DecryptError("handoff is stale")

    return doc
