"""Binary envelope wire format.

Each encrypted payload is wrapped in a self-delimiting, versioned
envelope:

+---------+---------+------+---------------+-----------+---------+-----------+
| magic   | version | flags| kem_ct_len(2) | eph_x_len | nonce_len | ct_len(4) |
| "SECE"  |   1     | 1    | (big-endian)  |    1      |    1     |(big-endian)|
+---------+---------+------+---------------+-----------+---------+-----------+

followed by ``kem_ct_len`` bytes of ML-KEM-768 ciphertext, ``eph_x_len``
bytes of the ephemeral X25519 public key, ``nonce_len`` bytes of the
AES-GCM nonce and ``ct_len`` bytes of ciphertext.

The envelope is self-delimiting (all field lengths are carried in the
fixed 14-byte header), so a stream of concatenated envelopes can be
parsed in order.  This is what the chunked streaming API relies on:
each ``yield`` of the LLM response becomes one envelope.

Flags bits:
  bit 2     has eph_x_pub (always set for the current hybrid scheme)
"""

import struct

from ._errors import DecryptError

MAGIC = b"SECE"
VERSION = 1
HEADER_SIZE = 14
_HEADER = struct.Struct(">4sBBHBBI")

_FLAG_HAS_EPH_X = 1 << 2


def _flags(has_eph_x: bool) -> int:
    return _FLAG_HAS_EPH_X if has_eph_x else 0


def _has_eph_x(flags: int) -> bool:
    return bool(flags & _FLAG_HAS_EPH_X)


def pack(kem_ct: bytes, eph_x_pub: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    has_eph = len(eph_x_pub) > 0
    header = _HEADER.pack(
        MAGIC,
        VERSION,
        _flags(has_eph),
        len(kem_ct),
        len(eph_x_pub),
        len(nonce),
        len(ciphertext),
    )
    return header + kem_ct + eph_x_pub + nonce + ciphertext


def unpack_header(data: bytes) -> dict:
    """Parse only the 14-byte header, returning the field lengths without
    requiring the body.  Used by the streaming reader to size the reads."""
    if len(data) < HEADER_SIZE:
        raise DecryptError("envelope truncated: header not complete")
    magic, version, flags, kem_ct_len, eph_x_len, nonce_len, ct_len = _HEADER.unpack(data[:HEADER_SIZE])
    if magic != MAGIC:
        raise DecryptError("not a secrets envelope (bad magic)")
    if version != VERSION:
        raise DecryptError(f"unsupported envelope version {version}")
    return {
        "flags": flags,
        "kem_ct_len": kem_ct_len,
        "eph_x_len": eph_x_len,
        "nonce_len": nonce_len,
        "ct_len": ct_len,
    }


def unpack(data: bytes) -> dict:
    """Parse an envelope from ``data``; raises :class:`DecryptError` when
    the header is truncated or does not match the expected format."""
    if len(data) < HEADER_SIZE:
        raise DecryptError("envelope truncated: header not complete")
    magic, version, flags, kem_ct_len, eph_x_len, nonce_len, ct_len = _HEADER.unpack(data[:HEADER_SIZE])
    if magic != MAGIC:
        raise DecryptError("not a secrets envelope (bad magic)")
    if version != VERSION:
        raise DecryptError(f"unsupported envelope version {version}")

    offset = HEADER_SIZE
    expected = kem_ct_len + eph_x_len + nonce_len + ct_len
    if len(data) < offset + expected:
        raise DecryptError("envelope truncated: body not complete")

    kem_ct = data[offset : offset + kem_ct_len]
    offset += kem_ct_len
    eph_x_pub = data[offset : offset + eph_x_len]
    offset += eph_x_len
    nonce = data[offset : offset + nonce_len]
    offset += nonce_len
    ciphertext = data[offset : offset + ct_len]

    if _has_eph_x(flags) and eph_x_len == 0:
        raise DecryptError("envelope flags claim eph_x_pub but it is missing")

    return {
        "kem_ct": kem_ct,
        "eph_x_pub": eph_x_pub,
        "nonce": nonce,
        "ciphertext": ciphertext,
    }
