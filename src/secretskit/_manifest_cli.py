"""CLI for signing and verifying manifests.

Runs in ops only — the manifest signing key must never be placed on the
proxy or any encryptor.

Usage::

    analytics-manifest genkey --signing-key signing.pem --anchor registry.pub.pem
    analytics-manifest make \\
        --entities server:keydir,spoke-1:keydir --signing-key signing.pem \\
        --ttl 3 --out manifest.json
    analytics-manifest verify --manifest manifest.json --anchor registry.pub.pem
"""

import argparse
import base64
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import _manifest
from ._errors import ConfigurationError


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cmd_genkey(args: argparse.Namespace) -> int:
    signing = _manifest.generate_signing_key()
    out = Path(args.signing_key)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(_manifest.serialize_signing_key(signing))
    Path(args.anchor).write_bytes(_manifest.serialize_verification_key(signing.public_key()))
    print(f"signing key  -> {args.signing_key}")
    print(f"anchor (pub) -> {args.anchor}")
    return 0


def _entity_publics(spec: str) -> dict:
    entities = {}
    for item in spec.split(","):
        item = item.strip()
        if not item or ":" not in item:
            raise ConfigurationError(f"expected 'id:keydir' but got {item!r}")
        entity_id, keydir = item.split(":", 1)
        keydir = Path(keydir)
        kem = (keydir / f"{entity_id}.kem.pub.pem").read_bytes()
        x = (keydir / f"{entity_id}.x.pub.pem").read_bytes()
        entities[entity_id] = {
            "kem_pub": base64.b64encode(kem).decode("ascii"),
            "x_pub": base64.b64encode(x).decode("ascii"),
        }
    return entities


def _cmd_make(args: argparse.Namespace) -> int:
    signing_key = _manifest.load_signing_key(Path(args.signing_key).read_bytes())
    entities = _entity_publics(args.entities)
    now = datetime.now(timezone.utc)
    issued = _now_iso()
    expires = (now + timedelta(hours=args.ttl)).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = _manifest.sign(entities, issued_at=issued, expires_at=expires, signing_key=signing_key)
    Path(args.out).write_bytes(_manifest.serialize(manifest))
    print(f"manifest with {len(entities)} entity/entities -> {args.out}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    verify_key = _manifest.load_verification_key(Path(args.anchor).read_bytes())
    payload = Path(args.manifest).read_bytes()
    doc = _manifest.verify(payload, verify_key, max_age_s=args.max_age_s, skew_s=args.skew_s)
    print(f"manifest valid: {len(doc['entities'])} entities, expires {doc['expires_at']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="analytics-manifest", description="Sign and verify E2EE manifests")
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genkey", help="generate an ML-DSA-65 signing keypair")
    g.add_argument("--signing-key", required=True, help="output path for the private signing key")
    g.add_argument("--anchor", required=True, help="output path for the verification public key")
    g.set_defaults(func=_cmd_genkey)

    m = sub.add_parser("make", help="sign a manifest from entity keydirs")
    m.add_argument("--entities", required=True, help="comma-separated id:keydir pairs, e.g. server:kd,spoke-1:kd")
    m.add_argument("--signing-key", required=True, help="path to the ML-DSA-65 signing key (PEM)")
    m.add_argument("--ttl", type=float, default=3.0, help="manifest lifetime in hours (default 3)")
    m.add_argument("--out", default="manifest.json", help="output path for the signed manifest")
    m.set_defaults(func=_cmd_make)

    v = sub.add_parser("verify", help="verify a signed manifest against an anchor")
    v.add_argument("--manifest", required=True, help="path to the signed manifest")
    v.add_argument("--anchor", required=True, help="path to the verification public key (PEM)")
    v.add_argument("--max-age-s", type=int, default=10800, help="max manifest age in seconds (default 10800)")
    v.add_argument("--skew-s", type=int, default=60, help="clock-skew tolerance in seconds (default 60)")
    v.set_defaults(func=_cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ConfigurationError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
