"""Key management.

The :class:`KeyProvider` abstraction decouples the public API from where
keys come from.  Two providers ship with the module:

* :class:`FileKeyProvider` — dev: a directory of PEM files,
* :class:`EnvKeyProvider` — base64 PEM carried in environment variables
  (suitable for CI / edge deployments without a filesystem).

A production provider (e.g. KMS-backed) can be added later behind the
same interface without touching application or server code.

File layout for ``FileKeyProvider(keydir, identity)``:

* ``<identity>.kem.pem``  PKCS8 ML-KEM-768 private key
* ``<identity>.x.pem``    PKCS8 X25519 private key
* ``<peer>.kem.pub.pem``  SPKI ML-KEM-768 public key (for each peer)
* ``<peer>.x.pub.pem``    SPKI X25519 public key (for each peer)

The ``generate_identity`` / ``save_identity`` / ``save_peer`` helpers
build a keyring for dev bring-up.
"""

import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa, x25519

from . import _manifest
from ._errors import ConfigurationError, DecryptError, UnknownPeerError

# Matches the registry/keyhub identity rule: a DNS-label-safe id.  Anything
# else (path traversal, URL metacharacters, whitespace) is rejected before it
# can be interpolated into a registry fetch URL (H8 SSRF guard).
USER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def valid_user_id(user_id: str) -> bool:
    """True when ``user_id`` is safe to embed in a registry path."""
    return bool(USER_ID_RE.match(user_id))
from ._hybrid import PeerPublic, PrivateKeys

_PKCS8 = serialization.PrivateFormat.PKCS8
_SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
_PEM = serialization.Encoding.PEM

_OPEN_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_TRUNC


def _write_private_pem(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Write a private-key PEM with owner-only permissions (H3).

    The mode is set at open time (not after a write) so the file is never
    world-readable even transiently; a belt-and-braces ``chmod`` also guards
    against a permissive umask.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), _OPEN_FLAGS, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    os.chmod(path, mode)


def _load_kem_private(data: bytes) -> mlkem.MLKEM768PrivateKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, mlkem.MLKEM768PrivateKey):
        raise ConfigurationError("expected an ML-KEM-768 private key")
    return key


def _load_x_private(data: bytes) -> x25519.X25519PrivateKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, x25519.X25519PrivateKey):
        raise ConfigurationError("expected an X25519 private key")
    return key


def _load_kem_public(data: bytes) -> mlkem.MLKEM768PublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, mlkem.MLKEM768PublicKey):
        raise ConfigurationError("expected an ML-KEM-768 public key")
    return key


def _load_x_public(data: bytes) -> x25519.X25519PublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, x25519.X25519PublicKey):
        raise ConfigurationError("expected an X25519 public key")
    return key


def generate_identity(identity_id: str) -> PrivateKeys:
    """Create a fresh long-term identity (ML-KEM-768 + X25519)."""
    return PrivateKeys(
        id=identity_id,
        kem=mlkem.MLKEM768PrivateKey.generate(),
        x=x25519.X25519PrivateKey.generate(),
    )


def save_identity(priv: PrivateKeys, keydir: Path) -> None:
    """Persist an identity as PEM files in ``keydir`` (owner-only perms, H3)."""
    keydir = Path(keydir)
    keydir.mkdir(parents=True, exist_ok=True)
    _write_private_pem(
        keydir / f"{priv.id}.kem.pem",
        priv.kem.private_bytes(_PEM, _PKCS8, serialization.NoEncryption()),
    )
    _write_private_pem(
        keydir / f"{priv.id}.x.pem",
        priv.x.private_bytes(_PEM, _PKCS8, serialization.NoEncryption()),
    )


def save_peer(peer, keydir: Path) -> None:
    """Persist a peer's public keys as PEM files in ``keydir``.

    ``peer`` may be a :class:`PeerPublic` or a :class:`PrivateKeys`
    (public half is derived) for ergonomic dev keyring setup.
    """
    keydir = Path(keydir)
    keydir.mkdir(parents=True, exist_ok=True)
    kem = peer.kem.public_key() if hasattr(peer.kem, "public_key") else peer.kem
    x = peer.x.public_key() if hasattr(peer.x, "public_key") else peer.x
    (keydir / f"{peer.id}.kem.pub.pem").write_bytes(kem.public_bytes(_PEM, _SPKI))
    (keydir / f"{peer.id}.x.pub.pem").write_bytes(x.public_bytes(_PEM, _SPKI))


def _default_hostname() -> str:
    """A sanitized, DNS-label-safe hostname for the spoke's identity/magicDNS."""
    import re
    import socket

    name = socket.gethostname().split(".")[0].lower()
    name = re.sub(r"[^a-z0-9-]", "-", name).strip("-")[:63]
    return name or "spoke"


def ensure_keyring(keydir, identity_id: str, *, signing: bool = False) -> Path:
    """Generate an identity into ``keydir`` if its key files are missing.

    Idempotent clean-room onboarding: on first start a service calls this and
    it mints ``<identity_id>.kem.pem`` / ``<identity_id>.x.pem`` (and with
    ``signing=True`` also ``<identity_id>.sign.pem``) only if they don't
    already exist.  Existing keys are never overwritten.
    """
    keydir = Path(keydir)
    keydir.mkdir(parents=True, exist_ok=True)
    if not (keydir / f"{identity_id}.kem.pem").exists():
        save_identity(generate_identity(identity_id), keydir)
    if signing and not (keydir / f"{identity_id}.sign.pem").exists():
        _write_private_pem(
            keydir / f"{identity_id}.sign.pem",
            _manifest.generate_signing_key().private_bytes(
                _PEM, _PKCS8, serialization.NoEncryption()
            ),
        )
    return keydir


def load_peer_public(*, peer_id: str, kem_pub: bytes, x_pub: bytes) -> PeerPublic:
    """Build a :class:`PeerPublic` from raw PEM public keys (for :func:`wrap_bytes`)."""
    return PeerPublic(
        id=peer_id,
        kem=_load_kem_public(kem_pub),
        x=_load_x_public(x_pub),
    )


class KeyProvider(ABC):
    """Supplies this party's identity and the public keys of its peers."""

    @abstractmethod
    def identity_keys(self) -> PrivateKeys:
        """This party's long-term private identity."""

    @abstractmethod
    def peer_public(self, peer_id: str) -> PeerPublic:
        """A recipient's long-term public keys; raises
        :class:`UnknownPeerError` if absent."""

    @abstractmethod
    def peer_ids(self) -> list[str]:
        """Identifiers of all configured peers."""


class FileKeyProvider(KeyProvider):
    """Directory-backed provider (development / single machine)."""

    def __init__(self, keydir, identity: str):
        self._dir = Path(keydir)
        self._identity_id = identity
        if not self._dir.is_dir():
            raise ConfigurationError(f"key directory does not exist: {self._dir}")
        self._identity = self._load_identity()
        self._peers = self._discover_peers()
        self._pinned: list[bytearray] = []

    def _load_identity(self) -> PrivateKeys:
        from ._hygiene import mlock_memory

        try:
            kem_raw = bytearray((self._dir / f"{self._identity_id}.kem.pem").read_bytes())
            x_raw = bytearray((self._dir / f"{self._identity_id}.x.pem").read_bytes())
            kem = _load_kem_private(bytes(kem_raw))
            x = _load_x_private(bytes(x_raw))
        except FileNotFoundError as exc:
            raise ConfigurationError(
                f"identity {self._identity_id!r} missing key files in {self._dir}"
            ) from exc
        # H3: pin the raw PEM bytes into RAM (mlock) so a swap-out / core-dump
        # can't spill the decrypt keys to disk. Best-effort; no-op if unsupported.
        self._pinned = [b for b in (kem_raw, x_raw) if mlock_memory(b)]
        return PrivateKeys(id=self._identity_id, kem=kem, x=x)

    def _wipe_pinned(self) -> None:
        """Zero + release the mlock'd key bytes (call on shutdown)."""
        from ._hygiene import wipe

        for buf in self._pinned:
            wipe(buf)
        self._pinned = []

    def _discover_peers(self) -> dict[str, PeerPublic]:
        peers: dict[str, PeerPublic] = {}
        for kem_pub in self._dir.glob("*.kem.pub.pem"):
            peer_id = kem_pub.name[: -len(".kem.pub.pem")]
            x_pub = self._dir / f"{peer_id}.x.pub.pem"
            if not x_pub.exists():
                raise ConfigurationError(f"peer {peer_id!r} has kem pub but no x pub")
            peers[peer_id] = PeerPublic(
                id=peer_id,
                kem=_load_kem_public(kem_pub.read_bytes()),
                x=_load_x_public(x_pub.read_bytes()),
            )
        return peers

    def identity_keys(self) -> PrivateKeys:
        return self._identity

    def peer_public(self, peer_id: str) -> PeerPublic:
        try:
            return self._peers[peer_id]
        except KeyError as exc:
            raise UnknownPeerError(f"unknown peer {peer_id!r}") from exc

    def peer_ids(self) -> list[str]:
        return sorted(self._peers)


@dataclass(frozen=True)
class EnvKeyProvider(KeyProvider):
    """Environment-variable-backed provider.

    Expects ``SECRETS_IDENTITY`` (id string), ``SECRETS_PRIVATE_KEM`` and
    ``SECRETS_PRIVATE_X`` (base64 PEM private keys) and ``SECRETS_PEERS``
    (JSON mapping peer id -> ``{"kem_pub": ..., "x_pub": ...}`` base64 PEM).
    """

    identity: str
    kem_private_pem: str
    x_private_pem: str
    peers: dict

    def __post_init__(self) -> None:
        object.__setattr__(self, "_identity", self._load_identity())
        object.__setattr__(self, "_peers", self._load_peers())

    def _load_identity(self) -> PrivateKeys:
        import base64

        def b64(pem: str) -> bytes:
            try:
                return base64.b64decode(pem.encode("ascii"), validate=True)
            except Exception as exc:
                raise ConfigurationError("invalid base64 key in environment") from exc

        return PrivateKeys(
            id=self.identity,
            kem=_load_kem_private(b64(self.kem_private_pem)),
            x=_load_x_private(b64(self.x_private_pem)),
        )

    def _load_peers(self) -> dict[str, PeerPublic]:
        import base64

        out: dict[str, PeerPublic] = {}
        for peer_id, material in self.peers.items():
            out[peer_id] = PeerPublic(
                id=peer_id,
                kem=_load_kem_public(base64.b64decode(material["kem_pub"])),
                x=_load_x_public(base64.b64decode(material["x_pub"])),
            )
        return out

    def identity_keys(self) -> PrivateKeys:
        return self._identity

    def peer_public(self, peer_id: str) -> PeerPublic:
        try:
            return self._peers[peer_id]
        except KeyError as exc:
            raise UnknownPeerError(f"unknown peer {peer_id!r}") from exc

    def peer_ids(self) -> list[str]:
        return sorted(self._peers)


def _fetch(url: str, token: str | None, fetcher) -> bytes:
    """Fetch ``url`` bytes. ``fetcher`` may be a callable ``(url, token) ->
    bytes`` (defaults to stdlib ``urllib``); used for tests/injection."""
    if fetcher is not None:
        return fetcher(url, token)
    import urllib.request

    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


class RegistryKeyProvider(KeyProvider):
    """Manifest-backed provider: peers come from an ops-signed manifest.

    The manifest is fetched from ``url`` and verified against
    ``verify_key`` — the pre-provisioned ML-DSA-65 anchor. The party's own
    identity is supplied separately (local keyring, boot release, etc.);
    it is never part of the manifest.

    Dev can keep using :class:`FileKeyProvider`; ``RegistryKeyProvider``
    is the prod mechanism. Both implement :class:`KeyProvider`, so the
    public API is unchanged.
    """

    def __init__(
        self,
        url: str,
        verify_key,
        identity: PrivateKeys | None = None,
        *,
        token: str | None = None,
        fetcher=None,
        max_age_s: int = 10800,
        skew_s: int = 60,
    ):
        self._url = url
        self._verify_key = verify_key
        self._identity = identity
        self._token = token
        self._max_age_s = max_age_s
        self._skew_s = skew_s
        self._peers = self._load_manifest(fetcher)

    def _load_manifest(self, fetcher) -> dict[str, PeerPublic]:
        import base64

        payload = _fetch(self._url, self._token, fetcher)
        doc = _manifest.verify(
            payload, self._verify_key, max_age_s=self._max_age_s, skew_s=self._skew_s
        )
        peers: dict[str, PeerPublic] = {}
        for peer_id, material in doc["entities"].items():
            peers[peer_id] = PeerPublic(
                id=peer_id,
                kem=_load_kem_public(base64.b64decode(material["kem_pub"])),
                x=_load_x_public(base64.b64decode(material["x_pub"])),
            )
        return peers

    def identity_keys(self) -> PrivateKeys:
        if self._identity is None:
            raise ConfigurationError(
                "RegistryKeyProvider has no local identity configured"
            )
        return self._identity

    def peer_public(self, peer_id: str) -> PeerPublic:
        try:
            return self._peers[peer_id]
        except KeyError as exc:
            raise UnknownPeerError(f"unknown peer {peer_id!r}") from exc

    def peer_ids(self) -> list[str]:
        return sorted(self._peers)


@dataclass(frozen=True)
class UserPublicKeys:
    """A registered user's three public keys (as stored in the user registry)."""

    user_id: str
    signing: mldsa.MLDSA65PublicKey
    kem: mlkem.MLKEM768PublicKey
    x: x25519.X25519PublicKey


def _load_mldsa_public(data: bytes) -> mldsa.MLDSA65PublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, mldsa.MLDSA65PublicKey):
        raise ConfigurationError("expected an ML-DSA-65 public key")
    return key


class RegistryUserProvider(KeyProvider):
    """User-registry-backed provider, used on the spoke.

    The spoke's identity is its own keys (for decrypting incoming
    envelopes); its *peers* are registered users (for encrypting responses
    back to them).  User keys are fetched from the user registry on demand
    and cached.  ``signing_public(user_id)`` is exposed separately for
    request-signature verification.
    """

    def __init__(
        self,
        registry_url: str,
        identity: PrivateKeys | None = None,
        *,
        token: str | None = None,
        signing_key=None,
        spoke_id: str = "",
        fetcher=None,
        cache_ttl_s: int = 300,
    ):
        self._base = registry_url.rstrip("/")
        self._identity = identity
        self._token = token
        self._signing_key = signing_key
        self._spoke_id = spoke_id
        self._fetcher = fetcher
        self._cache_ttl_s = cache_ttl_s
        self._users: dict[str, tuple[float, UserPublicKeys]] = {}

    def _fetch_user(self, user_id: str) -> UserPublicKeys:
        import base64
        import json
        import time
        import urllib.request

        # H8 SSRF guard: never interpolate a caller-controlled id into a
        # registry URL.  Invalid ids fail closed as an unknown user (the
        # caller sees 401/404) rather than ever reaching the network.
        if not valid_user_id(user_id):
            raise UnknownPeerError(f"invalid user_id {user_id!r}")

        now = time.time()
        cached = self._users.get(user_id)
        if cached and cached[0] > now:
            return cached[1]
        try:
            url = f"{self._base}/users/{user_id}"
            if self._signing_key and self._spoke_id:
                from ._transport_auth import sign_request
                headers = sign_request(
                    self._signing_key,
                    spoke_id=self._spoke_id,
                    method="GET",
                    path=f"/users/{user_id}",
                )
                req = urllib.request.Request(url)
                for k, v in headers.items():
                    req.add_header(k, v)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read()
            elif self._fetcher:
                raw = self._fetcher(url, self._token)
            else:
                raw = _fetch(url, self._token, None)
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code == 404:
                raise UnknownPeerError(f"unknown user {user_id!r}") from exc
            raise ConfigurationError(f"user registry lookup failed: {exc}") from exc
        try:
            data = json.loads(raw.decode("utf-8"))
            record = UserPublicKeys(
                user_id=data["user_id"],
                signing=_load_mldsa_public(base64.b64decode(data["signing_pub"])),
                kem=_load_kem_public(base64.b64decode(data["kem_pub"])),
                x=_load_x_public(base64.b64decode(data["x_pub"])),
            )
        except (KeyError, ValueError, TypeError, UnicodeDecodeError) as exc:
            raise ConfigurationError("user registry returned invalid keys") from exc
        self._users[user_id] = (now + self._cache_ttl_s, record)
        return record

    def peer_public(self, peer_id: str) -> PeerPublic:
        record = self._fetch_user(peer_id)
        return PeerPublic(id=record.user_id, kem=record.kem, x=record.x)

    def signing_public(self, user_id: str) -> mldsa.MLDSA65PublicKey:
        return self._fetch_user(user_id).signing

    def identity_keys(self) -> PrivateKeys:
        if self._identity is None:
            raise ConfigurationError(
                "RegistryUserProvider has no local identity configured"
            )
        return self._identity

    def peer_ids(self) -> list[str]:
        return sorted(self._users)


class BootKeyProvider(KeyProvider):
    """KeyProvider whose identity is released by a trusted hub at boot (§9.4).

    The spoke holds **no keys at rest**: its ML-KEM-768 + X25519 identity and
    its ML-DSA-65 signing key are fetched from the hub (a trusted, low-compute
    key-release edge on the operator's machine) at startup, kept in memory
    (best-effort ``mlock``), and wiped on :meth:`wipe` / shutdown.  Peer
    lookups (the registered users the spoke must encrypt responses back to)
    are delegated to a ``peers`` provider — typically a
    :class:`RegistryUserProvider`.

    **Onboarding approval** (§enrollment-approval): until an admin approves the
    spoke's enrollment on the hub, the release returns 403.  ``BootKeyProvider``
    handles this handshake itself — it submits the pending enrollment request
    (its enrollment public keys from ``enroll_keydir``, generated if absent)
    and polls with backoff until the hub releases, printing a "waiting for
    admin approval" hint.  A rejected enrollment fails fast.  No bearer token
    is required for the release: the ML-KEM envelope (wrapped to the approved
    enrollment key) is the authorization.

    Wire format from ``GET {url}/keys/identities/{id}``::

        {"id": "...", "kem_pem": "<base64 PEM>", "x_pem": "<base64 PEM>",
         "sign_pem": "<base64 PEM>"}

    or, once enrolled, ``{"id": "...", "envelope": "<base64>"}`` (app-layer PQ).

    With no keys at rest on the spoke, revocation is immediate: remove the
    spoke's keyring from the hub (and drop it from the user registry) and its
    next boot can't obtain keys, so it can never decrypt again.
    """

    def __init__(
        self,
        identity_url: str,
        identity_token: str,
        identity_id: str,
        *,
        peers: KeyProvider,
        fetcher=None,
        enroll_keydir: str | None = None,
        label: str = "",
        hostname: str = "",
        approve_url: str = "",
        backoff_s: float = 10.0,
        submitter=None,
    ):
        self._url = identity_url.rstrip("/")
        self._token = identity_token
        self._identity_id = identity_id
        self._peers = peers
        self._fetcher = fetcher
        self._enroll_keydir = enroll_keydir
        self._label = label
        self._hostname = hostname or _default_hostname()
        self._approve_url = approve_url
        self._backoff_s = backoff_s
        self._submitter = submitter
        self._identity: PrivateKeys | None = None
        self._signing = None
        self._pem: bytearray | None = None

    def _load(self) -> None:
        import base64
        import json

        if self._identity is not None:
            return
        raw, doc = self._fetch_identity_with_enrollment()
        try:
            if "envelope" in doc:
                # App-layer PQ release: unwrap with the enrollment key.
                if not self._enroll_keydir:
                    raise ConfigurationError(
                        "keyhub returned an envelope but no BOOT_ENROLL_KEYDIR is configured"
                    )
                from ._api import unwrap_bytes

                plain = unwrap_bytes(
                    FileKeyProvider(self._enroll_keydir, self._identity_id).identity_keys(),
                    base64.b64decode(doc["envelope"], validate=True),
                )
                material = json.loads(plain.decode("utf-8"))
            else:
                material = doc
            self._identity = PrivateKeys(
                id=material["id"],
                kem=_load_kem_private(base64.b64decode(material["kem_pem"])),
                x=_load_x_private(base64.b64decode(material["x_pem"])),
            )
            self._signing = _manifest.load_signing_key(
                base64.b64decode(material["sign_pem"])
            )
        except (KeyError, ValueError, TypeError, UnicodeDecodeError, DecryptError) as exc:
            raise ConfigurationError("hub returned invalid identity material") from exc
        try:
            from ._hygiene import mlock_memory

            self._pem = bytearray(raw)
            mlock_memory(self._pem)
        except Exception:  # pragma: no cover - best-effort
            self._pem = None

    def _fetch_identity_with_enrollment(self) -> tuple[bytes, dict]:
        """Fetch the identity, driving the onboarding-approval handshake.

        Until an admin approves, keyhub returns 403; this either submits the
        pending enrollment (first time / after expiry) and/or polls with
        backoff.  A rejected enrollment fails fast.  Transient network errors
        retry like a pending approval (keyhub may still be starting).
        """
        import json
        import time
        import urllib.error

        attempts = 0
        while True:
            try:
                raw = _fetch(
                    f"{self._url}/keys/identities/{self._identity_id}",
                    self._token, self._fetcher,
                )
                return raw, json.loads(raw.decode("utf-8"))
            except urllib.error.HTTPError as exc:
                detail = self._http_detail(exc)
                if exc.code == 403 and "rejected" in detail:
                    raise ConfigurationError(
                        f"enrollment rejected by admin ({self._identity_id}): {detail}"
                    ) from exc
                if exc.code == 403 and "no enrollment request" in detail:
                    self._submit_pending()
                    self._wait_for_approval(attempts)
                    attempts += 1
                    continue
                if exc.code == 403 and "pending approval" in detail:
                    self._wait_for_approval(attempts)
                    attempts += 1
                    continue
                raise ConfigurationError(
                    f"hub error fetching identity for {self._identity_id} "
                    f"({exc.code}): {detail}"
                ) from exc
            except (urllib.error.URLError, OSError, TimeoutError):
                self._wait_for_approval(attempts)
                attempts += 1

    @staticmethod
    def _http_detail(exc) -> str:
        try:
            return exc.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - detail is cosmetic
            return str(exc)

    def _wait_for_approval(self, attempts: int) -> None:
        import time

        if attempts == 0 or attempts % 6 == 0:
            where = f" at {self._approve_url}" if self._approve_url else ""
            print(
                f"[spoke] enrollment for {self._identity_id!r} pending admin "
                f"approval{where} — waiting…",
                flush=True,
            )
        delay = min(self._backoff_s * (2 ** min(attempts // 3, 3)), 60.0)
        time.sleep(delay)

    def _submit_pending(self) -> None:
        """Submit (or refresh) the pending enrollment request with the spoke's
        enrollment public keys.  Generates the enrollment keypair if absent."""
        import base64
        import json
        import urllib.error
        import urllib.request
        from cryptography.hazmat.primitives import serialization

        if not self._enroll_keydir:
            raise ConfigurationError(
                "identity requires admin approval but no BOOT_ENROLL_KEYDIR is "
                "configured to submit an enrollment request"
            )
        ensure_keyring(self._enroll_keydir, self._identity_id)
        enroll = FileKeyProvider(self._enroll_keydir, self._identity_id).identity_keys()

        def _b64_pub(key) -> str:
            return base64.b64encode(
                key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).decode("ascii")

        body = json.dumps({
            "id": self._identity_id,
            "label": self._label,
            "hostname": self._hostname,
            "kem_pub": _b64_pub(enroll.kem.public_key()),
            "x_pub": _b64_pub(enroll.x.public_key()),
        }).encode("utf-8")
        url = f"{self._url}/keys/enrollments"
        if self._submitter is not None:
            self._submitter(url, body)
            print(f"[spoke] submitted enrollment request for {self._identity_id!r}", flush=True)
            return
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp.read()
            print(f"[spoke] submitted enrollment request for {self._identity_id!r}", flush=True)
        except urllib.error.HTTPError as exc:
            if exc.code == 409:
                print(f"[spoke] enrollment already exists for {self._identity_id!r}", flush=True)
            elif exc.code == 429:
                print("[spoke] enrollment submission rate-limited — retrying", flush=True)
            else:
                raise ConfigurationError(
                    f"enrollment submission failed ({exc.code}): {self._http_detail(exc)}"
                ) from exc

    def identity_keys(self) -> PrivateKeys:
        self._load()
        return self._identity

    def signing_key(self):
        """The spoke's ML-DSA-65 signing key (for request/record signatures)."""
        self._load()
        return self._signing

    def signing_public(self, user_id: str) -> mldsa.MLDSA65PublicKey:
        """Delegate user signature verification to the peers provider."""
        return self._peers.signing_public(user_id)

    def peer_public(self, peer_id: str) -> PeerPublic:
        return self._peers.peer_public(peer_id)

    def peer_ids(self) -> list[str]:
        return self._peers.peer_ids()

    def wipe(self) -> None:
        """Drop all cached key material (call on shutdown)."""
        from ._hygiene import wipe as _wipe

        if self._pem is not None:
            _wipe(self._pem)
        self._pem = None
        self._identity = None
        self._signing = None
