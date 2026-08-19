"""Trusted logging edge — E2EE capture of prompt/response pairs (dev/testing).

Senders wrap each plaintext record in a signed document and encrypt it to
the logger's key.  The logger is the *only* party that materialises the
plaintext, and it stores it in plaintext JSONL for development visibility.

    server encryptor ──sign + encrypt to logger──► /log (kind=prompt)
    spoke wrapper    ──sign + encrypt to logger──► /log (kind=response)

Wire format (``POST {url}/log``)::

    {"kind": "prompt" | "response",
     "envelope": "<base64 envelope containing the signed record>"}

The record inside the envelope is a signed document (see
:mod:`secretskit._signing`) whose ``data`` is JSON::

    {"kind": ..., "request_id": ..., "endpoint": ...,
     "call": ..., "model": ..., "prompt": ... or "response": ...}

The logger correlates halves by ``request_id`` and appends plaintext lines
to ``records.jsonl`` / ``pairs.jsonl``.

Enabled only when ``LOG_EDGE_URL`` is set.  ``LogEdgeClient`` never raises
from a caller's perspective — the logging edge must never break the LLM
path.  Pass ``strict=True`` to surface failures (tests).
"""

import base64
import json
import os
import urllib.request
import urllib.error

from ._errors import ConfigurationError, UnknownPeerError
from ._hybrid import PeerPublic
from ._keys import KeyProvider, _load_kem_public, _load_x_public
from ._manifest import load_signing_key
from ._api import Encryptor

_ENV = {
    "url": "LOG_EDGE_URL",
    "token": "LOG_EDGE_TOKEN",
    "sender_id": "LOG_EDGE_SENDER_ID",
    "signing_key": "LOG_EDGE_SIGNING_KEY",
    "logger_id": "LOG_EDGE_LOGGER_ID",
    "max_age_s": "LOG_EDGE_MAX_AGE_S",
}


def _as_text(value) -> str:
    """Coerce a prompt/response payload to JSON-serialisable text."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


class LogEdgeConfig:
    """Configuration for a ``LogEdgeClient`` sender.

    Parameters mirror the ``LOG_EDGE_*`` environment variables; a sender's
    identity defaults to the secrets identity (``SECRETS_IDENTITY`` /
    ``SECRETS_SIGNING_KEY``) so server and spoke need no new key config.
    """

    def __init__(
        self,
        url: str = "",
        token: str = "",
        sender_id: str = "",
        signing_key: str = "",
        logger_id: str = "logsink-1",
        max_age_s: int = 3600,
    ):
        self.url = (url or "").strip()
        self.token = (token or "").strip()
        self.sender_id = sender_id
        self.signing_key = signing_key
        self.logger_id = logger_id or "logsink-1"
        self.max_age_s = max_age_s

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    @classmethod
    def from_env(cls, env: dict | None = None) -> "LogEdgeConfig":
        e = env if env is not None else os.environ
        return cls(
            url=e.get(_ENV["url"], ""),
            token=e.get(_ENV["token"], ""),
            sender_id=(
                e.get(_ENV["sender_id"], "")
                or e.get("SECRETS_IDENTITY", "")
                or e.get("E2EE_USER_ID", "")
            ),
            signing_key=(
                e.get(_ENV["signing_key"], "")
                or e.get("SECRETS_SIGNING_KEY", "")
            ),
            logger_id=e.get(_ENV["logger_id"], "logsink-1"),
            max_age_s=int(e.get(_ENV["max_age_s"], "3600")),
        )


class _StaticPeerProvider(KeyProvider):
    """A KeyProvider whose peers are supplied directly (logger keys)."""

    def __init__(self, peers: dict[str, PeerPublic]):
        self._peers = peers

    def identity_keys(self):
        raise ConfigurationError("StaticPeerProvider has no identity (encrypt-only)")

    def peer_public(self, peer_id: str) -> PeerPublic:
        try:
            return self._peers[peer_id]
        except KeyError as exc:
            raise UnknownPeerError(f"unknown peer {peer_id!r}") from exc

    def peer_ids(self) -> list[str]:
        return sorted(self._peers)


class LogEdgeClient:
    """Sends signed, E2EE-encrypted prompt/response records to the logger.

    The same client is used by both senders: the server encryptor sends
    ``kind="prompt"`` records (one per internal LLM call) and the spoke
    wrapper sends ``kind="response"`` records (one per LLM reply), both
    tagged with the request's ``request_id``.
    """

    def __init__(
        self,
        config: LogEdgeConfig,
        *,
        strict: bool = False,
        poster=None,
        background: bool = False,
        signing=None,
    ):
        self._cfg = config
        self._strict = strict
        self._poster = poster
        self._background = background
        self._enc: Encryptor | None = None
        self._signing = signing
        self._peer: PeerPublic | None = None

    @property
    def enabled(self) -> bool:
        return self._cfg.enabled

    def send_prompt(self, request_id: str, prompt, *, endpoint: str = "", call: str = "", model: str = "") -> None:
        """Send a prompt copy for one LLM call."""
        record = {
            "kind": "prompt",
            "request_id": request_id,
            "endpoint": endpoint,
            "call": call,
            "model": model,
            "prompt": _as_text(prompt),
        }
        self._deliver(record)

    def send_response(self, request_id: str, response, *, endpoint: str = "", call: str = "") -> None:
        """Send a response copy for one LLM call."""
        record = {
            "kind": "response",
            "request_id": request_id,
            "endpoint": endpoint,
            "call": call,
            "response": _as_text(response),
        }
        self._deliver(record)

    def _ensure(self) -> tuple[Encryptor, object]:
        if self._enc is None:
            self._peer = self._fetch_logger_keys()
            self._enc = Encryptor(provider=_StaticPeerProvider({self._cfg.logger_id: self._peer}))
            if self._signing is None:
                if not self._cfg.signing_key:
                    raise ConfigurationError(
                        "LogEdgeClient requires a signing key (LOG_EDGE_SIGNING_KEY "
                        "or SECRETS_SIGNING_KEY, or pass signing=)"
                    )
                with open(self._cfg.signing_key, "rb") as fh:
                    self._signing = load_signing_key(fh.read())
        return self._enc, self._signing

    def _fetch_logger_keys(self) -> PeerPublic:
        """Fetch the logger's public keys from ``GET {url}/keys``."""
        url = f"{self._cfg.url.rstrip('/')}/keys"
        try:
            with urllib.request.urlopen(self._signed_request(url), timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise ConfigurationError(f"log edge /keys fetch failed: {exc}") from exc
        try:
            return PeerPublic(
                id=body.get("id", self._cfg.logger_id),
                kem=_load_kem_public(base64.b64decode(body["kem_pub"])),
                x=_load_x_public(base64.b64decode(body["x_pub"])),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise ConfigurationError("log edge /keys returned invalid keys") from exc

    def _signed_request(self, url: str) -> urllib.request.Request:
        req = urllib.request.Request(url)
        if self._signing and self._cfg.sender_id:
            from ._transport_auth import sign_request
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path or "/"
            headers = sign_request(
                self._signing,
                spoke_id=self._cfg.sender_id,
                method="GET",
                path=path,
            )
            for k, v in headers.items():
                req.add_header(k, v)
        elif self._cfg.token:
            req.add_header("Authorization", f"Bearer {self._cfg.token}")
        return req

    def _deliver(self, record: dict) -> None:
        if not self._cfg.enabled:
            return
        if self._background:
            # Best-effort: never block the LLM path.  Daemon thread keeps the
            # delivery out of the request's critical path.
            import threading

            threading.Thread(target=self._deliver_sync, args=(record,), daemon=True).start()
            return
        self._deliver_sync(record)

    def _deliver_sync(self, record: dict) -> None:
        try:
            enc, signing = self._ensure()
            from . import _signing

            signed = _signing.sign(
                json.dumps(record, ensure_ascii=False).encode("utf-8"),
                signing,
                user_id=self._cfg.sender_id or enc.identity,
                request_id=record["request_id"],
            )
            envelope = base64.b64encode(enc.encrypt_chunk(signed, to=self._cfg.logger_id)).decode("ascii")
            body = json.dumps({"kind": record["kind"], "envelope": envelope}).encode("utf-8")
            self._post(f"{self._cfg.url.rstrip('/')}/log", body)
        except Exception as exc:  # noqa: BLE001 - the logging edge is best-effort
            if self._strict:
                raise
            print(f"[log_edge] failed to deliver {record['kind']} record: {exc}", file=os.sys.stderr)

    def _post(self, url: str, data: bytes) -> None:
        if self._poster is not None:
            self._poster(url, data, self._cfg.token)
            return
        req = urllib.request.Request(
            url, data=data, method="POST", headers={"Content-Type": "application/json"}
        )
        if self._signing and self._cfg.sender_id:
            from ._transport_auth import sign_request
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path or "/"
            headers = sign_request(
                self._signing,
                spoke_id=self._cfg.sender_id,
                method="POST",
                path=path,
            )
            for k, v in headers.items():
                req.add_header(k, v)
        elif self._cfg.token:
            req.add_header("Authorization", f"Bearer {self._cfg.token}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
