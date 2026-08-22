"""Configuration for the secrets module.

Dev and prod differ only in *where keys live*, never in the public API.
``SecretsConfig.from_env()`` reads a small, namespaced set of variables:

* ``SECRETS_PROVIDER``  ``file`` (default) | ``env`` | ``registry``
* ``SECRETS_KEYDIR``    key directory for the file provider
* ``SECRETS_IDENTITY``  this party's identity id
* ``SECRETS_PRIVATE_KEM``, ``SECRETS_PRIVATE_X``  base64 PEM (env provider)
* ``SECRETS_PEERS``     JSON mapping id -> {kem_pub, x_pub} (env provider)
* ``SECRETS_REGISTRY_URL``, ``SECRETS_REGISTRY_PUB``, ``SECRETS_REGISTRY_TOKEN``,
  ``SECRETS_REGISTRY_MAX_AGE``   (registry provider; ``SECRETS_REGISTRY_PUB`` is
  a PEM, a file path, or base64 PEM of the ML-DSA-65 anchor)
* ``SECRETS_REGISTRY_SIGNING_KEY``, ``SECRETS_REGISTRY_USER_ID``  (optional;
  when set the manifest fetch is authenticated with ML-DSA-65 transport
  signatures instead of a bearer token)

Moving to prod therefore means setting different environment variables —
application/server code does not change.
"""

import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from ._errors import ConfigurationError
from ._hybrid import PrivateKeys
from ._keys import EnvKeyProvider, FileKeyProvider, KeyProvider, RegistryKeyProvider

ENV_PROVIDER = "env"
FILE_PROVIDER = "file"
REGISTRY_PROVIDER = "registry"


@dataclass(frozen=True)
class SecretsConfig:
    provider: str = FILE_PROVIDER
    keydir: str | None = None
    identity: str | None = None
    kem_private_pem: str | None = None
    x_private_pem: str | None = None
    peers: dict = field(default_factory=dict)
    registry_url: str | None = None
    registry_pub: str | None = None
    registry_token: str | None = None
    registry_signing_key: str | None = None
    registry_user_id: str | None = None
    registry_max_age_s: int = 10800

    @classmethod
    def from_env(cls, env: dict | None = None) -> "SecretsConfig":
        e = env if env is not None else os.environ
        provider = e.get("SECRETS_PROVIDER", FILE_PROVIDER)
        peers: dict = {}
        raw_peers = e.get("SECRETS_PEERS")
        if raw_peers:
            try:
                peers = json.loads(raw_peers)
            except json.JSONDecodeError as exc:
                raise ConfigurationError("SECRETS_PEERS is not valid JSON") from exc
        return cls(
            provider=provider,
            keydir=e.get("SECRETS_KEYDIR"),
            identity=e.get("SECRETS_IDENTITY"),
            kem_private_pem=e.get("SECRETS_PRIVATE_KEM"),
            x_private_pem=e.get("SECRETS_PRIVATE_X"),
            peers=peers,
            registry_url=e.get("SECRETS_REGISTRY_URL"),
            registry_pub=e.get("SECRETS_REGISTRY_PUB"),
            registry_token=e.get("SECRETS_REGISTRY_TOKEN"),
            registry_signing_key=e.get("SECRETS_REGISTRY_SIGNING_KEY"),
            registry_user_id=e.get("SECRETS_REGISTRY_USER_ID"),
            registry_max_age_s=int(e.get("SECRETS_REGISTRY_MAX_AGE", "10800")),
        )

    def build_identity(self) -> PrivateKeys:
        """Build this party's private identity from file/env fields."""
        if self.keydir and self.identity:
            return FileKeyProvider(self.keydir, self.identity).identity_keys()
        if self.identity and self.kem_private_pem and self.x_private_pem:
            return EnvKeyProvider(
                identity=self.identity,
                kem_private_pem=self.kem_private_pem,
                x_private_pem=self.x_private_pem,
                peers=self.peers,
            ).identity_keys()
        raise ConfigurationError(
            "a local identity is required (SECRETS_KEYDIR+SECRETS_IDENTITY, "
            "or SECRETS_PRIVATE_KEM+SECRETS_PRIVATE_X)"
        )

    def _load_registry_verify_key(self):
        from ._manifest import load_verification_key

        value = self.registry_pub or ""
        data: bytes | None = None
        if value.startswith("-----BEGIN"):
            data = value.encode("utf-8")
        elif Path(value).is_file():
            data = Path(value).read_bytes()
        else:
            try:
                data = base64.b64decode(value, validate=True)
            except Exception as exc:
                raise ConfigurationError(
                    "SECRETS_REGISTRY_PUB must be a PEM, a file path, or base64 PEM"
                ) from exc
        return load_verification_key(data)

    def _load_registry_signing_key(self):
        """Load the optional ML-DSA-65 signing key (path or PEM) used for
        transport-auth on the manifest fetch."""
        from pathlib import Path

        from ._manifest import load_signing_key

        value = self.registry_signing_key or ""
        if not value:
            return None
        if value.startswith("-----BEGIN"):
            data = value.encode("utf-8")
        elif Path(value).is_file():
            data = Path(value).read_bytes()
        else:
            try:
                data = base64.b64decode(value, validate=True)
            except Exception as exc:
                raise ConfigurationError(
                    "SECRETS_REGISTRY_SIGNING_KEY must be a PEM, a file path, or base64 PEM"
                ) from exc
        return load_signing_key(data)

    def build_provider(self) -> KeyProvider:
        """Instantiate the configured :class:`KeyProvider`."""
        if self.provider == FILE_PROVIDER:
            if not self.keydir or not self.identity:
                raise ConfigurationError(
                    "file provider requires SECRETS_KEYDIR and SECRETS_IDENTITY"
                )
            return FileKeyProvider(self.keydir, self.identity)
        if self.provider == ENV_PROVIDER:
            if not (self.identity and self.kem_private_pem and self.x_private_pem):
                raise ConfigurationError(
                    "env provider requires SECRETS_IDENTITY, SECRETS_PRIVATE_KEM "
                    "and SECRETS_PRIVATE_X"
                )
            return EnvKeyProvider(
                identity=self.identity,
                kem_private_pem=self.kem_private_pem,
                x_private_pem=self.x_private_pem,
                peers=self.peers,
            )
        if self.provider == REGISTRY_PROVIDER:
            if not (self.registry_url and self.registry_pub):
                raise ConfigurationError(
                    "registry provider requires SECRETS_REGISTRY_URL and "
                    "SECRETS_REGISTRY_PUB"
                )
            return RegistryKeyProvider(
                self.registry_url,
                self._load_registry_verify_key(),
                identity=self.build_identity(),
                token=self.registry_token,
                signing_key=self._load_registry_signing_key(),
                user_id=self.registry_user_id or self.identity or "",
                max_age_s=self.registry_max_age_s,
            )
        raise ConfigurationError(f"unknown SECRETS_PROVIDER {self.provider!r}")
