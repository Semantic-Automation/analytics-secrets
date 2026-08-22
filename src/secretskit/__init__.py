"""Stable public interface for the analytics secrets module.

The classes exported from :mod:`secrets` are the only endpoints the
application and server code depend on.  Internal crypto, key storage and
envelope layout live in private submodules and can be replaced without
changing these signatures.
"""

from ._api import Decryptor, Encryptor, unwrap_bytes, wrap_bytes
from ._config import SecretsConfig
from ._errors import ConfigurationError, DecryptError, SecretsError, UnknownPeerError
from ._hygiene import disable_core_dumps, mlock_memory, munlock_memory, wipe
from ._keys import (
    BootKeyProvider,
    EnvKeyProvider,
    FileKeyProvider,
    KeyProvider,
    RegistryKeyProvider,
    RegistryUserProvider,
    ensure_keyring,
    generate_identity,
    load_peer_public,
    save_identity,
    save_peer,
    valid_user_id,
)
from ._hybrid import PeerPublic
from . import _manifest as manifest
from . import _signing as signing
from . import _transport_auth as transport_auth
from . import log_edge

__version__ = "0.7.1"

__all__ = [
    "BootKeyProvider",
    "ConfigurationError",
    "DecryptError",
    "Decryptor",
    "Encryptor",
    "EnvKeyProvider",
    "FileKeyProvider",
    "KeyProvider",
    "PeerPublic",
    "RegistryKeyProvider",
    "RegistryUserProvider",
    "SecretsConfig",
    "SecretsError",
    "UnknownPeerError",
    "disable_core_dumps",
    "ensure_keyring",
    "generate_identity",
    "load_peer_public",
    "log_edge",
    "manifest",
    "mlock_memory",
    "munlock_memory",
    "save_identity",
    "save_peer",
    "signing",
    "transport_auth",
    "unwrap_bytes",
    "valid_user_id",
    "wipe",
    "wrap_bytes",
]
