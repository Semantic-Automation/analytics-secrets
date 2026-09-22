"""Stable public interface for the analytics secrets module.

The classes exported from :mod:`secrets` are the only endpoints the
application and server code depend on.  Internal crypto, key storage and
envelope layout live in private submodules and can be replaced without
changing these signatures.
"""

from ._api import Decryptor, Encryptor, unwrap_bytes, wrap_bytes
from ._config import SecretsConfig
from ._errors import (
    AuthError,
    ConfigurationError,
    DecryptError,
    SecretsError,
    UnknownPeerError,
)
from ._user_auth import VerifiedIdentity
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
from . import _dpop as dpop
from . import _manifest as manifest
from . import _oidc as oidc
from . import _signing as signing
from . import _tiers as tiers
from . import _transport_auth as transport_auth
from . import _user_auth as user_auth
from . import log_edge

__version__ = "0.8.0"

__all__ = [
    "AuthError",
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
    "VerifiedIdentity",
    "disable_core_dumps",
    "dpop",
    "ensure_keyring",
    "generate_identity",
    "load_peer_public",
    "log_edge",
    "manifest",
    "mlock_memory",
    "munlock_memory",
    "oidc",
    "save_identity",
    "save_peer",
    "signing",
    "tiers",
    "transport_auth",
    "unwrap_bytes",
    "user_auth",
    "valid_user_id",
    "wipe",
    "wrap_bytes",
]
