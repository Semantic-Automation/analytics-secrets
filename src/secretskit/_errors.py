"""Exception hierarchy for the secrets module."""


class SecretsError(Exception):
    """Base class for all secrets module errors."""


class ConfigurationError(SecretsError):
    """Invalid or missing configuration / key material."""


class UnknownPeerError(SecretsError):
    """Requested peer is not present in the key provider."""


class DecryptError(SecretsError):
    """Envelope could not be decrypted or is malformed."""


class AuthError(SecretsError):
    """Human token / DPoP verification failed (see user_auth)."""

    def __init__(self, error: str, description: str = "", *, status: int = 401):
        super().__init__(f"{error}: {description}" if description else error)
        self.error = error
        self.description = description
        self.status = status

    def challenge(self) -> str:
        """Value for the ``WWW-Authenticate`` response header."""
        parts = [f'error="{self.error}"']
        if self.description:
            parts.append(f'error_description="{self.description}"')
        return "DPoP " + ", ".join(parts)
