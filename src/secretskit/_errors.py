"""Exception hierarchy for the secrets module."""


class SecretsError(Exception):
    """Base class for all secrets module errors."""


class ConfigurationError(SecretsError):
    """Invalid or missing configuration / key material."""


class UnknownPeerError(SecretsError):
    """Requested peer is not present in the key provider."""


class DecryptError(SecretsError):
    """Envelope could not be decrypted or is malformed."""
