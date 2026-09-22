"""Named tier ladder for the human status gate.

Tiers are Keycloak realm roles; a user carries exactly one. The gate is a
**rank comparison**, not a hardcoded role name, so adding a tier is a one-line
change here plus the realm role — no resource-server or contract change.

See ``analytics-wiki/architecture/user-platform/10-auth-service.md`` §3 and
``11-resource-server-auth.md`` §5.
"""

from __future__ import annotations

from typing import Iterable, Mapping

TIER_ORDER: tuple[str, ...] = ("pending", "active")
TIER_FLOOR: str = "active"

_RANK = {name: i for i, name in enumerate(TIER_ORDER)}


def realm_roles(claims: Mapping) -> frozenset[str]:
    """Return the ``realm_access.roles`` set from a token claims mapping."""
    access = claims.get("realm_access") or {}
    roles = access.get("roles") if isinstance(access, Mapping) else None
    return frozenset(str(r) for r in (roles or ()))


def tier_of(subject: Mapping | Iterable[str]) -> str | None:
    """Highest tier present.

    ``subject`` may be a token claims mapping or an explicit role iterable.
    Unknown roles are ignored; several tiers resolve to the highest.
    """
    roles = realm_roles(subject) if isinstance(subject, Mapping) else frozenset(subject)
    for name in reversed(TIER_ORDER):
        if name in roles:
            return name
    return None


def has_tier_floor(subject: Mapping | Iterable[str]) -> bool:
    """True when the subject's tier ranks at or above :data:`TIER_FLOOR`."""
    tier = tier_of(subject)
    return tier is not None and _RANK[tier] >= _RANK[TIER_FLOOR]
