"""Implémentation de démonstration du port ``ClaimsProvider``.

Résout des claims utilisateur à partir d'un annuaire de profils injecté au
constructeur. Les données de démonstration ne sont pas en dur dans le code :
elles sont déclarées dans ``config.toml`` (`THEPUROIDC_USERINFO_PROFILES`).
Une vraie base d'utilisateurs implémenterait le même port pour alimenter
``/userinfo``.
"""

from __future__ import annotations

from thepuroidc.domain.userinfo import UserClaims


class InMemoryClaimsProvider:
    """Résout les claims depuis un annuaire mémoire fourni à la construction.

    La table ``profiles`` mappe un ``sub`` vers son jeu de claims. Un
    sujet inconnu retourne des claims vides (seul ``sub`` est renvoyé
    ensuite par le use case).
    """

    def __init__(self, profiles: dict[str, dict[str, object]]) -> None:
        """Injection de l'annuaire des profils (déclaré dans la configuration)."""
        self._profiles = profiles

    def get_claims(self, subject: str) -> UserClaims:
        """Retourne les claims de l'utilisateur ``subject`` (vide si inconnu)."""
        return UserClaims(subject=subject, claims=dict(self._profiles.get(subject, {})))
