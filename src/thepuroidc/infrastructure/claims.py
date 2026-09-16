"""Implémentation de démonstration du port ``ClaimsProvider``.

Résout les claims utilisateur via le ``UserRepository`` injecté (le user
store). Les données de démonstration ne sont pas en dur dans le code :
elles sont déclarées dans ``config.toml`` (`THEPUROIDC_USERINFO_PROFILES`)
et déversées dans le store au démarrage. Une vraie base d'utilisateurs
implémenterait le même port pour alimenter ``/userinfo``.
"""

from __future__ import annotations

from thepuroidc.domain.userinfo import UserClaims
from thepuroidc.interfaces.repositories.user_repository import UserRepository


class InMemoryClaimsProvider:
    """Résout les claims depuis le user store (repository injecté).

    Un ``subject`` inconnu retourne des claims vides (seul ``sub`` est
    renvoyé ensuite par le use case).
    """

    def __init__(self, user_repository: UserRepository) -> None:
        """Injection du user store (port ``UserRepository``)."""
        self._user_repository = user_repository

    async def get_claims(self, subject: str) -> UserClaims:
        """Retourne les claims de l'utilisateur ``subject`` (vide si inconnu)."""
        user = await self._user_repository.find_by_subject(subject)
        if user is None:
            return UserClaims(subject=subject)
        return user
