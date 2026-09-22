"""Implémentation du port ``ClaimsProvider`` adossée au user store.

Résout les claims utilisateur via le ``UserRepository`` injecté (backends
``memory`` ou ``sql``, choisi par ``STORAGE_TYPE``), alimenté au démarrage
depuis les profils déclarés dans la configuration
(`PURIDENTITYSERVER_USERS_SEED`).
"""

from __future__ import annotations

from puridentityserver.domain.userinfo import UserClaims
from puridentityserver.interfaces.repositories.readers import UserReader


class UserStoreClaimsProvider:
    """Résout les claims depuis le user store (repository injecté).

    Un ``subject`` inconnu retourne des claims vides (seul ``sub`` est
    renvoyé ensuite par le use case).
    """

    def __init__(self, user_repository: UserReader) -> None:
        """Injection du user store (port ``UserRepository``)."""
        self._user_repository = user_repository

    async def get_claims(self, subject: str) -> UserClaims:
        """Retourne les claims de l'utilisateur ``subject`` (vide si inconnu)."""
        user = await self._user_repository.find_by_subject(subject)
        if user is None:
            return UserClaims(subject=subject)
        return user
