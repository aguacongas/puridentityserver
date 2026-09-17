"""Port de persistance des codes d'autorisation (RFC 6749 §4.1)."""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.authorization import AuthorizationCode


class AuthorizationCodeRepository(Protocol):
    """Contrat de stockage des codes d'autorisation.

    Les codes sont à usage unique : le port expose ``consume`` pour
    marquer atomiquement un code déjà échangé et ``delete`` pour purger
    les codes expirés. Les implémentations concrètes (mémoire, SQL…) sont
    choisies à la composition root selon la configuration.
    """

    async def save(self, code: AuthorizationCode) -> None:
        """Persiste le code d'autorisation (insertion ou mise à jour)."""
        ...

    async def find_by_code(self, code: str) -> AuthorizationCode | None:
        """Retourne le code d'autorisation identifié par ``code``, ou ``None``."""
        ...

    async def consume(self, code: str) -> None:
        """Marque le code comme déjà consommé (usage unique)."""
        ...

    async def delete(self, code: str) -> None:
        """Supprime le code d'autorisation (purge des codes expirés)."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (crée le schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du repository (connexions, moteur…)."""
        ...
