"""Port de persistance des requêtes d'autorisation poussées (RFC 9126).

Le ``request_uri`` renvoyé par ``POST /par`` est à usage unique, lié au
client qui l'a poussé et de courte durée : l'implémentation doit le stocker
avec son ``expires_at`` et consommer la référence lors de son utilisation
à l'endpoint d'autorisation.
"""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.authorization import PushedAuthorization


class PushedAuthorizationRepository(Protocol):
    """Contrat de stockage des requêtes poussées PAR.

    Les implémentations concrètes (mémoire, SQL…) sont choisies à la
    composition root selon la configuration.
    """

    async def save(self, pushed: PushedAuthorization) -> None:
        """Persiste la requête poussée (insertion ou mise à jour)."""
        ...

    async def find_by_request_uri(self, request_uri: str) -> PushedAuthorization | None:
        """Retourne la requête poussée identifiée par son ``request_uri``."""
        ...

    async def consume(self, request_uri: str) -> None:
        """Marque la requête poussée comme utilisée (usage unique, RFC 9126 §4)."""
        ...

    async def delete(self, request_uri: str) -> None:
        """Supprime la requête poussée (consommée ou expirée)."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (crée le schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du repository (connexions, moteur…)."""
        ...
