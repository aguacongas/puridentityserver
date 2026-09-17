"""Port de persistance des refresh tokens (RFC 6749 §6).

Les refresh tokens sont persistés par empreinte SHA-256 uniquement
(``token_hash``) : la valeur en clair n'est jamais stockée. Le port
expose ``consume`` pour marquer atomiquement un jeton déjà utilisé
(rotation) et ``delete`` pour purger les jetons expirés.
"""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.authorization import RefreshToken


class RefreshTokenRepository(Protocol):
    """Contrat de stockage des refresh tokens.

    Identique dans l'esprit au port des codes d'autorisation, à la
    différence près que la recherche se fait par empreinte et non par
    valeur en clair. Les implémentations concrètes (mémoire, SQL…) sont
    choisies à la composition root selon la configuration.
    """

    async def save(self, token: RefreshToken) -> None:
        """Persiste le refresh token (insertion ou mise à jour)."""
        ...

    async def find_by_token_hash(self, token_hash: str) -> RefreshToken | None:
        """Retourne le refresh token identifié par son empreinte, ou ``None``."""
        ...

    async def consume(self, token_hash: str) -> None:
        """Marque le jeton comme déjà utilisé (rotation)."""
        ...

    async def delete(self, token_hash: str) -> None:
        """Supprime le refresh token (purgé des jetons expirés)."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (crée le schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du repository (connexions, moteur…)."""
        ...
