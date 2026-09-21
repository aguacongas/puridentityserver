"""Port de vérification d'un JWT Bearer (jeton de gestion / d'administration)."""

from __future__ import annotations

from typing import Protocol


class BearerTokenVerifier(Protocol):
    """Vérifie la signature, l'`iss` et l'`exp` d'un JWT Bearer.

    L'infrastructure fournit deux implémentations : une validation locale
    (clés de signature du serveur, jeton émis par l'issuer courant) et une
    validation distante (JWKS découvert sur un issuer tiers, déploiement
    séparé). Le port isole les usecases de la source des clés.
    """

    async def verify(self, token: str) -> dict[str, object] | None:
        """Retourne les claims si le jeton est valide, ``None`` sinon.

        Un jeton dont la signature, l'issuer, l'audience (si contrôlée) ou
        l'expiration est invalide donne ``None``.
        """
        ...
