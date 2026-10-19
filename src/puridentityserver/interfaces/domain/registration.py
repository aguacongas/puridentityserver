"""Port du fetch du document ``sector_identifier_uri`` (OIDC Core 1.0 §8.1).

Le Dynamic Client Registration doit récupérer le document secteur (JSON
liste des ``redirect_uris`` hébergés) avant d'accepter un client
``pairwise`` : le cas d'utilisation ne connaît ni le client HTTP ni les
règles de sécurité appliquées à sa destination (schéma, adresses
privées, délais, taille, ``Content-Type``). L'infrastructure fournit
l'implémentation sur ``urllib`` partagée avec le fetch de
``request_uri``.
"""

from __future__ import annotations

from typing import Protocol


class SectorIdentifierFetcher(Protocol):
    """Télécharge le document secteur référencé par ``sector_identifier_uri``."""

    async def fetch(self, url: str) -> str | None:
        """Retourne le corps du document JSON, ``None`` si le flux est refusé.

        ``None`` couvre les refus de sécurité du fetcher (destination,
        redirection, type de réponse) comme les échecs réseau : le
        cas d'utilisation refuse alors l'enregistrement.
        """
