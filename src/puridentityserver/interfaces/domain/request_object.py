"""Port de récupération d'un ``request_uri`` de request object (RFC 9101 §5.2).

Isolé derrière un protocole : le cas d'utilisation ne connaît pas le
client HTTP qui lit le document JWT référencé — ni les règles de sécurité
appliquées à sa destination (schéma, adresses privées, délais, taille).
L'infrastructure fournit une implémentation sur ``urllib`` (aucune
dépendance réseau runtime ajoutée).
"""

from __future__ import annotations

from typing import Protocol


class RequestObjectFetcher(Protocol):
    """Télécharge le document ``request_uri`` référencé par un client."""

    async def fetch(self, url: str) -> str | None:
        """Retourne le corps du document JWT, ``None`` si le flux est refusé.

        ``None`` couvre les refus de sécurité (destination filtrée,
        schéma non permis) comme les échecs de transport : le cas
        d'utilisation rend alors ``invalid_request_uri`` (RFC 9101 §5.2).
        """
        ...
