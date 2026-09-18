"""Repository des requêtes d'autorisation poussées PAR (RFC 9126) en mémoire.

Implémentation monoprocess : les requêtes poussées disparaissent au
redémarrage, adaptée aux tests et au développement local.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace

from puridentityserver.domain.authorization import PushedAuthorization


class InMemoryPushedAuthorizationRepository:
    """Maintient les requêtes poussées dans un dictionnaire en mémoire.

    Un verrou asynchrone protège l'accès partagé entre requêtes et rend la
    consommation (usage unique du ``request_uri``) atomique dans ce
    processus.
    """

    def __init__(self) -> None:
        """Initialise le magasin vide et son verrou d'accès."""
        self._pushed: dict[str, PushedAuthorization] = {}
        self._lock = asyncio.Lock()

    async def save(self, pushed: PushedAuthorization) -> None:
        """Stocke la requête poussée (insertion ou mise à jour)."""
        async with self._lock:
            self._pushed[pushed.request_uri] = pushed

    async def find_by_request_uri(self, request_uri: str) -> PushedAuthorization | None:
        """Retourne la requête poussée identifiée par ``request_uri``, ou ``None``."""
        async with self._lock:
            return self._pushed.get(request_uri)

    async def consume(self, request_uri: str) -> None:
        """Marque la requête poussée comme utilisée (usage unique)."""
        async with self._lock:
            stored = self._pushed.get(request_uri)
            if stored is not None:
                self._pushed[request_uri] = replace(stored, is_consumed=True)

    async def delete(self, request_uri: str) -> None:
        """Retire la requête poussée identifiée par ``request_uri``, ignoré si absent."""
        async with self._lock:
            self._pushed.pop(request_uri, None)

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
