"""Repository clients en mémoire — implémentation de test/développement monoprocess.

Les clients ne survivent pas à la vie du processus : à utiliser pour les
tests unitaires et le développement local uniquement.
"""

from __future__ import annotations

import asyncio

from puridentityserver.domain.authorization import Client


class InMemoryClientRepository:
    """Maintient les clients dans un dictionnaire en mémoire.

    Le magasin partage son état entre toutes les requêtes du processus ;
    un verrou asynchrone série les opérations lecture/écriture comme le
    ferait n'importe quel stockage partagé (fidélité au contrat async).
    """

    def __init__(self) -> None:
        """Initialise le magasin vide et son verrou d'accès."""
        self._clients: dict[str, Client] = {}
        self._lock = asyncio.Lock()

    async def save(self, client: Client) -> None:
        """Enregistre le client (insertion ou mise à jour par ``client_id``)."""
        async with self._lock:
            self._clients[client.client_id] = client

    async def find_by_id(self, client_id: str) -> Client | None:
        """Retourne le client identifié par ``client_id``, ou ``None``."""
        async with self._lock:
            return self._clients.get(client_id)

    async def find_all(self) -> list[Client]:
        """Retourne tous les clients, dans l'ordre d'insertion."""
        async with self._lock:
            return list(self._clients.values())

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
