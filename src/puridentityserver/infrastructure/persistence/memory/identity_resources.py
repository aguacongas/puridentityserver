"""Repository IdentityResources en mémoire — implémentation monoprocess.

Les resources ne survivent pas à la vie du processus : à utiliser pour
les tests unitaires et le développement local uniquement.
"""

from __future__ import annotations

import asyncio

from puridentityserver.domain.identity_resource import IdentityResource


class InMemoryIdentityResourceRepository:
    """Maintient les IdentityResources dans un dictionnaire en mémoire.

    Le magasin partage son état entre toutes les requêtes du processus ;
    un verrou asynchrone série les opérations lecture/écriture comme le
    ferait n'importe quel stockage partagé (fidélité au contrat async).
    """

    def __init__(self) -> None:
        """Initialise le magasin vide et son verrou d'accès."""
        self._resources: dict[str, IdentityResource] = {}
        self._lock = asyncio.Lock()

    async def save(self, resource: IdentityResource) -> None:
        """Enregistre la resource (insertion ou mise à jour par ``name``)."""
        async with self._lock:
            self._resources[resource.name] = resource

    async def find_by_name(self, name: str) -> IdentityResource | None:
        """Retourne la resource identifiée par ``name``, ou ``None``."""
        async with self._lock:
            return self._resources.get(name)

    async def find_all(self) -> list[IdentityResource]:
        """Retourne toutes les resources, dans l'ordre d'insertion."""
        async with self._lock:
            return list(self._resources.values())

    async def delete(self, name: str) -> None:
        """Supprime la resource identifiée par ``name`` (idempotent)."""
        async with self._lock:
            self._resources.pop(name, None)

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
