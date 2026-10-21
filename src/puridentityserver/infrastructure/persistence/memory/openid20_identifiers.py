"""Store des associations OpenID 2.0 en mémoire — implémentation monoprocess.

Les associations ne survivent pas à la vie du processus : à utiliser pour
les tests unitaires et le développement local uniquement.
"""

from __future__ import annotations

import asyncio

from puridentityserver.domain.openid20 import OpenID20Identifier


class InMemoryOpenID20IdentifierRepository:
    """Maintient les identifiants OpenID 2.0 associés à une `sub` en mémoire.

    Un verrou asynchrone sérialise les opérations comme le ferait un stockage
    partagé, en accord avec le contrat async du port.
    """

    def __init__(self) -> None:
        """Initialise le store vide et son verrou."""
        self._identifiers: dict[tuple[str, str], OpenID20Identifier] = {}
        self._by_identifier: dict[str, OpenID20Identifier] = {}
        self._lock = asyncio.Lock()

    async def save(self, identifier: OpenID20Identifier) -> None:
        """Enregistre l'association (remplace l'éventuelle association du même couple)."""
        async with self._lock:
            self._identifiers[identifier.subject, identifier.realm] = identifier
            self._by_identifier[identifier.identifier] = identifier

    async def find(self, subject: str, realm: str = "") -> OpenID20Identifier | None:
        """Retourne l'association d'un compte pour le `realm` demandé."""
        async with self._lock:
            return self._identifiers.get((subject, realm))

    async def find_by_identifier(self, identifier: str) -> OpenID20Identifier | None:
        """Retourne l'association portant l'identifiant OpenID 2.0 donné."""
        async with self._lock:
            return self._by_identifier.get(identifier)

    async def find_all(self) -> list[OpenID20Identifier]:
        """Liste toutes les associations connues."""
        async with self._lock:
            return list(self._identifiers.values())

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
