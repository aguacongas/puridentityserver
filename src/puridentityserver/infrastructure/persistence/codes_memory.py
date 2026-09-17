"""Repository des codes d'autorisation en mémoire.

Implémentation monoprocess : les codes disparaissent au redémarrage,
adaptée aux tests et au développement local.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace

from puridentityserver.domain.authorization import AuthorizationCode


class InMemoryAuthorizationCodeRepository:
    """Maintient les codes d'autorisation dans un dictionnaire en mémoire.

    Un verrou asynchrone protège l'accès partagé entre requêtes et rend
    la consommation du code atomique dans ce processus.
    """

    def __init__(self) -> None:
        """Initialise le magasin vide et son verrou d'accès."""
        self._codes: dict[str, AuthorizationCode] = {}
        self._lock = asyncio.Lock()

    async def save(self, code: AuthorizationCode) -> None:
        """Stocke le code d'autorisation (insertion ou mise à jour)."""
        async with self._lock:
            self._codes[code.code] = code

    async def find_by_code(self, code: str) -> AuthorizationCode | None:
        """Retourne le code identifié par ``code``, ou ``None``."""
        async with self._lock:
            return self._codes.get(code)

    async def consume(self, code: str) -> None:
        """Marque le code comme déjà consommé (usage unique)."""
        async with self._lock:
            stored = self._codes.get(code)
            if stored is not None:
                self._codes[code] = replace(stored, is_consumed=True)

    async def delete(self, code: str) -> None:
        """Retire le code identifié par ``code``, ignoré si absent."""
        async with self._lock:
            self._codes.pop(code, None)

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
