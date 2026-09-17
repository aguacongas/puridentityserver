"""Repository des refresh tokens en mémoire.

Implémentation monoprocess : les jetons disparaissent au redémarrage,
adaptée aux tests et au développement local.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace

from puridentityserver.domain.authorization import RefreshToken


class InMemoryRefreshTokenRepository:
    """Maintient les refresh tokens dans un dictionnaire en mémoire.

    Un verrou asynchrone protège l'accès partagé entre requêtes et rend
    la rotation (consommation) atomique dans ce processus.
    """

    def __init__(self) -> None:
        """Initialise le magasin vide et son verrou d'accès."""
        self._tokens: dict[str, RefreshToken] = {}
        self._lock = asyncio.Lock()

    async def save(self, token: RefreshToken) -> None:
        """Stocke le refresh token (insertion ou mise à jour)."""
        async with self._lock:
            self._tokens[token.token_hash] = token

    async def find_by_token_hash(self, token_hash: str) -> RefreshToken | None:
        """Retourne le jeton identifié par ``token_hash``, ou ``None``."""
        async with self._lock:
            return self._tokens.get(token_hash)

    async def consume(self, token_hash: str) -> None:
        """Marque le jeton comme déjà utilisé (rotation)."""
        async with self._lock:
            stored = self._tokens.get(token_hash)
            if stored is not None:
                self._tokens[token_hash] = replace(stored, is_consumed=True)

    async def delete(self, token_hash: str) -> None:
        """Retire le jeton identifié par ``token_hash``, ignoré si absent."""
        async with self._lock:
            self._tokens.pop(token_hash, None)

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
