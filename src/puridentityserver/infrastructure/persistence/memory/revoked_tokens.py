"""Repository de jetons révoqués en mémoire — implémentation monoprocess.

Le denylist ne survit pas à la vie du processus : à utiliser pour les
tests unitaires et le développement local uniquement.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from puridentityserver.domain.revocation import RevokedToken


class InMemoryRevokedTokenRepository:
    """Maintient les jetons révoqués (hash) dans un dictionnaire en mémoire.

    Un verrou asynchrone série les opérations comme le ferait un stockage
    partagé, en accord avec le contrat async du port.
    """

    def __init__(self) -> None:
        """Initialise le denylist vide et son verrou d'accès."""
        self._revoked: dict[str, RevokedToken] = {}
        self._lock = asyncio.Lock()

    async def save(self, revoked: RevokedToken) -> None:
        """Enregistre la révocation (mise à jour par ``token_hash``)."""
        async with self._lock:
            self._revoked[revoked.token_hash] = revoked

    async def is_revoked(self, token_hash: str) -> bool:
        """Indique si l'empreinte figure au denylist."""
        async with self._lock:
            return token_hash in self._revoked

    async def purge_expired(self) -> int:
        """Supprime les entrées expirées ; retourne le nombre supprimé."""
        now = datetime.now(timezone.utc)
        async with self._lock:
            expired = [h for h, revoked in self._revoked.items() if revoked.expires_at <= now]
            for hash_value in expired:
                del self._revoked[hash_value]
        return len(expired)

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
