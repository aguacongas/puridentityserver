"""Store anti-replay DPoP en mémoire — implémentation monoprocess.

Les ``jti`` présentés ne survivent pas à la vie du processus : à
utiliser pour les tests unitaires et le développement local uniquement.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from puridentityserver.domain.dpop import DPoPReplay


class InMemoryDpopReplayRepository:
    """Maintient les ``jti`` déjà présentés dans un dictionnaire en mémoire.

    Un verrou asynchrone série les opérations comme le ferait un stockage
    partagé, en accord avec le contrat async du port.
    """

    def __init__(self) -> None:
        """Initialise le store vide et son verrou d'accès."""
        self._replays: dict[str, DPoPReplay] = {}
        self._lock = asyncio.Lock()

    async def save(self, replay: DPoPReplay) -> None:
        """Enregistre le ``jti`` présenté (insertion par ``jti_hash``)."""
        async with self._lock:
            self._replays[replay.jti_hash] = replay

    async def is_used(self, jti_hash: str) -> bool:
        """Indique si l'empreinte a déjà été présentée."""
        async with self._lock:
            return jti_hash in self._replays

    async def purge_expired(self) -> int:
        """Supprime les entrées expirées ; retourne le nombre supprimé."""
        now = datetime.now(timezone.utc)
        async with self._lock:
            expired = [
                digest for digest, replay in self._replays.items() if replay.expires_at <= now
            ]
            for digest in expired:
                del self._replays[digest]
        return len(expired)

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
