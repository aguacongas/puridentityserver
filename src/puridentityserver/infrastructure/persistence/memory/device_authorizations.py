"""Repository des sessions Device Authorization Grant (RFC 8628) en mémoire.

Implémentation monoprocess : les sessions disparaissent au redémarrage,
adaptée aux tests et au développement local.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace

from puridentityserver.domain.authorization import (
    DeviceAuthorization,
    DeviceAuthorizationStatus,
)


class InMemoryDeviceAuthorizationRepository:
    """Maintient les sessions de l'appareil dans un dictionnaire en mémoire.

    Un verrou asynchrone protège l'accès partagé entre requêtes et rend la
    décision de l'utilisateur (autorisation / refus) atomique dans ce
    processus.
    """

    def __init__(self) -> None:
        """Initialise le magasin vide et son verrou d'accès."""
        self._sessions: dict[str, DeviceAuthorization] = {}
        self._lock = asyncio.Lock()

    async def save(self, session: DeviceAuthorization) -> None:
        """Stocke la session (insertion ou mise à jour)."""
        async with self._lock:
            self._sessions[session.device_code_hash] = session

    async def find_by_device_code_hash(self, device_code_hash: str) -> DeviceAuthorization | None:
        """Retourne la session identifiée par ``device_code_hash``, ou ``None``."""
        async with self._lock:
            return self._sessions.get(device_code_hash)

    async def find_by_user_code(self, user_code: str) -> DeviceAuthorization | None:
        """Retourne la session identifiée par ``user_code``, ou ``None``."""
        async with self._lock:
            for stored in self._sessions.values():
                if stored.user_code == user_code:
                    return stored
            return None

    async def approve(self, device_code_hash: str, subject: str) -> None:
        """Marque la session comme autorisée et fixe le ``subject``."""
        async with self._lock:
            stored = self._sessions.get(device_code_hash)
            if stored is not None:
                self._sessions[device_code_hash] = replace(
                    stored, status=DeviceAuthorizationStatus.APPROVED, subject=subject
                )

    async def deny(self, device_code_hash: str) -> None:
        """Marque la session comme refusée par l'utilisateur."""
        async with self._lock:
            stored = self._sessions.get(device_code_hash)
            if stored is not None:
                self._sessions[device_code_hash] = replace(
                    stored, status=DeviceAuthorizationStatus.DENIED
                )

    async def delete(self, device_code_hash: str) -> None:
        """Retire la session identifiée par ``device_code_hash``, ignoré si absent."""
        async with self._lock:
            self._sessions.pop(device_code_hash, None)

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
