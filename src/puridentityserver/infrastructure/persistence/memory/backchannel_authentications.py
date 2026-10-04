"""Repository des demandes CIBA (OIDC CIBA 1.0) en mémoire.

Implémentation monoprocess : les demandes disparaissent au redémarrage,
adaptée aux tests et au développement local.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace

from puridentityserver.domain.authorization import (
    BackchannelAuthenticationRequest,
    BackchannelAuthenticationStatus,
)


class InMemoryBackchannelAuthenticationRepository:
    """Maintient les demandes CIBA dans un dictionnaire en mémoire.

    Un verrou asynchrone protège l'accès partagé entre requêtes et rend la
    décision de l'utilisateur (autorisation / refus) atomique dans ce
    processus.
    """

    def __init__(self) -> None:
        """Initialise le magasin vide et son verrou d'accès."""
        self._requests: dict[str, BackchannelAuthenticationRequest] = {}
        self._lock = asyncio.Lock()

    async def save(self, request: BackchannelAuthenticationRequest) -> None:
        """Stocke la demande (insertion ou mise à jour)."""
        async with self._lock:
            self._requests[request.auth_req_id_hash] = request

    async def find_by_auth_req_id_hash(
        self, auth_req_id_hash: str
    ) -> BackchannelAuthenticationRequest | None:
        """Retourne la demande identifiée par ``auth_req_id_hash``, ou ``None``."""
        async with self._lock:
            return self._requests.get(auth_req_id_hash)

    async def approve(self, auth_req_id_hash: str) -> None:
        """Marque la demande comme autorisée par l'utilisateur."""
        async with self._lock:
            stored = self._requests.get(auth_req_id_hash)
            if stored is not None:
                self._requests[auth_req_id_hash] = replace(
                    stored, status=BackchannelAuthenticationStatus.APPROVED
                )

    async def deny(self, auth_req_id_hash: str) -> None:
        """Marque la demande comme refusée par l'utilisateur."""
        async with self._lock:
            stored = self._requests.get(auth_req_id_hash)
            if stored is not None:
                self._requests[auth_req_id_hash] = replace(
                    stored, status=BackchannelAuthenticationStatus.DENIED
                )

    async def delete(self, auth_req_id_hash: str) -> None:
        """Retire la demande identifiée par ``auth_req_id_hash``, ignoré si absente."""
        async with self._lock:
            self._requests.pop(auth_req_id_hash, None)

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
