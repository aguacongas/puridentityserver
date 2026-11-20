"""Repository en mémoire — implémentation de test/développement monoprocess.

Les clés ne survivent pas à la vie du processus : à utiliser pour les
tests unitaires et le développement local uniquement.
"""

from __future__ import annotations

import asyncio

from puridentityserver.domain.jwks import KeyPair
from puridentityserver.interfaces.repositories.key_pair_repository import KeyPairConflictError


class InMemoryKeyPairRepository:
    """Maintient les paires de clés dans un dictionnaire en mémoire.

    Le magasin partage son état entre toutes les requêtes du processus ;
    un verrou asynchrone série les opérations lecture/écriture comme le
    ferait n'importe quel stockage partagé (fidélité au contrat async) et
    rend atomique l'arbitrage du ``slot`` de famille (issue #310).
    """

    def __init__(self) -> None:
        """Initialise le magasin vide et son verrou d'accès."""
        self._keys: dict[str, KeyPair] = {}
        self._lock = asyncio.Lock()

    async def save(self, key_pair: KeyPair) -> None:
        """Stocke la paire de clés (insertion ou mise à jour par ``kid``)."""
        async with self._lock:
            self._store(key_pair)

    async def find_all(self) -> list[KeyPair]:
        """Retourne toutes les paires de clés, dans l'ordre d'insertion."""
        async with self._lock:
            return list(self._keys.values())

    async def update(self, key_pair: KeyPair) -> None:
        """Remplace la paire de clés existante (par ``kid``)."""
        async with self._lock:
            self._store(key_pair)

    def _store(self, key_pair: KeyPair) -> None:
        """Écrit la paire, en refusant un ``slot`` de famille déjà pris.

        Reproduit sous le verrou la contrainte d'unicité ``(use, slot)`` du
        store relationnel : les ``NULL`` sont distincts, seules les deux
        lignes portant le même couple sont en conflit.
        """
        if key_pair.slot is not None and any(
            stored.use is key_pair.use and stored.slot == key_pair.slot
            for kid, stored in self._keys.items()
            if kid != key_pair.kid
        ):
            raise KeyPairConflictError(
                f"slot {key_pair.slot!r} de la famille {key_pair.use.value!r} déjà pris"
            )
        self._keys[key_pair.kid] = key_pair

    async def delete(self, kid: str) -> None:
        """Retire la paire de clés identifiée par ``kid``, ignoré si absente."""
        async with self._lock:
            self._keys.pop(kid, None)

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
