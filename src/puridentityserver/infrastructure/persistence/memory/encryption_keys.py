"""Repository en mémoire — implémentation de test/développement monoprocess.

La clé de chiffrement ne survit pas à la vie du processus : à utiliser
pour les tests unitaires et le développement local uniquement.
"""

from __future__ import annotations

import asyncio


class InMemoryEncryptionKeyRepository:
    """Maintient la clé de chiffrement de l'émetteur en mémoire.

    Le magasin partage son état entre toutes les requêtes du processus ;
    un verrou asynchrone série les opérations lecture/écriture comme le
    ferait n'importe quel stockage partagé (fidélité au contrat async) et
    rend ``save_if_absent`` atomique.
    """

    def __init__(self) -> None:
        """Initialise le magasin vide et son verrou d'accès."""
        self._pem: str | None = None
        self._lock = asyncio.Lock()

    async def load(self) -> str | None:
        """Retourne le PEM persisté, ou ``None``."""
        async with self._lock:
            return self._pem

    async def save_if_absent(self, private_key_pem: str) -> None:
        """Persiste le PEM seulement si aucune clé n'est déjà stockée."""
        async with self._lock:
            if self._pem is None:
                self._pem = private_key_pem

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
