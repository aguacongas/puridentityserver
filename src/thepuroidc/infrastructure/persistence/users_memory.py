"""Repository utilisateurs en mémoire — implémentation de test/développement monoprocess.

Les profils ne survivent pas à la vie du processus : à utiliser pour les
tests unitaires et le développement local uniquement.
"""

from __future__ import annotations

import asyncio

from thepuroidc.domain.userinfo import UserClaims


class InMemoryUserRepository:
    """Maintient les profils utilisateurs dans un dictionnaire en mémoire.

    Le magasin partage son état entre toutes les requêtes du processus ;
    un verrou asynchrone série les opérations lecture/écriture comme le
    ferait n'importe quel stockage partagé (fidélité au contrat async).
    """

    def __init__(self) -> None:
        """Initialise le magasin vide et son verrou d'accès."""
        self._users: dict[str, UserClaims] = {}
        self._lock = asyncio.Lock()

    async def save(self, user: UserClaims) -> None:
        """Enregistre le profil (insertion ou mise à jour par ``subject``)."""
        async with self._lock:
            self._users[user.subject] = user

    async def save_all(self, users: list[UserClaims]) -> None:
        """Enregistre plusieurs profils en une seule opération."""
        async with self._lock:
            for user in users:
                self._users[user.subject] = user

    async def find_by_subject(self, subject: str) -> UserClaims | None:
        """Retourne le profil identifié par ``subject``, ou ``None``."""
        async with self._lock:
            return self._users.get(subject)

    async def find_all(self) -> list[UserClaims]:
        """Retourne tous les profils, dans l'ordre d'insertion."""
        async with self._lock:
            return list(self._users.values())

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
