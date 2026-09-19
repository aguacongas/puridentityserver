"""Repository des consentements en mémoire (OIDC Core §3.1.2.2).

Implémentation monoprocess : les consentements disparaissent au
redémarrage, adaptée aux tests et au développement local.
"""

from __future__ import annotations

import asyncio

from puridentityserver.domain.authorization import Consent


class InMemoryConsentRepository:
    """Maintient les consentements dans un dictionnaire en mémoire.

    Clé composite ``(subject, client_id)`` — une entrée par couple
    utilisateur/client, les scopes accordés y étant fusionnés. Un verrou
    asynchrone sérialise l'accès partagé entre requêtes.
    """

    def __init__(self) -> None:
        """Initialise le magasin vide et son verrou d'accès."""
        self._consents: dict[tuple[str, str], Consent] = {}
        self._lock = asyncio.Lock()

    async def save(self, consent: Consent) -> None:
        """Enregistre le consentement (insertion ou mise à jour)."""
        async with self._lock:
            self._consents[consent.subject, consent.client_id] = consent

    async def find(self, subject: str, client_id: str) -> Consent | None:
        """Retourne le consentement de ``subject`` pour ``client_id``, ou ``None``."""
        async with self._lock:
            return self._consents.get((subject, client_id))

    async def delete(self, subject: str, client_id: str) -> None:
        """Supprime le consentement (idempotent si absent)."""
        async with self._lock:
            self._consents.pop((subject, client_id), None)

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
