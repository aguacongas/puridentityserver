"""Repository des offres de credential en mémoire.

Implémentation monoprocess : les offres disparaissent au redémarrage,
adaptée aux tests et au développement local.
"""

from __future__ import annotations

import asyncio

from puridentityserver.domain.credential_offer import CredentialOffer


class InMemoryCredentialOfferRepository:
    """Maintient les offres de credential dans un dictionnaire en mémoire."""

    def __init__(self) -> None:
        """Initialise le magasin vide et son verrou d'accès."""
        self._offers: dict[str, CredentialOffer] = {}
        self._lock = asyncio.Lock()

    async def save(self, offer: CredentialOffer) -> None:
        """Stocke l'offre (insertion ou mise à jour)."""
        async with self._lock:
            self._offers[offer.offer_id] = offer

    async def find_by_id(self, offer_id: str) -> CredentialOffer | None:
        """Retourne l'offre identifiée par ``offer_id``, ou ``None``."""
        async with self._lock:
            return self._offers.get(offer_id)

    async def delete(self, offer_id: str) -> None:
        """Retire l'offre identifiée par ``offer_id``, ignorée si absente."""
        async with self._lock:
            self._offers.pop(offer_id, None)

    async def initialise(self) -> None:
        """Rien à préparer : le magasin existe dès la construction."""

    async def close(self) -> None:
        """Rien à libérer."""
