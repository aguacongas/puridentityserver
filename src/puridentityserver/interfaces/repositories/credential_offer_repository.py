"""Port de persistance des offres de credential (OID4VCI 1.0 §4.1.1)."""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.credential_offer import CredentialOffer


class CredentialOfferRepository(Protocol):
    """Contrat de stockage des offres de credential.

    Une offre est adressable par son ``offer_id`` : c'est cet identifiant
    qui figure dans ``credential_offer_uri`` et que le wallet déréférence
    sans authentification. Les implémentations concrètes (mémoire, SQL)
    sont choisies à la composition root selon la configuration.
    """

    async def save(self, offer: CredentialOffer) -> None:
        """Persiste l'offre (insertion ou mise à jour)."""
        ...

    async def find_by_id(self, offer_id: str) -> CredentialOffer | None:
        """Retourne l'offre identifiée par ``offer_id``, ou ``None``."""
        ...

    async def delete(self, offer_id: str) -> None:
        """Supprime l'offre identifiée par ``offer_id``, ignorée si absente."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (création de schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du stockage."""
        ...
