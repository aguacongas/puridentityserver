"""Port de persistance des consentements utilisateurs (OIDC Core §3.1.2.2)."""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.authorization import Consent


class ConsentRepository(Protocol):
    """Contrat de stockage des consentements.

    Le port couvre le cycle de vie d'un consentement : sauvegarde (par
    ``subject`` + ``client_id``), lecture pour décider si une demande est
    déjà couverte, suppression (révocation explicite) et cycle de vie
    propre du stockage. Les implémentations concrètes (mémoire, SQL,
    Redis, MongoDB…) sont fournies en infrastructure et choisies à la
    composition root selon ``storage_type``.
    """

    async def save(self, consent: Consent) -> None:
        """Enregistre le consentement (insertion ou mise à jour)."""
        ...

    async def find(self, subject: str, client_id: str) -> Consent | None:
        """Retourne le consentement de ``subject`` pour ``client_id``, ou ``None``."""
        ...

    async def delete(self, subject: str, client_id: str) -> None:
        """Supprime le consentement (idempotent si absent)."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (crée le schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du repository (connexions, moteur…)."""
        ...
