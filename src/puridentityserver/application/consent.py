"""Cas d'utilisation : consentement éclairé de l'utilisateur (OIDC §3.1.2.2).

Décide si une demande d'autorisation exige la confirmation de
l'utilisateur et mémorise les scopes accordés : tant qu'un consentement
couvre la demande (``covers``), ``/authorize`` émet directement code et
jetons ; un scope non encore consenti redemande une confirmation, puis
les scopes sont fusionnés (le consentement ne se rétracte jamais
implicitement).
"""

from __future__ import annotations

from puridentityserver.domain.authorization import Client, Consent, Scope
from puridentityserver.interfaces.repositories.consent_repository import ConsentRepository


class ConsentUseCase:
    """Évalue et mémorise les consentements par couple ``(subject, client)``."""

    def __init__(self, consent_repository: ConsentRepository) -> None:
        """Injection du repository de consentements."""
        self._repository = consent_repository

    async def is_required(self, client: Client, subject: str, scopes: frozenset[Scope]) -> bool:
        """Vrai si le client exige un consentement que ``subject`` n'a pas encore donné.

        Un client non marqué ``require_consent`` ne passe jamais par la
        page de consentement ; pour les autres, la demande est déjà
        couverte quand le consentement stocké inclut tous les scopes
        demandés (``Consent.covers``).
        """
        if not client.require_consent:
            return False
        stored = await self._repository.find(subject, client.client_id)
        return stored is None or not stored.covers(scopes)

    async def grant(self, subject: str, client_id: str, scopes: frozenset[Scope]) -> None:
        """Mémorise les scopes accordés, fusionnés avec ceux déjà consentis.

        La réunion avec le consentement existant garantit qu'une demande
        élargie n'efface jamais les scopes déjà autorisés.
        """
        existing = await self._repository.find(subject, client_id)
        merged = scopes | (existing.scopes if existing is not None else frozenset())
        await self._repository.save(Consent(subject=subject, client_id=client_id, scopes=merged))
