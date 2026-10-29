"""Cas d'utilisation : consentement éclairé de l'utilisateur (OIDC §3.1.2.2).

Décide si une demande d'autorisation exige la confirmation de
l'utilisateur et mémorise les scopes accordés : tant qu'un consentement
couvre la demande (``covers``), ``/authorize`` émet directement code et
jetons ; un scope non encore consenti redemande une confirmation, puis
les scopes sont fusionnés (le consentement ne se rétracte jamais
implicitement).
"""

from __future__ import annotations

from puridentityserver.application.authorization_details import (
    authorization_detail_keys,
    parse_authorization_details,
)
from puridentityserver.domain.authorization import Client, Consent, Scope
from puridentityserver.interfaces.repositories.consent_repository import ConsentRepository


def _parse_detail_keys(authorization_details: str) -> frozenset[str]:
    """Clés canoniques des détails présents dans ``authorization_details``."""
    if not authorization_details:
        return frozenset()
    try:
        details = parse_authorization_details(authorization_details)
    except ValueError:
        return frozenset()
    return authorization_detail_keys(details)


class ConsentUseCase:
    """Évalue et mémorise les consentements par couple ``(subject, client)``."""

    def __init__(self, consent_repository: ConsentRepository) -> None:
        """Injection du repository de consentements."""
        self._repository = consent_repository

    async def is_required(
        self,
        client: Client,
        subject: str,
        scopes: frozenset[Scope],
        authorization_details: str = "",
        *,
        force: bool = False,
    ) -> bool:
        """Vrai si le client exige un consentement que ``subject`` n'a pas encore donné.

        Un client non marqué ``require_consent`` ne passe jamais par la
        page de consentement. Pour un client **FAPI/FAPI2**, l'écran est
        exigé à **chaque** demande (drapeau ou non) : la suite
        Certification doit pouvoir refuser même après un consentement
        mémorisé (``user-rejects-authentication``). Pour les autres, la
        demande est déjà couverte quand le consentement stocké inclut
        tous les scopes demandés (``Consent.covers``). ``force``
        (``prompt=consent``, OIDC Core 1.0 §3.1.2.1) impose l'écran même
        quand le consentement stocké couvre la demande : réafficher le
        choix est exactement l'objet de la demande.
        """
        if not client.require_consent:
            return False
        if client.fapi_enabled or client.fapi2_enabled:
            return True
        if force:
            return True
        stored = await self._repository.find(subject, client.client_id)
        if stored is None:
            return True
        requested_details = _parse_detail_keys(authorization_details)
        return not stored.covers(scopes, requested_details)

    async def grant(
        self,
        subject: str,
        client_id: str,
        scopes: frozenset[Scope],
        authorization_details: str = "",
    ) -> None:
        """Mémorise les scopes accordés, fusionnés avec ceux déjà consentis.

        La réunion avec le consentement existant garantit qu'une demande
        élargie n'efface jamais les scopes déjà autorisés.
        """
        existing = await self._repository.find(subject, client_id)
        merged_scopes = scopes | (existing.scopes if existing is not None else frozenset())
        merged_details = _parse_detail_keys(authorization_details) | (
            existing.authorization_details if existing is not None else frozenset()
        )
        await self._repository.save(
            Consent(
                subject=subject,
                client_id=client_id,
                scopes=merged_scopes,
                authorization_details=merged_details,
            )
        )
