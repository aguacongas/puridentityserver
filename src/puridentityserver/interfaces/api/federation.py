"""Routes FastAPI de la Fédération (OpenID Federation 1.1).

L'OP publie son **entity configuration** (son entity statement auto-signé)
à ``/.well-known/openid-federation`` : c'est le point d'entrée de la
fédération pour les RP qui lui font confiance (spec §9).

Les routes ne sont montées que si le support de la Fédération est activé
(``federation_enabled``) : sans lui, aucun chemin n'est exposé.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import Response

from puridentityserver.application.federation import FederationUseCase
from puridentityserver.domain.federation import ENTITY_STATEMENT_MEDIA_TYPE


def federation_router(usecase: FederationUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant l'entity configuration de l'OP."""
    router = APIRouter(tags=["federation"])

    @router.get(
        "/.well-known/openid-federation",
        summary="Entity statement de l'OP (entity configuration)",
        response_model=None,
    )
    async def entity_statement() -> Response:
        """Retourne l'entity statement auto-signé de l'OP (spec §9.2).

        Le corps est un JWT en texte (``application/entity-statement+jwt``) :
        l'en-tête ``typ`` vaut ``entity-statement+jwt`` et le ``kid`` désigne
        la clé de signature, publiée dans le claim ``jwks`` du statement.
        """
        statement = await usecase.entity_statement()
        return Response(content=statement, media_type=ENTITY_STATEMENT_MEDIA_TYPE)

    return router
