"""Route FastAPI d'exposition du JSON Web Key Set (RFC 7517)."""

from __future__ import annotations

from fastapi import APIRouter

from puridentityserver.application.jwks import JWKSetUseCase
from puridentityserver.interfaces.schemas.jwks import JWKKeyResponse, JWKSetResponse


def jwk_set_router(usecase: JWKSetUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant les clés publiques du serveur."""
    router = APIRouter(tags=["jwks"])

    @router.get(
        "/.well-known/jwks.json",
        summary="JSON Web Key Set",
        # Les membres inapplicables d'une clé (RFC 7517 §4) sont omis, pas
        # sérialisés ``null`` : la suite de certification lit ``n``/``e``/
        # ``crv``/``x``/``y`` sans tolérer de ``null``.
        response_model_exclude_none=True,
    )
    async def jwk_set() -> JWKSetResponse:
        keys = [
            JWKKeyResponse.from_key_pair(key_pair)
            for key_pair in await usecase.get_published_keys()
        ]
        return JWKSetResponse(keys=keys)

    return router
