"""Routes FastAPI minimales pour OpenID4VP (slice 0, issue #172/#223)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

if TYPE_CHECKING:
    from puridentityserver.application.oid4vp import OID4VPVerifierUseCase

_JSON_MEDIA_TYPE = "application/json"


def oid4vp_router(
    *,
    oid4vp_usecase: OID4VPVerifierUseCase | None = None,
) -> APIRouter:
    """Construit le routeur FastAPI de présentation OpenID4VP."""
    router = APIRouter(tags=["oid4vp"])
    usecase = oid4vp_usecase

    @router.post(
        "/presentation_requests",
        summary="Crée une demande de présentation signée (OID4VP)",
        response_model=None,
    )
    async def presentation_requests(request: Request) -> JSONResponse:
        if usecase is None:
            return _error(501, "not_implemented", "OID4VP désactivé")
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        presentation_definition = payload.get("presentation_definition")
        response_mode = str(payload.get("response_mode") or "direct_post")
        result = await usecase.create_presentation_request(
            presentation_definition=presentation_definition,
            response_mode=response_mode,
        )
        return JSONResponse(result, media_type=_JSON_MEDIA_TYPE)

    @router.post(
        "/vp_response",
        summary="Réception direct_post de la présentation (OID4VP)",
        response_model=None,
    )
    async def vp_response(request: Request) -> JSONResponse:
        # Validation de la présentation : tranche suivante (#223).
        return JSONResponse(
            {
                "error": "not_implemented",
                "error_description": "validation de réponse OID4VP pas encore implémentée.",
            },
            status_code=501,
            media_type=_JSON_MEDIA_TYPE,
        )

    return router


def _error(status_code: int, error: str, description: str) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        media_type=_JSON_MEDIA_TYPE,
    )
