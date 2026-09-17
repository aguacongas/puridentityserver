"""Route FastAPI de l'endpoint de révocation de jeton (RFC 7009 §2)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Form, Response

from puridentityserver.application.revocation import (
    RevocationError,
    RevocationRequest,
    RevocationSuccess,
    RevocationUseCase,
)


def revocation_router(usecase: RevocationUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``POST /revoke``."""
    router = APIRouter(tags=["revocation"])

    @router.post("/revoke", summary="Révocation de jeton (RFC 7009)")
    async def revoke(
        token: str = Form(default=""),
        client_id: str = Form(...),
        client_secret: str = Form(default=""),
    ) -> Response:
        request = RevocationRequest(
            token=token,
            client_id=client_id,
            client_secret=client_secret,
        )
        result = await usecase.execute(request)
        if isinstance(result, RevocationError):
            return _error_response(result)
        return _success_response(result)

    return router


def _success_response(result: RevocationSuccess) -> Response:
    """Réponse de succès RFC 7009 §2.2 : HTTP 200 et corps vide.

    Le corps reste vide même pour un jeton inconnu ou invalide : la
    révocation ne doit pas révéler la validité d'un jeton.
    """
    return Response(status_code=200)


def _error_response(result: RevocationError) -> Response:
    """Sérialise une erreur au format JSON OAuth avec le statut HTTP attendu."""
    return Response(
        content=json.dumps({"error": result.error, "error_description": result.error_description}),
        media_type="application/json",
        status_code=result.status_code,
    )
