"""Route FastAPI de l'endpoint d'introspection (RFC 7662 §2)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Form, Response

from puridentityserver.application.introspect import (
    IntrospectError,
    IntrospectRequest,
    IntrospectResponse,
    IntrospectUseCase,
)


def introspect_router(usecase: IntrospectUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``POST /introspect``."""
    router = APIRouter(tags=["introspect"])

    @router.post("/introspect", summary="Introspection de jeton (RFC 7662)")
    async def introspect(
        token: str = Form(default=""),
        client_id: str = Form(...),
        client_secret: str = Form(default=""),
    ) -> Response:
        request = IntrospectRequest(
            token=token,
            client_id=client_id,
            client_secret=client_secret,
        )
        result = await usecase.execute(request)
        if isinstance(result, IntrospectError):
            return _error_response(result)
        return _success_response(result)

    return router


def _success_response(result: IntrospectResponse) -> Response:
    """Sérialise la réponse d'introspection (RFC 7662 §3)."""
    return Response(
        content=json.dumps({"active": result.active, **result.claims}),
        media_type="application/json",
    )


def _error_response(result: IntrospectError) -> Response:
    """Sérialise une erreur au format JSON OAuth avec le statut HTTP attendu."""
    return Response(
        content=json.dumps({"error": result.error, "error_description": result.error_description}),
        media_type="application/json",
        status_code=result.status_code,
    )
