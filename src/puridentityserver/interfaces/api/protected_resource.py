"""Route FastAPI du resource server intégré (FAPI-R-6.2.1, RFC 6750 §2).

Le jeton est exigé en en-tête ``Authorization: Bearer`` (RFC 6750 §2.1) ;
le transport en query string — déconseillé par §2.3 — est refusé. Chaque
réponse porte l'en-tête ``x-fapi-interaction-id`` (FAPI 1.0 §7.4) :
valeur reçue échoyée, ou `uuid4` généré quand le client n'en envoie pas
(la suite l'exige en réponse même sans l'avoir émis).
"""

from __future__ import annotations

import json
from uuid import uuid4

from fastapi import APIRouter, Request, Response

from puridentityserver.application.protected_resource import (
    ProtectedResourceError,
    ProtectedResourceRequest,
    ProtectedResourceResponse,
    ProtectedResourceUseCase,
)
from puridentityserver.infrastructure.client_tls import extract_client_certificate
from puridentityserver.interfaces.api.security import bearer_token

#: En-tête d'interaction FAPI échoyé sur les réponses de la ressource.
_FAPI_INTERACTION_ID = "x-fapi-interaction-id"


def protected_resource_router(usecase: ProtectedResourceUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``GET /protected-resource``."""
    router = APIRouter(tags=["resource"])

    @router.get(
        "/protected-resource",
        summary="Ressource protégée (resource server, FAPI-R-6.2.1)",
    )
    async def protected_resource(request: Request) -> Response:
        interaction_id = _interaction_id(request)
        query_token = request.query_params.get("access_token", "")
        if query_token and not bearer_token(request):
            return _error_response(
                ProtectedResourceError(
                    error="invalid_request",
                    error_description=("Transport du jeton en query string refusé (RFC 6750 §2.3)"),
                ),
                interaction_id,
            )
        token = bearer_token(request)
        if not token:
            return _error_response(
                ProtectedResourceError(
                    error="invalid_request",
                    error_description=(
                        "En-tête Authorization 'Bearer <token>' attendu (RFC 6750 §2.1)"
                    ),
                ),
                interaction_id,
            )
        result = await usecase.execute(
            ProtectedResourceRequest(
                access_token=token, tls_certificate=extract_client_certificate(request)
            )
        )
        if isinstance(result, ProtectedResourceError):
            return _error_response(result, interaction_id)
        return _success_response(result, interaction_id)

    return router


def _interaction_id(request: Request) -> str:
    """Valeur ``x-fapi-interaction-id`` reçue, ou `uuid4` à défaut (FAPI 1.0 §7.4)."""
    received = request.headers.get(_FAPI_INTERACTION_ID, "").strip()
    return received or str(uuid4())


def _success_response(result: ProtectedResourceResponse, interaction_id: str) -> Response:
    """Sérialise la réponse protégée en JSON (200, FAPI-R-6.2.1-1)."""
    payload = {
        "message": "Ressource protégée accessible",
        "sub": result.subject,
        "scope": result.scope,
    }
    return Response(
        content=json.dumps(payload, ensure_ascii=False),
        media_type="application/json",
        headers={
            _FAPI_INTERACTION_ID: interaction_id,
            "Cache-Control": "no-store",
        },
    )


def _error_response(result: ProtectedResourceError, interaction_id: str) -> Response:
    """Sérialise l'erreur en JSON avec challenge ``WWW-Authenticate`` (RFC 6750 §3)."""
    return Response(
        content=json.dumps(
            {"error": result.error, "error_description": result.error_description},
            ensure_ascii=False,
        ),
        media_type="application/json",
        status_code=401,
        headers={
            "WWW-Authenticate": f'Bearer error="{result.error}"',
            _FAPI_INTERACTION_ID: interaction_id,
            "Cache-Control": "no-store",
        },
    )
