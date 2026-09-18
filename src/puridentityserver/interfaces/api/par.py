"""Route FastAPI de la Pushed Authorization Request (RFC 9126).

Expose ``POST /par`` : le client pousse les paramètres d'autorisation en
corps ``application/x-www-form-urlencoded`` (comme à l'endpoint token, RFC
6749 §2.3) et reçoit un ``request_uri`` opaque à usage unique, JSON
``{request_uri, expires_in}`` (RFC 9126 §2).

Le ``client_id`` (et éventuellement le ``client_secret``) voyage dans le
corps form ; les échecs d'authentification répondent ``invalid_client``
(401), les paramètres invalides ``invalid_request``/``invalid_scope``/… (400).
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import Response

from puridentityserver.application.par import PushedAuthorizationUseCase, PushError

_JSON_MEDIA_TYPE = "application/json"


def par_router(usecase: PushedAuthorizationUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``POST /par`` (RFC 9126)."""
    router = APIRouter(tags=["par"])

    @router.post(
        "/par",
        summary="Pushed Authorization Request (RFC 9126)",
        response_model=None,
    )
    async def push(request: Request) -> Response:
        """Pousse une demande d'autorisation et retourne un request_uri à usage unique."""
        params = await _form_body(request)
        result = await usecase.push(params)
        if isinstance(result, PushError):
            return _error_response(result)
        return Response(
            content=json.dumps(
                {
                    "request_uri": result.request_uri,
                    "expires_in": result.expires_in,
                },
                separators=(",", ":"),
            ),
            media_type=_JSON_MEDIA_TYPE,
            status_code=201,
        )

    return router


async def _form_body(request: Request) -> dict[str, str]:
    """Décode le corps form-urlencodé de la requête.

    Les valeurs multiples pour une même clé sont concaténées avec un espace
    (cas de ``scope`` répété) ; les clés vides sont ignorées.
    """
    form = await request.form()
    params: dict[str, str] = {}
    for key, value in form.multi_items():
        if not key:
            continue
        parts = [params[key]] if key in params else []
        parts.append(str(value))
        params[key] = " ".join(parts)
    return params


def _error_response(error: PushError) -> Response:
    """Sérialise une erreur au format JSON OAuth (RFC 6749 §5.2)."""
    return Response(
        content=json.dumps(
            {"error": error.error, "error_description": error.error_description},
            separators=(",", ":"),
        ),
        media_type=_JSON_MEDIA_TYPE,
        status_code=error.status_code,
    )
