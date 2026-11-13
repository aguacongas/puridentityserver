"""Routes FastAPI OpenID4VP : initiation verifier et réception direct_post.jwt.

Le préfixe ``/oid4vp`` isole la surface de présentation (issue #224) :

- ``POST /oid4vp/presentation_requests`` : crée et signe une demande ;
- ``GET|POST /oid4vp/request_uri/{request_id}`` : sert le request object
  (le POST porte le ``wallet_nonce`` du mode ``request_uri_method=post``) ;
- ``POST /oid4vp/vp_response/{request_id}`` : reçoit la présentation chiffrée
  du wallet et renvoie le verdict de la section 8.2 ;
- ``GET /oid4vp/result/{request_id}`` : page de résultat du ``redirect_uri``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from puridentityserver.application.oid4vp import (
    REQUEST_OBJECT_MEDIA_TYPE,
    OID4VPVerifierUseCase,
)

_JSON_MEDIA_TYPE = "application/json"

#: Motif du 501 rendu par chaque route quand le verifier n'est pas monté.
_DISABLED_DETAIL = "OpenID4VP non active"


def oid4vp_router(
    *,
    oid4vp_usecase: OID4VPVerifierUseCase | None = None,
) -> APIRouter:
    """Construit le routeur FastAPI de présentation OpenID4VP.

    Args:
        oid4vp_usecase: cas d'utilisation du verifier, ``None`` si la
            feature est désactivée (chaque route répond alors 501).

    Returns:
        Le routeur prêt à être monté sur l'application.
    """
    router = APIRouter(tags=["oid4vp"])
    _mount_presentation_requests(router, oid4vp_usecase)
    _mount_request_uri(router, oid4vp_usecase)
    _mount_vp_response(router, oid4vp_usecase)
    _mount_result(router, oid4vp_usecase)
    return router


def _mount_presentation_requests(router: APIRouter, usecase: OID4VPVerifierUseCase | None) -> None:
    """Monte ``POST /oid4vp/presentation_requests`` (création signée)."""

    @router.post(
        "/oid4vp/presentation_requests",
        summary="Crée une demande de présentation signée (OID4VP)",
        status_code=201,
        response_model=None,
    )
    async def presentation_requests(request: Request) -> JSONResponse:
        if usecase is None:
            return _error(501, "not_implemented", _DISABLED_DETAIL)
        payload = await _json_body(request)
        if payload is None:
            return _error(400, "invalid_request", "corps JSON objet attendu")
        dcql_query = payload.get("dcql_query")
        if dcql_query is not None and not isinstance(dcql_query, dict):
            return _error(400, "invalid_request", "dcql_query attendu comme objet JSON")
        created = usecase.create_presentation_request(dcql_query=dcql_query)
        return JSONResponse(
            {
                "request_id": created.request_id,
                "client_id": created.client_id,
                "request_uri": created.request_uri,
                "nonce": created.nonce,
                "request_object": created.request_object,
            },
            status_code=201,
        )


def _mount_request_uri(router: APIRouter, usecase: OID4VPVerifierUseCase | None) -> None:
    """Monte le ``request_uri`` du verifier (GET idempotent, POST wallet_nonce)."""

    @router.get(
        "/oid4vp/request_uri/{request_id}",
        summary="Sert le request object signé (GET idempotent)",
        response_model=None,
    )
    async def get_request_object(request_id: str) -> Response:
        if usecase is None:
            return _error(501, "not_implemented", _DISABLED_DETAIL)
        document = usecase.get_request_object(request_id)
        if document is None:
            return _error(404, "invalid_request", "demande de presentation inconnue")
        return Response(content=document, media_type=REQUEST_OBJECT_MEDIA_TYPE)

    @router.post(
        "/oid4vp/request_uri/{request_id}",
        summary="Sert le request object enrichi du wallet_nonce (POST)",
        response_model=None,
    )
    async def post_request_object(request: Request, request_id: str) -> Response:
        if usecase is None:
            return _error(501, "not_implemented", _DISABLED_DETAIL)
        form = await request.form()
        wallet_nonce = form.get("wallet_nonce")
        document = usecase.get_request_object(
            request_id,
            wallet_nonce=wallet_nonce if isinstance(wallet_nonce, str) else None,
        )
        if document is None:
            return _error(404, "invalid_request", "demande de presentation inconnue")
        return Response(content=document, media_type=REQUEST_OBJECT_MEDIA_TYPE)


def _mount_vp_response(router: APIRouter, usecase: OID4VPVerifierUseCase | None) -> None:
    """Monte le ``response_uri`` qui reçoit la présentation chiffrée."""

    @router.post(
        "/oid4vp/vp_response/{request_id}",
        summary="Reçoit la présentation chiffrée du wallet (direct_post.jwt)",
        response_model=None,
    )
    async def vp_response(request: Request, request_id: str) -> JSONResponse:
        if usecase is None:
            return _error(501, "not_implemented", _DISABLED_DETAIL)
        form = await request.form()
        response = form.get("response")
        if not isinstance(response, str) or not response:
            return _error(400, "invalid_request", "paramètre de formulaire response manquant")
        # La validation peut fetcher la status list référencée par le
        # credential (réseau bloquant) : hors de la boucle d'événements.
        result = await asyncio.to_thread(
            usecase.validate_presentation_response, request_id, response=response
        )
        return JSONResponse(result.body, status_code=result.status_code)


def _mount_result(router: APIRouter, usecase: OID4VPVerifierUseCase | None) -> None:
    """Monte la page de résultat visitée via le ``redirect_uri``."""

    @router.get(
        "/oid4vp/result/{request_id}",
        summary="Page de résultat visitée via le redirect_uri du verifier",
        response_model=None,
    )
    async def result_page(request_id: str) -> HTMLResponse:
        if usecase is None:
            return HTMLResponse("<h1>OpenID4VP non active</h1>", status_code=501)
        page = usecase.result_page(request_id)
        if page is None:
            return HTMLResponse("<h1>Demande inconnue</h1>", status_code=404)
        return HTMLResponse(page)


async def _json_body(request: Request) -> dict[str, Any] | None:
    """Lit le corps JSON d'une requête ; ``{}`` si vide, ``None`` si invalide."""
    try:
        raw = await request.body()
        if not raw.strip():
            return {}
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _error(status_code: int, error: str, description: str) -> JSONResponse:
    """Réponse d'erreur OAuth 2.0 en JSON (RFC 6749 §5.2)."""
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        media_type=_JSON_MEDIA_TYPE,
    )
