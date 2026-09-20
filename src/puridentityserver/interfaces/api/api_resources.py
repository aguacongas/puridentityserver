"""Routes FastAPI de gestion des ApiResources (CRUD).

Expose ``GET /api-resources`` (liste), ``POST /api-resources`` (création)
et, sur ``/api-resources/{name}``, la lecture (``GET``), le remplacement
(``PUT``) et la suppression (``DELETE``). Le corps des requêtes est du
JSON.
"""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Path, Request
from fastapi.responses import Response

from puridentityserver.application.api_resource import (
    ApiResourceData,
    ApiResourceError,
    ApiResourceRequest,
    ApiResourceUseCase,
)

_JSON_MEDIA_TYPE = "application/json"


def api_resources_router(usecase: ApiResourceUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant la gestion des ApiResources."""
    router = APIRouter(tags=["api-resources"])

    @router.get(
        "/api-resources",
        summary="Liste les ApiResources",
        response_model=None,
    )
    async def list_resources() -> Response:
        """Retourne la liste des ApiResources enregistrées."""
        resources = await usecase.list()
        return Response(
            content=json.dumps([_data_json(resource) for resource in resources]),
            media_type=_JSON_MEDIA_TYPE,
        )

    @router.post(
        "/api-resources",
        summary="Crée une ApiResource",
        response_model=None,
        responses={201: {"description": "Créée"}, 409: {"description": "Nom déjà pris"}},
    )
    async def create_resource(request: Request) -> Response:
        """Crée une ApiResource à partir de son JSON."""
        result = await _create(usecase, request)
        if isinstance(result, ApiResourceError):
            return _error_response(result)
        return Response(
            content=json.dumps(_data_json(result)),
            media_type=_JSON_MEDIA_TYPE,
            status_code=201,
            headers={"Location": f"/api-resources/{result.name}"},
        )

    @router.get(
        "/api-resources/{name}",
        summary="Lit une ApiResource",
        response_model=None,
        responses={404: {"description": "Inconnue"}},
    )
    async def read_resource(name: Annotated[str, Path()]) -> Response:
        """Relit la ApiResource identifiée par ``name``."""
        result = await usecase.read(name)
        if isinstance(result, ApiResourceError):
            return _error_response(result)
        return Response(content=json.dumps(_data_json(result)), media_type=_JSON_MEDIA_TYPE)

    @router.put(
        "/api-resources/{name}",
        summary="Remplace une ApiResource",
        response_model=None,
        responses={404: {"description": "Inconnue"}},
    )
    async def update_resource(name: Annotated[str, Path()], request: Request) -> Response:
        """Remplace la ApiResource identifiée par ``name`` (nom stable)."""
        result = await _update(usecase, name, request)
        if isinstance(result, ApiResourceError):
            return _error_response(result)
        return Response(content=json.dumps(_data_json(result)), media_type=_JSON_MEDIA_TYPE)

    @router.delete(
        "/api-resources/{name}",
        summary="Supprime une ApiResource",
        response_model=None,
        responses={204: {"description": "Supprimée"}, 404: {"description": "Inconnue"}},
    )
    async def delete_resource(name: Annotated[str, Path()]) -> Response:
        """Supprime la ApiResource identifiée par ``name``."""
        result = await usecase.delete(name)
        if isinstance(result, ApiResourceError):
            return _error_response(result)
        return Response(status_code=204)

    return router


async def _create(
    usecase: ApiResourceUseCase, request: Request
) -> ApiResourceData | ApiResourceError:
    """Décode le corps puis délègue la création au usecase."""
    payload = await _json_body(request)
    if isinstance(payload, ApiResourceError):
        return payload
    return await usecase.create(_parse_payload(payload))


async def _update(
    usecase: ApiResourceUseCase, name: str, request: Request
) -> ApiResourceData | ApiResourceError:
    """Décode le corps puis délègue le remplacement au usecase."""
    payload = await _json_body(request)
    if isinstance(payload, ApiResourceError):
        return payload
    return await usecase.update(name, _parse_payload(payload))


def _parse_payload(payload: dict[str, object]) -> ApiResourceRequest:
    """Transforme le JSON reçu en demande de gestion normalisée."""
    scopes = payload.get("scopes", ())
    if isinstance(scopes, list):
        parsed_scopes = frozenset(str(scope) for scope in scopes)
    else:
        parsed_scopes = frozenset()
    algos = payload.get("allowed_access_token_signing_algos", ())
    if isinstance(algos, list):
        parsed_algos = frozenset(str(algo) for algo in algos)
    else:
        parsed_algos = frozenset()
    return ApiResourceRequest(
        name=str(payload.get("name", "")),
        display_name=str(payload.get("display_name", "")),
        scopes=parsed_scopes,
        allowed_access_token_signing_algos=parsed_algos,
    )


async def _json_body(request: Request) -> dict[str, object] | ApiResourceError:
    """Décode le corps JSON de la requête (objet) ou retourne une erreur 400."""
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        return ApiResourceError("invalid_api_resource", "Corps JSON invalide", 400)
    if not isinstance(payload, dict):
        return ApiResourceError("invalid_api_resource", "Objet JSON attendu", 400)
    return payload


def _data_json(resource: ApiResourceData) -> dict[str, object]:
    """Sérialise une ApiResource au format de réponse."""
    return {
        "name": resource.name,
        "display_name": resource.display_name,
        "scopes": resource.scopes,
        "allowed_access_token_signing_algos": resource.allowed_access_token_signing_algos,
    }


def _error_response(error: ApiResourceError) -> Response:
    """Sérialise une erreur au format JSON OAuth (RFC 6749 §5.2)."""
    return Response(
        content=json.dumps(
            {"error": error.error, "error_description": error.error_description},
            separators=(",", ":"),
        ),
        media_type=_JSON_MEDIA_TYPE,
        status_code=error.status_code,
    )
