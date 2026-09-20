"""Routes FastAPI de gestion des IdentityResources (CRUD).

Expose ``GET /identity-resources`` (liste), ``POST /identity-resources``
(création) et, sur ``/identity-resources/{name}``, la lecture (``GET``),
le remplacement (``PUT``) et la suppression (``DELETE``). Le corps des
requêtes est du JSON.
"""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Path, Request
from fastapi.responses import Response

from puridentityserver.application.identity_resource import (
    IdentityResourceData,
    IdentityResourceError,
    IdentityResourceRequest,
    IdentityResourceUseCase,
)

_JSON_MEDIA_TYPE = "application/json"


def identity_resources_router(usecase: IdentityResourceUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant la gestion des IdentityResources."""
    router = APIRouter(tags=["identity-resources"])

    @router.get(
        "/identity-resources",
        summary="Liste les IdentityResources",
        response_model=None,
    )
    async def list_resources() -> Response:
        """Retourne la liste des IdentityResources enregistrées."""
        resources = await usecase.list()
        return Response(
            content=json.dumps([_data_json(resource) for resource in resources]),
            media_type=_JSON_MEDIA_TYPE,
        )

    @router.post(
        "/identity-resources",
        summary="Crée une IdentityResource",
        response_model=None,
        responses={201: {"description": "Créée"}, 409: {"description": "Nom déjà pris"}},
    )
    async def create_resource(request: Request) -> Response:
        """Crée une IdentityResource à partir de son JSON."""
        result = await _create(usecase, request)
        if isinstance(result, IdentityResourceError):
            return _error_response(result)
        return Response(
            content=json.dumps(_data_json(result)),
            media_type=_JSON_MEDIA_TYPE,
            status_code=201,
            headers={"Location": f"/identity-resources/{result.name}"},
        )

    @router.get(
        "/identity-resources/{name}",
        summary="Lit une IdentityResource",
        response_model=None,
        responses={404: {"description": "Inconnue"}},
    )
    async def read_resource(name: Annotated[str, Path()]) -> Response:
        """Relit la IdentityResource identifiée par ``name``."""
        result = await usecase.read(name)
        if isinstance(result, IdentityResourceError):
            return _error_response(result)
        return Response(content=json.dumps(_data_json(result)), media_type=_JSON_MEDIA_TYPE)

    @router.put(
        "/identity-resources/{name}",
        summary="Remplace une IdentityResource",
        response_model=None,
        responses={404: {"description": "Inconnue"}},
    )
    async def update_resource(name: Annotated[str, Path()], request: Request) -> Response:
        """Remplace la IdentityResource identifiée par ``name`` (nom stable)."""
        result = await _update(usecase, name, request)
        if isinstance(result, IdentityResourceError):
            return _error_response(result)
        return Response(content=json.dumps(_data_json(result)), media_type=_JSON_MEDIA_TYPE)

    @router.delete(
        "/identity-resources/{name}",
        summary="Supprime une IdentityResource",
        response_model=None,
        responses={204: {"description": "Supprimée"}, 404: {"description": "Inconnue"}},
    )
    async def delete_resource(name: Annotated[str, Path()]) -> Response:
        """Supprime la IdentityResource identifiée par ``name``."""
        result = await usecase.delete(name)
        if isinstance(result, IdentityResourceError):
            return _error_response(result)
        return Response(status_code=204)

    return router


async def _create(
    usecase: IdentityResourceUseCase, request: Request
) -> IdentityResourceData | IdentityResourceError:
    """Décode le corps puis délègue la création au usecase."""
    payload = await _json_body(request)
    if isinstance(payload, IdentityResourceError):
        return payload
    return await usecase.create(_parse_payload(payload))


async def _update(
    usecase: IdentityResourceUseCase, name: str, request: Request
) -> IdentityResourceData | IdentityResourceError:
    """Décode le corps puis délègue le remplacement au usecase."""
    payload = await _json_body(request)
    if isinstance(payload, IdentityResourceError):
        return payload
    return await usecase.update(name, _parse_payload(payload))


def _parse_payload(payload: dict[str, object]) -> IdentityResourceRequest:
    """Transforme le JSON reçu en demande de gestion normalisée."""
    claims = payload.get("user_claims", ())
    if isinstance(claims, list):
        user_claims = frozenset(str(claim) for claim in claims)
    else:
        user_claims = frozenset()
    return IdentityResourceRequest(
        name=str(payload.get("name", "")),
        display_name=str(payload.get("display_name", "")),
        user_claims=user_claims,
        show_in_discovery_document=bool(payload.get("show_in_discovery_document", True)),
    )


async def _json_body(request: Request) -> dict[str, object] | IdentityResourceError:
    """Décode le corps JSON de la requête (objet) ou retourne une erreur 400."""
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        return IdentityResourceError("invalid_identity_resource", "Corps JSON invalide", 400)
    if not isinstance(payload, dict):
        return IdentityResourceError("invalid_identity_resource", "Objet JSON attendu", 400)
    return payload


def _data_json(resource: IdentityResourceData) -> dict[str, object]:
    """Sérialise une IdentityResource au format de réponse."""
    return {
        "name": resource.name,
        "display_name": resource.display_name,
        "user_claims": resource.user_claims,
        "show_in_discovery_document": resource.show_in_discovery_document,
    }


def _error_response(error: IdentityResourceError) -> Response:
    """Sérialise une erreur au format JSON OAuth (RFC 6749 §5.2)."""
    return Response(
        content=json.dumps(
            {"error": error.error, "error_description": error.error_description},
            separators=(",", ":"),
        ),
        media_type=_JSON_MEDIA_TYPE,
        status_code=error.status_code,
    )
