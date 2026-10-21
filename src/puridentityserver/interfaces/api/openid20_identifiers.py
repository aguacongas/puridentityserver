"""Routes FastAPI de gestion des associations OpenID 2.0 (spec de migration).

Expose ``GET /openid20-identifiers`` (consultation des anciens identifiants
liés aux comptes OpenID Connect) et ``POST /openid20-identifiers`` (liaison
d'un identifiant OpenID 2.0 à un compte). Les routes ne sont exposées que
lorsque le support de la migration est activé
(``PURIDENTITYSERVER_OPENID20_MIGRATION_ENABLED``) : sans lui, l'API
d'administration répond 404 et aucun chemin n'est actif.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import Response

from puridentityserver.application.claim_authorizer import BearerClaimAuthorizer
from puridentityserver.application.openid20_migration import OpenID20MigrationUseCase
from puridentityserver.domain.openid20 import OpenID20Identifier
from puridentityserver.interfaces.api.security import authorization_dependencies

_JSON_MEDIA_TYPE = "application/json"


def openid20_identifiers_router(
    usecase: OpenID20MigrationUseCase,
    *,
    authorizer: BearerClaimAuthorizer | None = None,
) -> APIRouter:
    """Construit le routeur FastAPI exposant les associations OpenID 2.0.

    Si ``authorizer`` est fourni, chaque route exige un JWT portant le claim
    configuré (401 sinon).
    """
    router = APIRouter(
        tags=["openid20-identifiers"], dependencies=authorization_dependencies(authorizer)
    )

    @router.get(
        "/openid20-identifiers",
        summary="Liste les identifiants OpenID 2.0 associés",
        response_model=None,
    )
    async def list_identifiers() -> Response:
        """Retourne les associations entre comptes et identifiants OpenID 2.0."""
        identifiers = await usecase.all_identifiers()
        return Response(
            content=json.dumps([_data_json(identifier) for identifier in identifiers]),
            media_type=_JSON_MEDIA_TYPE,
        )

    @router.post(
        "/openid20-identifiers",
        summary="Associe un identifiant OpenID 2.0 à un compte",
        response_model=None,
        responses={201: {"description": "Associé"}},
    )
    async def link_identifier(request: Request) -> Response:
        """Lie l'identifiant OpenID 2.0 reçu (JSON) au compte indiqué."""
        payload = await _json_body(request)
        if payload is None:
            return Response(
                content=json.dumps(
                    {
                        "error": "invalid_request",
                        "error_description": "Corps JSON invalide",
                    },
                    separators=(",", ":"),
                ),
                media_type=_JSON_MEDIA_TYPE,
                status_code=400,
            )
        identifier = await usecase.link(
            subject=str(payload.get("subject", "")),
            identifier=str(payload.get("identifier", "")),
            realm=str(payload.get("realm", "")),
        )
        return Response(
            content=json.dumps(_data_json(identifier)),
            media_type=_JSON_MEDIA_TYPE,
            status_code=201,
        )

    return router


async def _json_body(request: Request) -> dict[str, object] | None:
    """Décode le corps JSON de la requête (objet) ou retourne ``None``."""
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _data_json(identifier: OpenID20Identifier) -> dict[str, object]:
    """Sérialise une association au format de réponse."""
    return {
        "subject": identifier.subject,
        "identifier": identifier.identifier,
        "realm": identifier.realm,
        "created_at": identifier.created_at.isoformat(),
    }
