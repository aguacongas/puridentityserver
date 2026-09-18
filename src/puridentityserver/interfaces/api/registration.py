"""Routes FastAPI de l'enregistrement dynamique de clients (RFC 7591 + 7592).

Expose ``POST /register`` (création) et, sur ``/register/{client_id}``,
les opérations de gestion autentifiées par le registration access token :
``GET`` (lecture), ``PUT`` (remplacement), ``DELETE`` (suppression).

Le corps des requêtes est du JSON ; l'authentification se fait dans
l'en-tête ``Authorization: Bearer <token>`` (initial access token pour la
création, registration access token pour la gestion).
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import Response

from puridentityserver.application.registration import (
    ClientRegistration,
    DeleteClientRequest,
    ReadClientRequest,
    RegisterRequest,
    RegistrationError,
    RegistrationUseCase,
    UpdateClientRequest,
)


def registration_router(usecase: RegistrationUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant les endpoints de registration."""
    router = APIRouter(tags=["registration"])

    @router.post(
        "/register",
        summary="Dynamic Client Registration (RFC 7591)",
        response_model=None,
    )
    async def register(request: Request) -> Response:
        """Crée un client à partir de ses métadonnées JSON (RFC 7591 §4)."""
        result = await _create_client(usecase, request)
        if isinstance(result, RegistrationError):
            return _error_response(result)
        return Response(
            content=_registration_json(result),
            media_type="application/json",
            status_code=201,
            headers={"Location": result.registration_client_uri},
        )

    @router.get(
        "/register/{client_id}",
        summary="Lecture de la configuration d'un client (RFC 7592 §2)",
        response_model=None,
    )
    async def read(client_id: str, request: Request) -> Response:
        """Relit la configuration enregistrée d'un client (registration token)."""
        result = await usecase.read(ReadClientRequest(client_id, _bearer_token(request)))
        if isinstance(result, RegistrationError):
            return _error_response(result)
        return Response(content=_registration_json(result), media_type="application/json")

    @router.put(
        "/register/{client_id}",
        summary="Remplacement de la configuration d'un client (RFC 7592 §3)",
        response_model=None,
    )
    async def update(client_id: str, request: Request) -> Response:
        """Remplace la configuration d'un client (registration token)."""
        result = await _update_client(usecase, client_id, request)
        if isinstance(result, RegistrationError):
            return _error_response(result)
        return Response(content=_registration_json(result), media_type="application/json")

    @router.delete(
        "/register/{client_id}",
        summary="Suppression d'un client (RFC 7592 §4)",
        response_model=None,
    )
    async def delete(client_id: str, request: Request) -> Response:
        """Supprime le client et sa configuration (registration token)."""
        result = await usecase.delete(DeleteClientRequest(client_id, _bearer_token(request)))
        if isinstance(result, RegistrationError):
            return _error_response(result)
        return Response(status_code=204)

    return router


async def _create_client(
    usecase: RegistrationUseCase, request: Request
) -> ClientRegistration | RegistrationError:
    """Décode le corps puis délègue la création au usecase."""
    payload = await _json_body(request)
    if isinstance(payload, RegistrationError):
        return payload
    return await usecase.register(
        RegisterRequest(payload, initial_access_token=_bearer_token(request))
    )


async def _update_client(
    usecase: RegistrationUseCase, client_id: str, request: Request
) -> ClientRegistration | RegistrationError:
    """Décode le corps puis délègue le remplacement au usecase."""
    payload = await _json_body(request)
    if isinstance(payload, RegistrationError):
        return payload
    return await usecase.update(UpdateClientRequest(client_id, _bearer_token(request), payload))


async def _json_body(request: Request) -> dict[str, object] | RegistrationError:
    """Décode le corps JSON de la requête (objet) ou retourne une erreur 400."""
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        return RegistrationError("invalid_client_metadata", "Corps JSON invalide", 400)
    if not isinstance(payload, dict):
        return RegistrationError("invalid_client_metadata", "Objet JSON attendu", 400)
    return payload


def _bearer_token(request: Request) -> str:
    """Extrait le jeton de l'en-tête ``Authorization: Bearer <token>``."""
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def _registration_json(result: ClientRegistration) -> str:
    """Sérialise la réponse de registration (RFC 7591 §3.2.1), sans champs vides."""
    data: dict[str, object] = {
        "client_id": result.client_id,
        "client_id_issued_at": result.client_id_issued_at,
        "token_endpoint_auth_method": result.token_endpoint_auth_method,
        "grant_types": result.grant_types,
        "response_types": result.response_types,
        "scope": result.scope,
        "redirect_uris": result.redirect_uris,
    }
    if result.post_logout_redirect_uris:
        data["post_logout_redirect_uris"] = result.post_logout_redirect_uris
    if result.client_secret:
        data["client_secret"] = result.client_secret
    if result.registration_access_token:
        data["registration_access_token"] = result.registration_access_token
    if result.registration_client_uri:
        data["registration_client_uri"] = result.registration_client_uri
    return json.dumps(data, separators=(",", ":"))


def _error_response(error: RegistrationError) -> Response:
    """Sérialise une erreur au format JSON OAuth (RFC 6749 §5.2)."""
    return Response(
        content=json.dumps(
            {"error": error.error, "error_description": error.error_description},
            separators=(",", ":"),
        ),
        media_type="application/json",
        status_code=error.status_code,
    )
