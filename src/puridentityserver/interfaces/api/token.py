"""Routes FastAPI de l'endpoint de jetons (RFC 6749 §4.1.3, §6, §4.4, RFC 7523, RFC 8628)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Form, Request, Response
from starlette.datastructures import FormData

from puridentityserver.application.token import (
    TokenError,
    TokenRequest,
    TokenResponse,
    TokenUseCase,
)
from puridentityserver.infrastructure.client_tls import extract_client_certificate
from puridentityserver.interfaces.api.dpop_proof import extract_dpop_proof
from puridentityserver.interfaces.api.error_description import ascii_error_description
from puridentityserver.interfaces.api.http_client_auth import parse_basic_auth


def token_router(usecase: TokenUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``POST /token``."""
    router = APIRouter(tags=["token"])

    @router.post("/token", summary="Endpoint de jetons OAuth 2.0")
    async def token(request: Request, grant_type: str = Form(...)) -> Response:
        dpop_proof, dpop_error = extract_dpop_proof(request.headers)
        if dpop_error is not None:
            error = TokenError(error="invalid_request", error_description=dpop_error)
            return _error_response(error)
        header_id, header_secret = parse_basic_auth(request)
        form = await request.form()
        client_id = _form_field(form, "client_id") or header_id
        client_secret = _form_field(form, "client_secret") or header_secret
        token_request = TokenRequest(
            grant_type=grant_type,
            code=_form_field(form, "code"),
            redirect_uri=_form_field(form, "redirect_uri"),
            client_id=client_id,
            client_secret=client_secret,
            code_verifier=_form_field(form, "code_verifier"),
            refresh_token=_form_field(form, "refresh_token"),
            scope=_form_field(form, "scope"),
            device_code=_form_field(form, "device_code"),
            auth_req_id=_form_field(form, "auth_req_id"),
            client_assertion_type=_form_field(form, "client_assertion_type"),
            client_assertion=_form_field(form, "client_assertion"),
            assertion=_form_field(form, "assertion"),
            tls_certificate=extract_client_certificate(request),
            dpop_proof=dpop_proof,
        )
        result = await usecase.execute(token_request)
        if isinstance(result, TokenError):
            return _error_response(result)
        return _success_response(result)

    return router


def _form_field(form: FormData, name: str) -> str:
    """Valeur texte d'un champ du corps form (absent ou non texte → ``""``)."""
    value = form.get(name)
    return str(value) if isinstance(value, str) else ""


def _success_response(result: TokenResponse) -> Response:
    """Sérialise une réponse de succès au format JSON OAuth."""
    payload: dict[str, object] = {
        "access_token": result.access_token,
        "token_type": result.token_type,
        "expires_in": result.expires_in,
        "scope": result.scope,
    }
    if result.id_token:
        payload["id_token"] = result.id_token
    if result.refresh_token:
        payload["refresh_token"] = result.refresh_token
    return Response(
        content=json.dumps(payload),
        media_type="application/json",
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _error_response(result: TokenError) -> Response:
    """Sérialise une réponse d'erreur au format JSON OAuth (HTTP 400)."""
    return Response(
        content=json.dumps(
            {
                "error": result.error,
                "error_description": ascii_error_description(result.error_description),
            }
        ),
        media_type="application/json",
        status_code=400,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )
