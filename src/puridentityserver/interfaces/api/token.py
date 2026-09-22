"""Routes FastAPI de l'endpoint de jetons (RFC 6749 §4.1.3, §6, §4.4, RFC 7523, RFC 8628)."""

from __future__ import annotations

import base64
import json

from fastapi import APIRouter, Form, Request, Response

from puridentityserver.application.token import (
    TokenError,
    TokenRequest,
    TokenResponse,
    TokenUseCase,
)
from puridentityserver.infrastructure.client_tls import extract_client_certificate


def token_router(usecase: TokenUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``POST /token``."""
    router = APIRouter(tags=["token"])

    @router.post("/token", summary="Endpoint de jetons OAuth 2.0")
    async def token(
        request: Request,
        grant_type: str = Form(...),
        code: str = Form(default=""),
        redirect_uri: str = Form(default=""),
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
        code_verifier: str = Form(default=""),
        refresh_token: str = Form(default=""),
        scope: str = Form(default=""),
        device_code: str = Form(default=""),
        client_assertion_type: str = Form(default=""),
        client_assertion: str = Form(default=""),
        assertion: str = Form(default=""),
    ) -> Response:
        header_id, header_secret = _parse_basic_auth(request)
        if not client_id:
            client_id = header_id
        if not client_secret:
            client_secret = header_secret
        token_request = TokenRequest(
            grant_type=grant_type,
            code=code,
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            code_verifier=code_verifier,
            refresh_token=refresh_token,
            scope=scope,
            device_code=device_code,
            client_assertion_type=client_assertion_type,
            client_assertion=client_assertion,
            assertion=assertion,
            tls_certificate=extract_client_certificate(request),
        )
        result = await usecase.execute(token_request)
        if isinstance(result, TokenError):
            return _error_response(result)
        return _success_response(result)

    return router


def _parse_basic_auth(request: Request) -> tuple[str, str]:
    """Identifiants client depuis l'en-tête ``Authorization: Basic`` (RFC 7617)."""
    authorization = request.headers.get("Authorization", "")
    if not authorization.lower().startswith("basic "):
        return "", ""
    try:
        decoded = base64.b64decode(authorization.split(None, 1)[1], validate=True).decode("utf-8")
    except ValueError:
        return "", ""
    username, separator, password = decoded.partition(":")
    if not separator:
        return "", ""
    return username, password


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
    return Response(content=json.dumps(payload), media_type="application/json")


def _error_response(result: TokenError) -> Response:
    """Sérialise une réponse d'erreur au format JSON OAuth (HTTP 400)."""
    return Response(
        content=json.dumps({"error": result.error, "error_description": result.error_description}),
        media_type="application/json",
        status_code=400,
    )
