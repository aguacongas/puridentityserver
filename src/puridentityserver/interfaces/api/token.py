"""Routes FastAPI de l'endpoint de jetons (RFC 6749 §4.1.3, §6)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Form, Response

from puridentityserver.application.token import (
    TokenError,
    TokenRequest,
    TokenResponse,
    TokenUseCase,
)


def token_router(usecase: TokenUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``POST /token``."""
    router = APIRouter(tags=["token"])

    @router.post("/token", summary="Endpoint de jetons OAuth 2.0")
    async def token(
        grant_type: str = Form(...),
        code: str = Form(default=""),
        redirect_uri: str = Form(default=""),
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
        code_verifier: str = Form(default=""),
        refresh_token: str = Form(default=""),
        scope: str = Form(default=""),
        device_code: str = Form(default=""),
    ) -> Response:
        request = TokenRequest(
            grant_type=grant_type,
            code=code,
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            code_verifier=code_verifier,
            refresh_token=refresh_token,
            scope=scope,
            device_code=device_code,
        )
        result = await usecase.execute(request)
        if isinstance(result, TokenError):
            return _error_response(result)
        return _success_response(result)

    return router


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
