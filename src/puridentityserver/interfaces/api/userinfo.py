"""Route FastAPI de l'endpoint UserInfo (RFC 6750 §2, §3)."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Header, Response

from puridentityserver.application.userinfo import (
    UserInfoError,
    UserInfoRequest,
    UserInfoResponse,
    UserInfoUseCase,
)


def userinfo_router(usecase: UserInfoUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``GET /userinfo``."""
    router = APIRouter(tags=["userinfo"])

    @router.get("/userinfo", summary="Endpoint UserInfo (claims de l'utilisateur)")
    async def userinfo(
        authorization: Annotated[str | None, Header()] = None,
    ) -> Response:
        token = _extract_bearer_token(authorization)
        if token is None:
            return _bearer_error(
                "invalid_request",
                "En-tête Authorization 'Bearer' absent ou mal formé",
            )
        result = await usecase.execute(UserInfoRequest(access_token=token))
        if isinstance(result, UserInfoError):
            return _bearer_error(result.error, result.error_description)
        return _success_response(result)

    return router


def _extract_bearer_token(authorization: str | None) -> str | None:
    """Extrait le token d'un en-tête ``Authorization: Bearer <token>`` (RFC 6750 §2.1)."""
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def _success_response(result: UserInfoResponse) -> Response:
    """Sérialise les claims au format JSON (RFC 6750 §3.1)."""
    return Response(
        content=json.dumps(result.claims, ensure_ascii=False),
        media_type="application/json",
    )


def _bearer_error(error: str, description: str) -> Response:
    """Réponse d'erreur Bearer avec en-tête ``WWW-Authenticate`` (RFC 6750 §3).

    L'en-tête HTTP doit rester ASCII : seuls les codes d'erreur standard
    y figurent ; la description lisible passe dans le corps JSON.
    """
    return Response(
        content=json.dumps({"error": error, "error_description": description}),
        media_type="application/json",
        status_code=401,
        headers={"WWW-Authenticate": f'Bearer error="{error}"'},
    )
