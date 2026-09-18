"""Routes FastAPI de l'endpoint d'autorisation (RFC 6749 §4.1, OIDC Core 1.0 §3)."""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Query
from fastapi.responses import RedirectResponse

from puridentityserver.application.authorize import (
    AuthorizeError,
    AuthorizeRedirect,
    AuthorizeRequest,
    AuthorizeUseCase,
)
from puridentityserver.domain.authorization import ResponseMode
from puridentityserver.identity.config import CurrentUserOptional


def authorize_router(usecase: AuthorizeUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``GET /authorize``."""
    router = APIRouter(tags=["authorize"])

    @router.get("/authorize", summary="Endpoint d'autorisation OAuth 2.0")
    async def authorize(
        response_type: str = Query(...),
        client_id: str = Query(...),
        redirect_uri: str = Query(...),
        scope: str = Query(...),
        state: str = Query(default=""),
        nonce: str = Query(default=""),
        code_challenge: str = Query(default=""),
        code_challenge_method: str = Query(default="S256"),
        response_mode: str = Query(default=""),
        user: CurrentUserOptional = None,
    ) -> RedirectResponse:
        auth_request = AuthorizeRequest(
            response_type=response_type,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            subject=str(user.id) if user is not None else "",
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            response_mode=response_mode,
        )
        result = await usecase.execute(auth_request)
        if isinstance(result, AuthorizeRedirect):
            return RedirectResponse(result.redirect_uri, status_code=302)
        return _error_redirect(result)

    return router


def _error_redirect(result: AuthorizeError) -> RedirectResponse:
    """Construit le redirect d'erreur vers ``redirect_uri``.

    Les erreurs des flows retournant des jetons (implicit/hybrid) sont
    placées dans le fragment de l'URL (RFC 6749 §4.2.2.1), les autres dans
    la query string (RFC 6749 §4.1.2.1).
    """
    parts = [f"error={result.error}"]
    if result.error_description:
        parts.append(f"error_description={quote(result.error_description, safe='')}")
    if result.state:
        parts.append(f"state={result.state}")
    params = "&".join(parts)
    separator = "#" if result.response_mode is ResponseMode.FRAGMENT else "?"
    location = f"{result.redirect_uri}{separator}{params}"
    return RedirectResponse(location, status_code=302)
