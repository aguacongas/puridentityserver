"""Routes FastAPI de l'endpoint d'autorisation (RFC 6749 §4.1)."""

from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import RedirectResponse

from thepuroidc.application.authorize import (
    AuthorizeError,
    AuthorizeRedirect,
    AuthorizeRequest,
    AuthorizeUseCase,
)
from thepuroidc.identity.config import CurrentUserOptional


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
        )
        result = await usecase.execute(auth_request)
        if isinstance(result, AuthorizeRedirect):
            return RedirectResponse(result.redirect_uri, status_code=302)
        return _error_redirect(result)

    return router


def _error_redirect(result: AuthorizeError) -> RedirectResponse:
    """Construit le redirect d'erreur vers ``redirect_uri``."""
    parts = [f"error={result.error}"]
    if result.error_description:
        parts.append(f"error_description={result.error_description}")
    if result.state:
        parts.append(f"state={result.state}")
    location = f"{result.redirect_uri}?{'&'.join(parts)}"
    return RedirectResponse(location, status_code=302)
