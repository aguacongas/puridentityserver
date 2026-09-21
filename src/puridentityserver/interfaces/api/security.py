"""Authentification des endpoints de gestion par JWT Bearer.

Fournit l'extraction du jeton ``Authorization: Bearer`` et une fabrique de
dépendance FastAPI qui exige un jeton valide portant le claim configuré
(401 avec ``WWW-Authenticate: Bearer`` sinon).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, HTTPException, Request, params, status

from puridentityserver.application.claim_authorizer import BearerClaimAuthorizer


def bearer_token(request: Request) -> str:
    """Extrait le jeton de l'en-tête ``Authorization: Bearer <token>``."""
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def bearer_authorization_dependency(
    authorizer: BearerClaimAuthorizer,
) -> Callable[[Request], Awaitable[None]]:
    """Construit une dépendance FastAPI exigeant un JWT au claim attendu."""

    async def dependency(request: Request) -> None:
        """Rejette la requête (401) si le jeton est absent ou non autorisé."""
        token = bearer_token(request)
        if not token or not await authorizer.authorise(token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
                detail="invalid_token",
            )

    return dependency


def authorization_dependencies(
    authorizer: BearerClaimAuthorizer | None,
) -> list[params.Depends]:
    """Dépendances de routeur exigeant le JWT, ou liste vide si non protégé."""
    if authorizer is None:
        return []
    return [Depends(bearer_authorization_dependency(authorizer))]
