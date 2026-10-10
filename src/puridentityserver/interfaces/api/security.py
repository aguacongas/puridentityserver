"""Authentification des endpoints de gestion par JWT Bearer.

Fournit l'extraction du jeton ``Authorization: Bearer`` et une fabrique de
dépendance FastAPI qui exige un jeton valide portant le claim configuré
(401 avec ``WWW-Authenticate: Bearer`` sinon), plus la dépendance qui déclare
le schéma OAuth2 de Swagger UI (bouton « Authorize » de ``/docs``).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, HTTPException, Request, Security, params, status
from fastapi.security import OAuth2AuthorizationCodeBearer

from puridentityserver.application.claim_authorizer import BearerClaimAuthorizer
from puridentityserver.infrastructure.settings import Settings

# Nom du schéma OAuth2 publié dans `components.securitySchemes` du document OpenAPI.
_SWAGGER_OAUTH2_SCHEME_NAME = "oidc"


def bearer_token(request: Request) -> str:
    """Extrait le jeton de l'en-tête ``Authorization: Bearer <token>``."""
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def split_authorization(authorization: str | None) -> tuple[str, str | None]:
    """Scheme et jeton d'un en-tête ``Authorization: <scheme> <token>`` (RFC 6750 §2.1).

    ``bearer`` et ``dpop`` (RFC 9449 §7.1) sont reconnus, sans distinction
    de casse (RFC 9110 §11.1 : le nom du scheme est insensible à la
    casse) ; tout autre scheme produit un jeton absent, trahi par un
    ``invalid_request``.
    """
    if not authorization:
        return "", None
    scheme, _, token = authorization.partition(" ")
    token = token.strip()
    scheme = scheme.lower()
    if scheme not in ("bearer", "dpop") or not token:
        return scheme, None
    return scheme, token


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


def swagger_oauth2_dependencies(settings: Settings) -> list[params.Depends]:
    """Dépendances de routeur déclarant le schéma OAuth2 de Swagger UI.

    Le schéma (authorization code + PKCE, URL d'autorisation et de jeton
    construites sur ``base_url`` ou ``issuer``) est publié dans
    ``components.securitySchemes`` et référencé par les opérations montées
    avec ces dépendances : Swagger UI affiche alors le bouton Authorize et
    pré-sélectionne les scopes ``openid`` + ``admin_required_claim_values``.
    Retourne une liste vide si ``swagger_ui_oauth2_enabled`` est désactivé :
    le document OpenAPI reste inchangé et aucun bouton n'apparaît.
    """
    if not settings.swagger_ui_oauth2_enabled:
        return []
    scopes = ["openid", *settings.admin_required_claim_values]
    base_url = (settings.base_url or settings.issuer).rstrip("/")
    scheme = OAuth2AuthorizationCodeBearer(
        authorizationUrl=f"{base_url}/authorize",
        tokenUrl=f"{base_url}/token",
        scopes=dict.fromkeys(scopes, ""),
        description="Authentification OIDC (authorization code + PKCE) contre ce serveur",
        auto_error=False,
        scheme_name=_SWAGGER_OAUTH2_SCHEME_NAME,
    )
    return [Security(scheme, scopes=scopes)]
