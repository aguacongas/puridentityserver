"""Routes FastAPI de l'endpoint d'autorisation (RFC 6749 §4.1, OIDC Core 1.0 §3)."""

from __future__ import annotations

from urllib.parse import parse_qs, quote

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import RedirectResponse

from puridentityserver.application.authorize import (
    AuthorizeError,
    AuthorizeRedirect,
    AuthorizeRequest,
    AuthorizeUseCase,
)
from puridentityserver.application.consent import ConsentUseCase
from puridentityserver.application.par import PushedAuthorizationUseCase, PushError
from puridentityserver.domain.authorization import ResponseMode, Scope
from puridentityserver.identity.config import CurrentUserOptional, session_sid
from puridentityserver.interfaces.api.consent import consent_url
from puridentityserver.interfaces.repositories.readers import ClientReader


def authorize_router(
    usecase: AuthorizeUseCase,
    par_usecase: PushedAuthorizationUseCase | None = None,
    client_repository: ClientReader | None = None,
    consent_usecase: ConsentUseCase | None = None,
) -> APIRouter:
    """Construit le routeur FastAPI exposant ``GET /authorize``.

    ``par_usecase`` active la résolution de ``request_uri`` (RFC 9126 §6.2) ;
    ``None`` (PAR désactivé) rejette toute référence poussée.
    ``client_repository`` permet d'appliquer l'obligation PAR par client
    (``par_required``, RFC 9126 §6.1) et de résoudre le client pour le
    consentement. ``consent_usecase`` active l'écran de consentement
    (``require_consent``, OIDC Core 1.0 §3.1.2.2) : la demande est alors
    redirigée vers ``/consent`` quand les scopes demandés ne sont pas déjà
    couverts par un consentement mémorisé.
    """
    router = APIRouter(tags=["authorize"])

    @router.get(
        "/authorize",
        summary="Endpoint d'autorisation OAuth 2.0",
        responses={
            400: {
                "description": "Erreur OAuth 2.0 (invalid_request, invalid_client, "
                "obligation PAR par client…)."
            },
            422: {"description": "Paramètres requis manquants."},
        },
    )
    async def authorize(
        request: Request,
        response_type: str = Query(default=""),
        client_id: str = Query(default=""),
        redirect_uri: str = Query(default=""),
        scope: str = Query(default=""),
        state: str = Query(default=""),
        nonce: str = Query(default=""),
        code_challenge: str = Query(default=""),
        code_challenge_method: str = Query(default="S256"),
        response_mode: str = Query(default=""),
        request_uri: str = Query(default=""),
        user: CurrentUserOptional = None,
    ) -> RedirectResponse:
        if request_uri:
            auth_request = await _resolve_pushed_request(
                request, client_id, request_uri, par_usecase
            )
        else:
            missing = [
                name
                for name, value in (
                    ("response_type", response_type),
                    ("client_id", client_id),
                    ("redirect_uri", redirect_uri),
                    ("scope", scope),
                )
                if not value
            ]
            if missing:
                raise HTTPException(
                    status_code=422,
                    detail=f"Paramètres requis manquants : {', '.join(missing)}",
                )
            await _enforce_par_requirement(client_id, client_repository)
            auth_request = AuthorizeRequest(
                response_type=response_type,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                nonce=nonce,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                response_mode=response_mode,
            )

        if user is not None:
            auth_request = AuthorizeRequest(
                response_type=auth_request.response_type,
                client_id=auth_request.client_id,
                redirect_uri=auth_request.redirect_uri,
                scope=auth_request.scope,
                subject=str(user.id),
                state=auth_request.state,
                nonce=auth_request.nonce,
                code_challenge=auth_request.code_challenge,
                code_challenge_method=auth_request.code_challenge_method,
                response_mode=auth_request.response_mode,
                session_id=await session_sid(request),
            )
        consent_redirect = await _consent_redirect_if_required(
            auth_request, consent_usecase, client_repository
        )
        if consent_redirect is not None:
            return consent_redirect
        result = await usecase.execute(auth_request)
        if isinstance(result, AuthorizeRedirect):
            return RedirectResponse(result.redirect_uri, status_code=302)
        return _error_redirect(result)

    return router


async def _resolve_pushed_request(
    request: Request,
    client_id: str,
    request_uri: str,
    par_usecase: PushedAuthorizationUseCase | None,
) -> AuthorizeRequest:
    """Résout une référence poussée (RFC 9126 §6.2).

    La query string brute de ``/authorize`` ne doit contenir que ``client_id``
    et ``request_uri`` : le serveur ignore les paramètres déjà poussés et
    rejette tout paramètre supplémentaire. Les erreurs de résolution
    (référence inconnue, expirée, consommée, client incohérent ; PAR
    désactivé) répondent en JSON ``invalid_request``.
    """
    if par_usecase is None:
        raise _push_error(
            PushError(
                error="invalid_request",
                error_description="Pushed Authorization Request désactivé",
                status_code=400,
            )
        )

    allowed = {"client_id", "request_uri"}
    unexpected = [
        name for name in parse_qs(request.url.query, keep_blank_values=True) if name not in allowed
    ]
    if unexpected:
        raise _push_error(
            PushError(
                error="invalid_request",
                error_description="Les paramètres supplémentaires sont interdits "
                "avec request_uri (RFC 9126 §6.2)",
                status_code=400,
            )
        )

    resolved = await par_usecase.resolve(request_uri=request_uri, client_id=client_id)
    if isinstance(resolved, PushError):
        raise _push_error(resolved)
    return resolved


def _push_error(error: PushError) -> HTTPException:
    """Construit l'exception HTTP JSON structurée d'une erreur PAR."""
    return HTTPException(
        status_code=error.status_code,
        detail={"error": error.error, "error_description": error.error_description},
    )


async def _enforce_par_requirement(client_id: str, client_repository: ClientReader | None) -> None:
    """Refuse une demande directe à /authorize si le client exige PAR (RFC 9126 §6.1).

    Un client marqué ``par_required`` doit pousser ses paramètres via
    ``POST /par`` puis présenter le ``request_uri`` à l'endpoint
    d'autorisation ; toute demande non poussée est rejetée en
    ``invalid_request``.
    """
    if client_repository is None:
        return
    client = await client_repository.find_by_id(client_id)
    if client is not None and client.par_required:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "Ce client exige l'utilisation de Pushed "
                "Authorization Request (RFC 9126 §6.1)",
            },
        )


async def _consent_redirect_if_required(
    request: AuthorizeRequest,
    consent_usecase: ConsentUseCase | None,
    client_repository: ClientReader | None,
) -> RedirectResponse | None:
    """Retourne la redirection vers ``/consent`` quand le consentement est requis.

    Délégué à ``ConsentUseCase.is_required`` : un client sans
    ``require_consent`` ne passe jamais par la page ; un consentement déjà
    mémorisé couvrant la demande (``Consent.covers``) n'est pas redemandé.
    Utilisateur non connecté (``subject`` vide) : la page de consentement
    redirigera elle-même vers ``/login`` — aucun code ou jeton n'est émis
    sans confirmation pour les clients ``require_consent``.
    """
    if consent_usecase is None or client_repository is None:
        return None
    client = await client_repository.find_by_id(request.client_id)
    scopes = Scope.from_space_separated(request.scope)
    if client is not None and await consent_usecase.is_required(client, request.subject, scopes):
        return RedirectResponse(consent_url(request), status_code=302)
    return None


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
