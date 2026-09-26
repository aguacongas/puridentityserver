"""Routes FastAPI de l'endpoint d'autorisation (RFC 6749 §4.1, OIDC Core 1.0 §3)."""

from __future__ import annotations

import html
from urllib.parse import parse_qs, quote

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from puridentityserver.application.authorize import (
    AuthorizeError,
    AuthorizeRedirect,
    AuthorizeRequest,
    AuthorizeUseCase,
    validate_authorization_request,
)
from puridentityserver.application.consent import ConsentUseCase
from puridentityserver.application.par import PushedAuthorizationUseCase, PushError
from puridentityserver.domain.authorization import ResponseMode, Scope
from puridentityserver.identity.config import CurrentUserOptional, session_auth_time, session_sid
from puridentityserver.interfaces.api.consent import consent_url
from puridentityserver.interfaces.repositories.readers import ClientReader


def authorize_router(
    usecase: AuthorizeUseCase,
    par_usecase: PushedAuthorizationUseCase | None = None,
    client_repository: ClientReader | None = None,
    consent_usecase: ConsentUseCase | None = None,
    *,
    require_login: bool = False,
    base_url: str = "",
) -> APIRouter:
    """Construit le routeur FastAPI exposant ``GET /authorize``.

    ``par_usecase`` active la résolution de ``request_uri`` (RFC 9126 §6.2) ;
    ``None`` (PAR désactivé) rejette toute référence poussée.
    ``client_repository`` permet d'appliquer l'obligation PAR par client
    (``par_required``, RFC 9126 §6.1) et de résoudre le client pour le
    consentement. ``consent_usecase`` active l'écran de consentement
    (``require_consent``, OIDC Core 1.0 §3.1.2.2) : la demande est alors
    redirigée vers ``/consent`` quand les scopes demandés ne sont pas déjà
    couverts par un consentement mémorisé. ``require_login`` : la demande non
    authentifiée est redirigée vers ``/login`` (OIDC Core 1.0 §3.1.2.1), ou
    renvoyée en erreur ``login_required`` quand ``prompt=none`` (§3.1.2.6).
    """
    router = APIRouter(tags=["authorize"])

    @router.get(
        "/authorize",
        summary="Endpoint d'autorisation OAuth 2.0",
        response_model=None,
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
        prompt: str = Query(default=""),
        request_uri: str = Query(default=""),
        user: CurrentUserOptional = None,
    ) -> RedirectResponse | HTMLResponse:
        params: dict[str, str] = {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "response_mode": response_mode,
            "prompt": prompt,
            "request_uri": request_uri,
        }
        return await _handle_authorize(request, params, user)

    @router.post(
        "/authorize",
        summary="Endpoint d'autorisation OAuth 2.0 (POST, RFC 6749 §4.1)",
        response_model=None,
        responses={
            400: {"description": "Erreur OAuth 2.0 (invalid_request, invalid_client…)."},
            422: {"description": "Paramètres requis manquants."},
        },
    )
    async def authorize_post(
        request: Request,
        user: CurrentUserOptional = None,
    ) -> RedirectResponse | HTMLResponse:
        """Traitement d'une demande ``POST /authorize`` (corps form-urlencoded)."""
        form = await request.form()
        params = {name: str(value) for name, value in form.items()}
        return await _handle_authorize(request, params, user)

    async def _handle_authorize(
        request: Request,
        params: dict[str, str],
        user: CurrentUserOptional,
    ) -> RedirectResponse | HTMLResponse:
        request_uri = params.get("request_uri", "")
        if request_uri:
            auth_request = await _resolve_pushed_request(
                request, params.get("client_id", ""), request_uri, par_usecase
            )
        else:
            missing = [
                name
                for name, value in (
                    ("response_type", params.get("response_type", "")),
                    ("client_id", params.get("client_id", "")),
                    ("redirect_uri", params.get("redirect_uri", "")),
                    ("scope", params.get("scope", "")),
                )
                if not value
            ]
            if missing:
                # RFC 6749 §3.1.1 / §4.1.2.1 : quand une demande d'autorisation
                # échoue en amont de toute redirection exploitable, l'OP doit
                # afficher une PAGE HTML d'erreur dans le navigateur de
                # l'utilisateur (pas un JSON) — c'est cette page que la suite
                # de certification hébergée (module ExpectResponseTypeMissing
                # ErrorPage) capture en screenshot.
                return HTMLResponse(
                    status_code=400,
                    content=(
                        '<!doctype html><html lang="fr"><head>'
                        '<meta charset="utf-8"><title>Erreur de la demande '
                        "d'autorisation</title><style>body{font-family:"
                        "sans-serif;margin:2rem;max-width:28rem}h1{font-size:"
                        "1.3rem}.hint{color:#666;font-size:0.9rem}</style>"
                        "</head><body><h1>Requête d'autorisation invalide</h1>"
                        '<p class="hint">Paramètres requis manquants : '
                        + ", ".join(html.escape(p) for p in missing)
                        + ". Conformément à la RFC 6749 §3.1.1, la demande ne "
                        "peut pas être traitée car un paramètre obligatoire "
                        "(dont <code>response_type</code>) est absent.</p>"
                        "</body></html>"
                    ),
                )
            await _enforce_par_requirement(params.get("client_id", ""), client_repository)
            auth_request = AuthorizeRequest(
                response_type=params.get("response_type", ""),
                client_id=params.get("client_id", ""),
                redirect_uri=params.get("redirect_uri", ""),
                scope=params.get("scope", ""),
                state=params.get("state", ""),
                nonce=params.get("nonce", ""),
                code_challenge=params.get("code_challenge", ""),
                code_challenge_method=params.get("code_challenge_method", "S256"),
                response_mode=params.get("response_mode", ""),
                prompt=params.get("prompt", ""),
            )

        if require_login and user is None:
            return await _login_or_error(auth_request, request, client_repository, base_url)

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
                prompt=auth_request.prompt,
                session_id=await session_sid(request),
                auth_time=await session_auth_time(request),
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


async def _login_or_error(
    auth_request: AuthorizeRequest,
    http_request: Request,
    client_repository: ClientReader | None,
    base_url: str = "",
) -> RedirectResponse:
    """Gère une demande ``/authorize`` non authentifiée (:param:`require_login`).

    ``prompt=none`` (OIDC Core 1.0 §3.1.2.6) : aucune redirection vers le
    formulaire n'est autorisée — une erreur ``login_required`` est renvoyée au
    client via sa ``redirect_uri`` (validation préalable pour ne jamais
    rediriger sur une URI non enregistrée). Sinon : redirection vers
    ``/login?next=<url complète d'/authorize>`` ; après connexion le
    ``subject`` est porté par le cookie et la demande est rejouée telle quelle.

    Le ``next`` est reconstruit depuis ``base_url`` (URL externe explicite de
    l'émetteur, jamais ``request.url`` : derrière un proxy de terminaison TLS
    l'en-tête Host ne porte pas le port non standard, ce qui cassait la
    redirection post-login avec e.g. ``https://host.example:8445``).
    """
    if "none" in auth_request.prompt.split():
        validated = (
            await validate_authorization_request(auth_request, client_repository)
            if client_repository is not None
            else None
        )
        if isinstance(validated, AuthorizeError):
            return _error_redirect(validated)
        error = AuthorizeError(
            error="login_required",
            error_description="Authentification requise (prompt=none)",
            redirect_uri=auth_request.redirect_uri,
            state=auth_request.state,
            response_mode=validated.response_mode if validated is not None else ResponseMode.QUERY,
        )
        return _error_redirect(error)
    return RedirectResponse(
        f"/login?next={quote(_authorize_url_from_base(base_url, http_request))}",
        status_code=302,
    )


def _authorize_url_from_base(base_url: str, http_request: Request) -> str:
    """URL ``/authorize`` absolue reconstruite depuis la base explicite.

    La query string brute du scope ASGI (déjà encodée) est conservée telle
    quelle ; la base sert d'autorité (schéma + hôte + port), indépendamment
    des en-têtes du proxy.
    """
    url = base_url.rstrip("/") + (http_request.scope.get("path") or "")
    query = http_request.scope.get("query_string") or b""
    if query:
        url += "?" + query.decode("latin-1")
    return url


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
