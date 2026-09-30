"""Routes FastAPI de l'endpoint d'autorisation (RFC 6749 §4.1, OIDC Core 1.0 §3)."""

from __future__ import annotations

import html
import time
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import parse_qs, quote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict

from puridentityserver.application.authorize import (
    AuthorizeError,
    AuthorizeRedirect,
    AuthorizeRequest,
    AuthorizeUseCase,
    parse_max_age,
    validate_authorization_request,
)
from puridentityserver.application.consent import ConsentUseCase
from puridentityserver.application.par import PushedAuthorizationUseCase, PushError
from puridentityserver.domain.authorization import ResponseMode, Scope
from puridentityserver.identity.config import (
    CurrentUser,
    CurrentUserOptional,
    reauth_context,
    session_auth_time,
    session_reauth,
    session_sid,
)
from puridentityserver.interfaces.api.authorize_error import error_response
from puridentityserver.interfaces.api.consent import consent_url
from puridentityserver.interfaces.repositories.readers import ClientReader


@dataclass
class _AuthorizeContext:
    """Contexte de ``GET /authorize`` : requête HTTP et utilisateur courant.

    Regroupé en dépendance : la route ne porte plus que ce contexte en plus
    de ses query parameters (S107), l'utilisateur étant déjà résolu par la
    chaîne de dépendances FastAPI Users.
    """

    request: Request
    user: CurrentUserOptional = None


def _authorize_context(request: Request, user: CurrentUserOptional = None) -> _AuthorizeContext:
    """Résout le couple (requête, utilisateur) injecté dans la route GET."""
    return _AuthorizeContext(request=request, user=user)


class AuthorizeQueryParams(BaseModel):
    """Query parameters de ``GET /authorize`` (RFC 6749 §4.1, OIDC Core 1.0 §3.1.2.1).

    Regroupés en modèle Pydantic injecté comme dépendance ``Query()`` : la
    route ne porte plus que ce modèle et son contexte (S107), chaque champ
    restant un query parameter distinct dans l'OpenAPI. Les paramètres
    inconnus sont ignorés (RFC 6749 §3.1 : « no constraints ») — des
    propriétés non standard ne doivent pas produire d'erreur 422.
    """

    model_config = ConfigDict(extra="ignore")

    response_type: str = ""
    client_id: str = ""
    redirect_uri: str = ""
    scope: str = ""
    state: str = ""
    nonce: str = ""
    code_challenge: str = ""
    code_challenge_method: str = "S256"
    response_mode: str = ""
    prompt: str = ""
    max_age: str = ""
    request_uri: str = ""
    acr_values: str = ""
    claims: str = ""


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
        context: Annotated[_AuthorizeContext, Depends(_authorize_context)],
        query: Annotated[AuthorizeQueryParams, Query()],
    ) -> RedirectResponse | HTMLResponse:
        return await _handle_authorize(context.request, query.model_dump(), context.user)

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
        # RFC 6749 §4.1.2 note : la demande voyage dans le corps, mais la
        # redirection vers /login part en query string. On mémorise le corps
        # traité pour que `next` (et le hash de réauthentification) rejoue
        # exactement les mêmes paramètres après connexion — sinon le retour
        # arrive sur /authorize nu et la suite de certification ne voit jamais
        # le callback (warning `ensure-post-request-succeeds`).
        request.state.form_query = urlencode(params) if params else ""
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
                max_age=parse_max_age(params.get("max_age", "")),
                acr_values=params.get("acr_values", ""),
                claims=params.get("claims", ""),
            )

        pre = await _pre_execution_response(
            auth_request, request, user, client_repository, require_login, base_url
        )
        if pre is not None:
            return pre

        if user is not None:
            auth_request = await _with_authenticated_subject(auth_request, request, user)
        consent_redirect = await _consent_redirect_if_required(
            auth_request, consent_usecase, client_repository
        )
        if consent_redirect is not None:
            return consent_redirect
        result = await usecase.execute(auth_request)
        if isinstance(result, AuthorizeRedirect):
            return RedirectResponse(result.redirect_uri, status_code=302)
        return error_response(result)

    return router


async def _pre_execution_response(
    auth_request: AuthorizeRequest,
    request: Request,
    user: CurrentUserOptional,
    client_repository: ClientReader | None,
    require_login: bool,
    base_url: str,
) -> RedirectResponse | HTMLResponse | None:
    """Réponses possibles **avant** émission : page d'erreur, reconnexion, ``prompt``.

    Regroupe ``_non_redirectable_error`` (la ``redirect_uri`` doit être
    vérifiée avant toute redirection sortante) puis ``_authentication_gate``
    (reconnexion exigée par ``prompt=login`` / ``max_age``). ``None`` : la
    demande peut être exécutée.
    """
    error_page = await _non_redirectable_error(auth_request, client_repository)
    if error_page is not None:
        return error_page
    return await _authentication_gate(
        auth_request, request, user, client_repository, require_login, base_url
    )


async def _with_authenticated_subject(
    auth_request: AuthorizeRequest, request: Request, user: CurrentUser
) -> AuthorizeRequest:
    """Rejoue la demande en portant ``subject``, ``auth_time`` et ``session_id``."""
    return AuthorizeRequest(
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
        max_age=auth_request.max_age,
        session_id=await session_sid(request),
        auth_time=await session_auth_time(request),
        acr_values=auth_request.acr_values,
        claims=auth_request.claims,
    )


async def _non_redirectable_error(
    auth_request: AuthorizeRequest, client_repository: ClientReader | None
) -> RedirectResponse | HTMLResponse | None:
    """Affiche la page d'erreur pour les erreurs qui interdisent la redirection.

    ``redirect_uri`` non enregistrée ou ``client_id`` invalide ne doivent
    jamais repartir en redirection (RFC 6749 §4.1.2.1) : la validation est
    menée **avant** toute redirection vers ``/login`` ou ``/consent`` pour
    que l'utilisateur voie immédiatement la page d'erreur. ``None`` quand
    rien n'empêche de poursuivre (demande valide ou erreur redirigeable,
    traitée plus loin après l'éventuelle reconnexion).
    """
    if client_repository is None:
        return None
    validated = await validate_authorization_request(auth_request, client_repository)
    if isinstance(validated, AuthorizeError) and not validated.redirectable:
        return error_response(validated)
    return None


async def _authentication_gate(
    auth_request: AuthorizeRequest,
    request: Request,
    user: CurrentUserOptional,
    client_repository: ClientReader | None,
    require_login: bool,
    base_url: str,
) -> RedirectResponse | HTMLResponse | None:
    """Contrôle d'accès avant émission : reconnexion, ``prompt``, ``max_age``.

    - ``prompt=login`` ou ``max_age`` expiré impose une authentification plus
      récente que la demande (OIDC Core 1.0 §3.1.2.1) : l'utilisateur connecté
      est renvoyé vers ``/login`` même s'il a déjà une session, la reconnexion
      rafraîchissant ``auth_time`` ;
    - ``prompt=none`` dans ce cas renvoie ``login_required`` au client plutôt
      que l'écran de connexion (§3.1.2.6) ;
    - non connecté : ``prompt=login`` ou ``require_login`` déclenchent le
      formulaire de connexion, ``prompt=none`` renvoie ``login_required``.
    """
    if user is not None and await _reauthentication_required(auth_request, request, base_url):
        if "none" in auth_request.prompt.split():
            return await _login_or_error(auth_request, request, client_repository, base_url)
        return _login_redirect(request, base_url)
    if user is None and (require_login or "login" in auth_request.prompt.split()):
        return await _login_or_error(auth_request, request, client_repository, base_url)
    return None


async def _reauthentication_required(
    auth_request: AuthorizeRequest, request: Request, base_url: str
) -> bool:
    """Indique si ``prompt=login`` / ``max_age`` exigent une reconnexion.

    ``prompt=login`` (et ``max_age=0``) est satisfait par une session issue
    d'un ``POST /login`` dont le ``next`` était **cette** URL d'autorisation :
    le claim ``reauth`` de la session porte son empreinte, ce qui évite toute
    boucle de reconnexion — un login déclenché par la demande la valide
    toujours. ``max_age`` strictement positif compare l'âge de la session à
    la valeur demandée ; l'``auth_time`` est lu sur la session courante (le
    ``auth_time`` de la demande n'est renseigné qu'après le contrôle, au
    moment de l'émission) — sans quoi tout ``max_age`` paraîtrait dépassé et
    la reconnexion tournerait en boucle.
    """
    session_reauth_hash = await session_reauth(request)
    url_hash = reauth_context(_authorize_url_from_base(base_url, request))
    tokens = auth_request.prompt.split()
    if ("login" in tokens or auth_request.max_age == 0) and session_reauth_hash != url_hash:
        return True
    if auth_request.max_age > 0:
        auth_time = await session_auth_time(request)
        if auth_time == 0:
            return True
        return (int(time.time()) - auth_time) > auth_request.max_age
    return False


def _login_redirect(request: Request, base_url: str) -> RedirectResponse:
    """Redirige vers ``/login`` en portant l'URL d'autorisation complète en ``next``."""
    return RedirectResponse(
        f"/login?next={quote(_authorize_url_from_base(base_url, request))}",
        status_code=302,
    )


async def _login_or_error(
    auth_request: AuthorizeRequest,
    http_request: Request,
    client_repository: ClientReader | None,
    base_url: str = "",
) -> RedirectResponse | HTMLResponse:
    """Gère une demande ``/authorize`` non réauthentifiée (``prompt``/``require_login``).

    ``prompt=none`` (OIDC Core 1.0 §3.1.2.6) : aucune redirection vers le
    formulaire n'est autorisée — une erreur ``login_required`` est renvoyée au
    client via sa ``redirect_uri`` (la ``redirect_uri`` a déjà été validée en
    amont par ``_non_redirectable_error``). Sinon : redirection vers
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
            return error_response(validated)
        error = AuthorizeError(
            error="login_required",
            error_description="Authentification requise (prompt=none)",
            redirect_uri=auth_request.redirect_uri,
            state=auth_request.state,
            response_mode=validated.response_mode if validated is not None else ResponseMode.QUERY,
        )
        return error_response(error)
    return _login_redirect(http_request, base_url)


def _authorize_url_from_base(base_url: str, http_request: Request) -> str:
    """URL ``/authorize`` absolue reconstruite depuis la base explicite.

    La query string de référence est celle que la demande a **traitée** : la
    query string ASGI d'un GET, sinon le corps form d'un POST (mémorisé par
    ``authorize_post``) — sans quoi la redirection vers ``/login`` perd les
    paramètres et le retour après connexion arrive sur ``/authorize`` nu.
    Elle est conservée brute (déjà encodée) ; la base sert d'autorité
    (schéma + hôte + port), indépendamment des en-têtes du proxy.
    """
    url = base_url.rstrip("/") + (http_request.scope.get("path") or "")
    query = getattr(http_request.state, "form_query", "") or (
        http_request.scope.get("query_string") or b""
    ).decode("latin-1")
    if query:
        url += "?" + query
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
