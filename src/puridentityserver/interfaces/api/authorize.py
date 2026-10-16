"""Routes FastAPI de l'endpoint d'autorisation (RFC 6749 §4.1, OIDC Core 1.0 §3)."""

from __future__ import annotations

import html
import time
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
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
from puridentityserver.application.request_object import (
    RequestObjectError,
    RequestObjectResolver,
    is_pushed_request_uri,
)
from puridentityserver.application.resource_indicators import encode_resource_parameter
from puridentityserver.domain.authorization import ResponseMode, Scope
from puridentityserver.identity.config import (
    CurrentUser,
    CurrentUserOptional,
    reauth_context,
    session_auth_time,
    session_reauth,
    session_sid,
)
from puridentityserver.interfaces.api.authorize_error import error_redirect, error_response
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
    request: str = ""
    request_uri: str = ""
    acr_values: str = ""
    claims: str = ""
    dpop_jkt: str = ""
    resource: list[str] = []


def authorize_router(
    usecase: AuthorizeUseCase,
    par_usecase: PushedAuthorizationUseCase | None = None,
    client_repository: ClientReader | None = None,
    consent_usecase: ConsentUseCase | None = None,
    *,
    request_object_resolver: RequestObjectResolver,
    par_required: bool = False,
    require_login: bool = False,
    base_url: str = "",
) -> APIRouter:
    """Construit le routeur FastAPI exposant ``GET /authorize``.

    ``request_object_resolver`` incorpore le request object (RFC 9101) aux
    paramètres d'une demande non poussée, ``par_usecase`` résout au contraire
    la référence opaque ``request_uri`` (RFC 9126 §6.2) — ``None`` (PAR
    désactivé) rejette toute référence poussée. ``request_uris`` RFC 9101
    pointant un document hébergé ailleurs n'ont besoin que du resolver.
    ``client_repository`` permet d'appliquer l'obligation PAR par client
    (``par_required``, RFC 9126 §6.1) et de résoudre le client pour le
    consentement ; ``par_required`` (serveur) l'étend à **tous** les
    clients. ``consent_usecase`` active l'écran de consentement
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
    ) -> RedirectResponse | HTMLResponse | Response:
        return await _handle_authorize(context.request, _query_params(query), context.user)

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
    ) -> RedirectResponse | HTMLResponse | Response:
        """Traitement d'une demande ``POST /authorize`` (corps form-urlencoded)."""
        form = await request.form()
        params = {name: str(value) for name, value in form.items()}
        params["resource"] = encode_resource_parameter([str(v) for v in form.getlist("resource")])
        # RFC 6749 §4.1.2 note : la demande voyage dans le corps, mais la
        # redirection vers /login part en query string. On mémorise le corps
        # traité pour que `next` (et le hash de réauthentification) rejoue
        # exactement les mêmes paramètres après connexion — sinon le retour
        # arrive sur /authorize nu et la suite de certification ne voit jamais
        # le callback (warning `ensure-post-request-succeeds`).
        request.state.form_query = urlencode(params)
        return await _handle_authorize(request, params, user)

    async def _handle_authorize(
        request: Request,
        params: dict[str, str],
        user: CurrentUserOptional,
    ) -> RedirectResponse | HTMLResponse | Response:
        auth_request, pushed_reference = await _authorize_entry(
            params,
            par_usecase=par_usecase,
            request_object_resolver=request_object_resolver,
            client_repository=client_repository,
            par_required=par_required,
        )
        if isinstance(auth_request, Response):
            return auth_request
        pre = await _pre_execution_response(
            auth_request, request, user, client_repository, require_login, base_url
        )
        if pre is not None:
            return pre

        if user is not None:
            auth_request = await _with_authenticated_subject(auth_request, request, user)
        consent_redirect = await _consent_redirect_if_required(
            auth_request, consent_usecase, client_repository, pushed_reference
        )
        if consent_redirect is not None:
            return consent_redirect
        result = await usecase.execute(auth_request)
        if isinstance(result, AuthorizeRedirect):
            return await _success_redirect(result, par_usecase, pushed_reference)
        return error_response(result)

    return router


async def _success_redirect(
    result: AuthorizeRedirect,
    par_usecase: PushedAuthorizationUseCase | None,
    pushed_reference: str,
) -> RedirectResponse:
    """Redirection de succès ; consomme la référence poussée le cas échéant.

    La consommation unique de la demande poussée est appliquée à
    l'émission réussie de la réponse (RFC 9126 §4) : la visite de
    ``/authorize`` reste répétable jusqu'à l'achèvement du flux
    (conformance-suite #1296).
    """
    if par_usecase is not None and pushed_reference:
        await par_usecase.complete(pushed_reference)
    return RedirectResponse(result.redirect_uri, status_code=302)


async def _direct_authorize_request(
    params: dict[str, str],
    request_object_resolver: RequestObjectResolver,
    client_repository: ClientReader | None,
    par_required: bool = False,
) -> AuthorizeRequest | RedirectResponse | HTMLResponse:
    """Construit la demande d'une requête **non poussée** (RFC 6749 §3.1).

    Le request object (RFC 9101) est résolu en premier : ses claims priment
    sur la query (OIDC Core 1.0 §6.1), qui n'est plus qu'un repli. Puis les
    paramètres requis sont contrôlés et l'obligation PAR du client appliquée
    (RFC 9126 §6.1). Un request object refusé suit le transport
    ``/authorize`` (RFC 6749 §4.1.2.1, issue #178) : redirection vers la
    ``redirect_uri`` de la query quand elle est exactement enregistrée,
    page HTML sinon — c'est l'observable du placeholder
    ``ExpectAuthorizationRequestWithoutRequestObjectErrorPage`` de la
    suite. Les paramètres manquants restent rendus en **page HTML**
    (check ``ExpectResponseTypeMissingErrorPage`` exigé par la suite).
    Le refus PAR, lui, se redirige vers la ``redirect_uri`` de la query
    quand elle est enregistrée (issue #160), page HTML sinon.
    """
    resolved = await request_object_resolver.resolve(params)
    if isinstance(resolved, RequestObjectError):
        return await _request_object_error_response(resolved, params, client_repository)
    params = resolved
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
        return _missing_parameters_page(missing)
    enforced = await _enforce_par_requirement(params, client_repository, par_required)
    if enforced is not None:
        return enforced
    return AuthorizeRequest(
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
        dpop_jkt=params.get("dpop_jkt", ""),
        resource=params.get("resource", ""),
    )


def _query_params(query: AuthorizeQueryParams) -> dict[str, str]:
    """Plat le modèle de query en paramètres de chaînes (RFC 8707 inclus).

    ``resource`` peut être répété (``?resource=a&resource=b``) : les
    occurrences sont repliées en tableau JSON compact, forme décodée par
    ``parse_resource_parameter`` — les dictionnaires de params ne gardent
    qu'une valeur par clé.
    """
    raw = query.model_dump()
    resources = raw.pop("resource", [])
    values = resources if isinstance(resources, list) else [resources]
    raw["resource"] = encode_resource_parameter([str(value) for value in values])
    return {name: str(value) for name, value in raw.items()}


def _missing_parameters_page(missing: list[str]) -> HTMLResponse:
    """Page d'erreur 400 listant les paramètres requis absents (RFC 6749 §3.1.1)."""
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
            + ", ".join(html.escape(name) for name in missing)
            + ". Conformément à la RFC 6749 §3.1.1, la demande ne "
            "peut pas être traitée car un paramètre obligatoire "
            "(dont <code>response_type</code>) est absent.</p>"
            "</body></html>"
        ),
    )


def _request_object_error_page(error: RequestObjectError) -> HTMLResponse:
    """Page d'erreur 400 d'un request object refusé sans callback sûr (RFC 9101 §6, §7).

    Repli de :func:`_request_object_error_response` (issue #178) : sans
    ``redirect_uri`` de la query exactement enregistrée pour le client —
    la RFC 6749 §4.1.2.1 interdit alors de rediriger.
    """
    return HTMLResponse(
        status_code=400,
        content=(
            '<!doctype html><html lang="fr"><head><meta charset="utf-8">'
            "<title>Erreur de la demande d'autorisation</title><style>body{"
            "font-family:sans-serif;margin:2rem;max-width:28rem}h1{font-size:"
            "1.3rem}.hint{color:#666;font-size:0.9rem}</style></head><body>"
            "<h1>Requête d'autorisation invalide</h1>"
            '<p class="hint"><code>'
            + html.escape(error.error)
            + "</code> — "
            + html.escape(error.error_description)
            + "</p></body></html>"
        ),
    )


async def _request_object_error_response(
    error: RequestObjectError,
    params: dict[str, str],
    client_repository: ClientReader | None,
) -> RedirectResponse | HTMLResponse:
    """Transporte un refus de request object (RFC 6749 §4.1.2.1, issue #178).

    La ``redirect_uri`` de la **query** reçoit une redirection 302 portant
    ``error``, ``error_description`` et ``state`` quand elle fait un exact
    match sur les ``redirect_uris`` du client (URI validée à
    l'enregistrement, même garantie que les erreurs PAR de l'issue #160) :
    les claims du request object rejeté — qui n'est pas fiable par
    définition — ne sont jamais utilisés pour choisir la cible. Sans
    callback sûr (URI absente ou non enregistrée, client inconnu), la
    page HTML d'erreur est servie.

    L'enveloppe suit le ``response_type`` du transport : le fragment
    d'entrée (implicit/hybrid, FAPI1 ``code id_token``) impose de renvoyer
    l'erreur dans le fragment de la callback (RFC 6749 §4.1.2.1,
    §4.2.2.1 — ``response_mode=query`` y est interdit), la query sinon.
    Le ``state`` écho vient du request object lui-même quand il est lisible
    (RFC 9101 §6.3), de la query à défaut.
    """
    if client_repository is None:
        return _request_object_error_page(error)
    client = await client_repository.find_by_id(params.get("client_id", ""))
    if client is None:
        return _request_object_error_page(error)
    redirect_uri = params.get("redirect_uri", "")
    if redirect_uri not in client.redirect_uris:
        return _request_object_error_page(error)
    response_type = params.get("response_type", "")
    has_tokens = bool({"token", "id_token"} & set(response_type.split()))
    requested_mode = params.get("response_mode", "")
    if requested_mode == ResponseMode.FRAGMENT.value or has_tokens:
        response_mode = ResponseMode.FRAGMENT
    else:
        response_mode = ResponseMode.QUERY
    return error_redirect(
        AuthorizeError(
            error=error.error,
            error_description=error.error_description,
            redirect_uri=redirect_uri,
            state=error.state or params.get("state", ""),
            response_mode=response_mode,
        )
    )


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
        dpop_jkt=auth_request.dpop_jkt,
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
    la reconnexion tournerait en boucle. Même mécanisme d'anti-boucle lorsque
    l'âge dépasse ``max_age>0`` : si la session vient d'un login déclenché par
    **cette** URL (empreinte ``reauth``), le dépassement est imputable à la
    latence de l'OP, pas à une session ancienne, et la demande est validée.
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
        if (int(time.time()) - auth_time) <= auth_request.max_age:
            return False
        return session_reauth_hash != url_hash
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


async def _authorize_entry(
    params: dict[str, str],
    *,
    par_usecase: PushedAuthorizationUseCase | None,
    request_object_resolver: RequestObjectResolver,
    client_repository: ClientReader | None,
    par_required: bool,
) -> tuple[AuthorizeRequest | Response, str]:
    """Résout l'entrée ``/authorize`` : poussée (``request_uri``) ou directe.

    Retourne ``(demande, pushed_reference)`` — la ``Response`` d'erreur
    tient la place de la demande quand la résolution échoue (page HTML,
    cf. :func:`_pushed_param_response`, issue #160) ; ``pushed_reference``
    (vide hors PAR) accompagne le reste du parcours pour consommer la
    demande poussée à l'émission.
    """
    request_uri = params.get("request_uri", "")
    if request_uri and is_pushed_request_uri(request_uri):
        resolved = await _resolve_pushed_request(
            params.get("client_id", ""), request_uri, par_usecase
        )
        return resolved, request_uri
    built = await _direct_authorize_request(
        params, request_object_resolver, client_repository, par_required
    )
    if isinstance(built, HTMLResponse):
        return built, ""
    return built, ""


async def _resolve_pushed_request(
    client_id: str,
    request_uri: str,
    par_usecase: PushedAuthorizationUseCase | None,
) -> AuthorizeRequest | Response:
    """Résout une référence poussée (RFC 9126 §4).

    La query string de ``/authorize`` peut contenir d'autres paramètres que
    ``client_id`` et ``request_uri`` (la suite de certification en ajoute) :
    ils sont ignorés — seule la charge utile poussée fait foi (RFC 9126 §4 :
    la requête issue du PAR se valide comme n'importe quelle requête
    d'autorisation, son contenu venant du ``request_uri`` ; §7.5 : l'intégrité
    de la requête est portée par la charge poussée, les paramètres de la
    redirection ne peuvent donc rien y changer). Les erreurs de résolution
    (référence inconnue, expirée, consommée → ``invalid_request_uri`` ;
    client incohérent → ``invalid_request`` ; PAR désactivé →
    ``invalid_request``) suivent le transport ``/authorize`` (RFC 6749
    §4.1.2.1, issue #160) : une redirection 302 vers le callback de la
    demande poussée quand ce callback reste connu du store (référence
    expirée, déjà consommée ou d'un autre client), page HTML d'erreur
    sinon (référence inconnue, PAR désactivé).
    """
    if par_usecase is None:
        return _pushed_param_response(
            PushError(
                error="invalid_request",
                error_description="Pushed Authorization Request désactivé",
                status_code=400,
            )
        )

    resolved = await par_usecase.resolve(request_uri=request_uri, client_id=client_id)
    if isinstance(resolved, PushError):
        return _pushed_param_response(resolved)
    return resolved


def _pushed_param_response(error: PushError) -> Response:
    """Transporte une erreur de résolution poussée (RFC 6749 §4.1.2.1, issue #160).

    Une ``redirect_uri`` poussée encore connue (référence expirée, déjà
    consommée ou présentée par un autre client) reçoit une redirection 302
    portant ``error``, ``error_description`` et ``state`` (redirection sûre :
    cette URI a été validée à l'enregistrement puis au push). Sans
    ``redirect_uri`` exploitable (référence inconnue, PAR désactivé), une
    page HTML d'erreur est servie au user agent (RFC 6749 §4.1.2.1 : pas de
    redirection vers un callback inconnu).
    """
    if not error.redirect_uri:
        return _pushed_error_page(error)
    return error_redirect(
        AuthorizeError(
            error=error.error,
            error_description=error.error_description,
            redirect_uri=error.redirect_uri,
            state=error.state,
            response_mode=error.response_mode,
            redirectable=True,
        )
    )


def _pushed_error_page(error: PushError) -> HTMLResponse:
    """Page d'erreur 400 d'une résolution poussée sans callback sûr (issue #160)."""
    return HTMLResponse(
        status_code=400,
        content=(
            '<!doctype html><html lang="fr"><head><meta charset="utf-8">'
            "<title>Erreur de la demande d'autorisation</title><style>body{"
            "font-family:sans-serif;margin:2rem;max-width:28rem}h1{font-size:"
            "1.3rem}.hint{color:#666;font-size:0.9rem}</style></head><body>"
            "<h1>Requête d'autorisation invalide</h1>"
            '<p class="hint"><code>'
            + html.escape(error.error)
            + "</code> — "
            + html.escape(error.error_description)
            + "</p></body></html>"
        ),
    )


async def _enforce_par_requirement(
    params: dict[str, str],
    client_repository: ClientReader | None,
    server_par_required: bool = False,
) -> RedirectResponse | HTMLResponse | None:
    """Refuse une demande directe à /authorize si PAR est exigé (RFC 9126 §6.1).

    Un client marqué ``par_required`` (ou ``fapi2_enabled``, FAPI2-SP-5.3.2.2-4 :
    FAPI2 n'admet que les demandes poussées) doit passer par ``POST /par``
    puis présenter le ``request_uri`` à l'endpoint d'autorisation ; le
    drapeau serveur ``server_par_required`` impose la même discipline à
    **tous** les clients. Toute demande non poussée est rejetée en
    ``invalid_request`` (issue #160) : une redirection 302 quand la
    ``redirect_uri`` de la query est exactement enregistrée pour le client
    (redirection sûre), page HTML d'erreur sinon — ``None`` quand aucune
    exigence PAR ne s'applique.
    """
    if client_repository is None:
        return None
    client = await client_repository.find_by_id(params.get("client_id", ""))
    if client is None:
        return None
    if not (client.par_required or client.fapi2_enabled or server_par_required):
        return None
    description = "Ce client exige l'utilisation de Pushed Authorization Request (RFC 9126 §6.1)"
    redirect_uri = params.get("redirect_uri", "")
    if redirect_uri and redirect_uri in client.redirect_uris:
        return error_redirect(
            AuthorizeError(
                error="invalid_request",
                error_description=description,
                redirect_uri=redirect_uri,
                state=params.get("state", ""),
            )
        )
    return _pushed_error_page(PushError(error="invalid_request", error_description=description))


async def _consent_redirect_if_required(
    request: AuthorizeRequest,
    consent_usecase: ConsentUseCase | None,
    client_repository: ClientReader | None,
    pushed_reference: str = "",
) -> RedirectResponse | None:
    """Retourne la redirection vers ``/consent`` quand le consentement est requis.

    Délégué à ``ConsentUseCase.is_required`` : un client sans
    ``require_consent`` ne passe jamais par la page ; un consentement déjà
    mémorisé couvrant la demande (``Consent.covers``) n'est pas redemandé,
    sauf ``prompt=consent`` (OIDC Core 1.0 §3.1.2.1) qui force l'écran
    même quand la demande est couverte. Utilisateur non connecté
    (``subject`` vide) : la page de consentement redirigera elle-même vers
    ``/login`` — aucun code ou jeton n'est émis sans confirmation pour les
    clients ``require_consent``.
    ``pushed_reference`` (PAR) accompagne la page : l'approbation consomme
    la demande poussée à l'émission du code.
    """
    if consent_usecase is None or client_repository is None:
        return None
    client = await client_repository.find_by_id(request.client_id)
    scopes = Scope.from_space_separated(request.scope)
    forced = "consent" in request.prompt.split()
    if client is not None and await consent_usecase.is_required(
        client, request.subject, scopes, force=forced
    ):
        return RedirectResponse(consent_url(request, pushed_reference), status_code=302)
    return None
