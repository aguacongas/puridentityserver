"""Page de consentement OAuth (OIDC Core 1.0 §3.1.2.2).

``/authorize`` redirige ici (via ``consent_url``) dès qu'un client
marqué ``require_consent`` demande des scopes non encore couverts par le
consentement mémorisé de l'utilisateur connecté. ``GET /consent``
affiche l'écran (client, scopes, destination) et ``POST /consent``
applique la décision :

- autoriser → ``ConsentUseCase.grant`` puis exécution directe
  d'``AuthorizeUseCase`` : l'utilisateur récupère le code / les jetons
  dans sa ``redirect_uri`` sans repasser par ``/authorize`` (indispensable
  pour PAR, dont le ``request_uri`` est à usage unique) ; la référence
  poussée est alors consommée (``pushed_reference``, même invariant que
  ``_success_redirect``) ;
- refuser → redirection d'erreur ``access_denied`` vers ``redirect_uri``.

Utilisateur non connecté : redirection vers le formulaire de connexion
(``/login?next=<consent>``), le consentement étant lié au ``subject``.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import quote, urlencode, urlsplit

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict

from puridentityserver.application.authorize import (
    AuthorizeError,
    AuthorizeRequest,
    AuthorizeUseCase,
    validate_authorization_request,
)
from puridentityserver.application.consent import ConsentUseCase
from puridentityserver.application.jarm import JarmSigner
from puridentityserver.application.par import PushedAuthorizationUseCase
from puridentityserver.domain.authorization import Scope
from puridentityserver.identity.config import CurrentUserOptional
from puridentityserver.interfaces.api.authorize_error import error_response
from puridentityserver.interfaces.api.form_post import authorization_response
from puridentityserver.interfaces.repositories.readers import ClientReader

_SCOPE_LABELS = {
    Scope.OPENID: "S'identifier (OpenID)",
    Scope.PROFILE: "Consulter votre profil",
    Scope.EMAIL: "Consulter votre adresse e-mail",
    Scope.ADDRESS: "Consulter votre adresse postale",
    Scope.PHONE: "Consulter votre numéro de téléphone",
    Scope.OFFLINE_ACCESS: "Rester connecté hors ligne (refresh token)",
}

_PAGE_TEMPLATE = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>PurIdentityServer — autoriser une application</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 28rem; }}
    h1 {{ font-size: 1.3rem; }}
    ul {{ padding-left: 1.2rem; }}
    li {{ margin: 0.3rem 0; }}
    button {{ margin-top: 1rem; padding: 0.5rem 1.2rem; margin-right: 0.5rem; }}
    .hint {{ color: #666; font-size: 0.9rem; }}
    .action {{ color: #b00020; }}
  </style>
</head>
<body>
  <h1>Autoriser <em>{client_id}</em>&nbsp;?</h1>
  <p class="hint">L'application <strong>{client_id}</strong> souhaite
  {scope_list} de votre part :</p>
  <ul>{scopes}</ul>
  <p class="hint">Après votre accord, elle recevra la réponse sur
  <code>{redirect_uri}</code>. Vous pouvez aussi
  <a href="{logout_url}">vous déconnecter</a> avant de décider.</p>
  <form method="post" action="/consent">
    {hidden}
    <button type="submit" name="action" value="authorize">Autoriser</button>
    <button type="submit" name="action" value="deny" class="action">Refuser</button>
  </form>
</body>
</html>
"""


def _consent_params(request: AuthorizeRequest, pushed_reference: str = "") -> dict[str, str]:
    """Paramètres d'autorisation portés par l'URL de consentement.

    Les champs sont énumérés explicitement (jamais ``getattr``) afin de
    garder un typage strict et un ordre stable pour les champs cachés du
    formulaire. La ``request_uri`` ne circule pas comme paramètre
    d'autorisation (la page travaille sur les paramètres poussés) : seule
    son alias opaque ``pushed_reference`` l'accompagne (vide hors PAR) pour
    que l'approbation consomme la demande poussée à l'émission de la
    réponse.
    """
    params = {
        "response_type": request.response_type,
        "client_id": request.client_id,
        "redirect_uri": request.redirect_uri,
        "scope": request.scope,
        "state": request.state,
        "nonce": request.nonce,
        "code_challenge": request.code_challenge,
        "code_challenge_method": request.code_challenge_method,
        "response_mode": request.response_mode,
        "prompt": request.prompt,
        "acr_values": request.acr_values,
        "claims": request.claims,
        "dpop_jkt": request.dpop_jkt,
    }
    if pushed_reference:
        params["pushed_reference"] = pushed_reference
    return params


def consent_url(request: AuthorizeRequest, pushed_reference: str = "") -> str:
    """URL de la page de consentement portant les paramètres d'autorisation."""
    return "/consent?" + urlencode(_consent_params(request, pushed_reference))


@dataclass
class _ConsentContext:
    """Contexte des routes ``/consent`` : référence PAR poussée et utilisateur.

    Regroupé en dépendance : les routes ne portent plus que leurs query /
    form parameters et ce contexte (S107), l'utilisateur étant déjà résolu
    par la chaîne de dépendances FastAPI Users. ``pushed_reference``
    circule en query (GET) ou en champ de formulaire (POST) — même alias
    opaque dans les deux cas, jamais la ``request_uri`` elle-même.
    """

    pushed_reference: str = ""
    user: CurrentUserOptional = None


class _ConsentQueryParams(BaseModel):
    """Query parameters de ``GET /consent`` (miroir des champs d'autorisation).

    Regroupés en modèle Pydantic injecté comme dépendance ``Query()`` : la
    route ne porte plus que ce modèle et son contexte (S107), chaque champ
    restant un query parameter distinct dans l'OpenAPI. Valeurs par défaut
    identiques à celles de ``GET /authorize``.
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
    acr_values: str = ""
    claims: str = ""
    dpop_jkt: str = ""
    authorization_details: str = ""


class _ConsentFormParams(BaseModel):
    """Champs du formulaire ``POST /consent`` (décision autoriser / refuser).

    Regroupés en modèle Pydantic injecté comme dépendance ``Form()`` (S107) :
    ``response_type``, ``client_id`` et ``scope`` restent obligatoires (422
    en leur absence). ``prompt`` voyage en champ caché mais n'est pas relu :
    il ne fait que forcer l'affichage de la page, déjà consommé au GET.
    """

    model_config = ConfigDict(extra="ignore")

    response_type: str
    client_id: str
    scope: str
    redirect_uri: str = ""
    state: str = ""
    nonce: str = ""
    code_challenge: str = ""
    code_challenge_method: str = "S256"
    response_mode: str = ""
    acr_values: str = ""
    claims: str = ""
    dpop_jkt: str = ""
    authorization_details: str = ""
    action: str = "authorize"


def _authorize_request(params: _ConsentQueryParams | _ConsentFormParams) -> AuthorizeRequest:
    """Reconstruit l'``AuthorizeRequest`` d'un modèle de page de consentement.

    Les deux modèles (query GET / formulaire POST) portent les mêmes champs
    d'autorisation ; ``prompt`` n'est relevé que sur le GET (le POST ne
    reconstruit pas ce paramètre, l'écran ayant déjà été consommé).
    """
    prompt = params.prompt if isinstance(params, _ConsentQueryParams) else ""
    return AuthorizeRequest(
        response_type=params.response_type,
        client_id=params.client_id,
        redirect_uri=params.redirect_uri,
        scope=params.scope,
        state=params.state,
        nonce=params.nonce,
        code_challenge=params.code_challenge,
        code_challenge_method=params.code_challenge_method,
        response_mode=params.response_mode,
        prompt=prompt,
        acr_values=params.acr_values,
        claims=params.claims,
        dpop_jkt=params.dpop_jkt,
        authorization_details=getattr(params, "authorization_details", ""),
    )


async def _consent_context(
    request: Request,
    user: CurrentUserOptional = None,
) -> _ConsentContext:
    """Résout la ``pushed_reference`` (query GET ou champ form POST) et l'utilisateur."""
    if request.method == "POST":
        form = await request.form()
        raw = form.get("pushed_reference", "")
        pushed_reference = raw if isinstance(raw, str) else ""
    else:
        pushed_reference = request.query_params.get("pushed_reference", "")
    return _ConsentContext(pushed_reference=pushed_reference, user=user)


def consent_router(
    consent_usecase: ConsentUseCase,
    authorize_usecase: AuthorizeUseCase,
    client_repository: ClientReader,
    par_usecase: PushedAuthorizationUseCase | None = None,
    *,
    jarm_signer: JarmSigner | None = None,
    issuer: str = "",
) -> APIRouter:
    """Construit le routeur FastAPI exposant la page de consentement ``/consent``.

    ``par_usecase`` (``None`` : PAR désactivé) consomme la ``pushed_reference``
    au moment où l'approbation émet la réponse d'autorisation — même
    invariant que la redirection de succès de ``GET /authorize``.
    ``jarm_signer`` signe les refus redirigeables (``access_denied`` du
    bouton « Refuser », erreurs de re-validation) en ``response_mode=jwt``
    (JARM Final 1.0 §3) ; sans injection, ils restent en query/fragment.
    ``issuer`` porte l'identifiant d'émetteur publié par discovery, réfléchi
    en ``iss`` dans les erreurs soumises en ``response_mode=form_post``
    (RFC 9207 §2) ; ignoré hors ``form_post``.
    """
    router = APIRouter(tags=["consent"])

    @router.get(
        "/consent",
        response_class=HTMLResponse,
        response_model=None,
        summary="Page de consentement OAuth",
        responses={400: {"description": "redirect_uri requis"}},
    )
    async def consent_prompt(
        context: Annotated[_ConsentContext, Depends(_consent_context)],
        params: Annotated[_ConsentQueryParams, Query()],
    ) -> RedirectResponse | HTMLResponse | str:
        user = context.user
        pushed_reference = context.pushed_reference
        request = _authorize_request(params)
        if user is None:
            return RedirectResponse(
                f"/login?next={quote(consent_url(request, pushed_reference))}",
                status_code=302,
            )
        return await _handle_consent(
            consent_usecase,
            authorize_usecase,
            client_repository,
            request,
            str(user.id),
            pushed_reference=pushed_reference,
            par_usecase=par_usecase,
            jarm_signer=jarm_signer,
            issuer=issuer,
        )

    @router.post(
        "/consent",
        response_class=HTMLResponse,
        response_model=None,
        summary="Autorise ou refuse la demande d'autorisation",
        responses={400: {"description": "redirect_uri requis"}},
    )
    async def consent_decision(
        context: Annotated[_ConsentContext, Depends(_consent_context)],
        form: Annotated[_ConsentFormParams, Form()],
    ) -> RedirectResponse | HTMLResponse:
        user = context.user
        pushed_reference = context.pushed_reference
        request = _authorize_request(form)
        if user is None:
            return RedirectResponse(
                f"/login?next={quote(consent_url(request, pushed_reference))}",
                status_code=302,
            )
        if not request.redirect_uri:
            raise HTTPException(status_code=400, detail="redirect_uri requis")
        validated = await validate_authorization_request(request, client_repository)
        if isinstance(validated, AuthorizeError):
            return await error_response(validated, jarm_signer, issuer=issuer)
        if form.action == "deny":
            return await error_response(
                AuthorizeError(
                    error="access_denied",
                    error_description="L'utilisateur a refusé l'accès",
                    redirect_uri=request.redirect_uri,
                    state=request.state,
                    response_mode=validated.response_mode,
                    client_id=request.client_id,
                ),
                jarm_signer,
                issuer=issuer,
            )
        await consent_usecase.grant(
            str(user.id),
            request.client_id,
            _requested_scopes(request),
            request.authorization_details,
        )
        return await _execution_redirect(
            authorize_usecase,
            AuthorizeRequest(
                response_type=request.response_type,
                client_id=request.client_id,
                redirect_uri=request.redirect_uri,
                scope=request.scope,
                subject=str(user.id),
                state=request.state,
                nonce=request.nonce,
                code_challenge=request.code_challenge,
                code_challenge_method=request.code_challenge_method,
                response_mode=request.response_mode,
                acr_values=request.acr_values,
                claims=request.claims,
                dpop_jkt=request.dpop_jkt,
                authorization_details=request.authorization_details,
            ),
            par_usecase=par_usecase,
            pushed_reference=pushed_reference,
            jarm_signer=jarm_signer,
            issuer=issuer,
        )

    return router


async def _handle_consent(
    consent_usecase: ConsentUseCase,
    authorize_usecase: AuthorizeUseCase,
    client_repository: ClientReader,
    request: AuthorizeRequest,
    subject: str,
    *,
    pushed_reference: str = "",
    par_usecase: PushedAuthorizationUseCase | None = None,
    jarm_signer: JarmSigner | None = None,
    issuer: str = "",
) -> RedirectResponse | HTMLResponse | str:
    """Affiche la page ou court-circuite quand le consentement est déjà couvert.

    Réutilisée par ``GET /consent`` : la demande est re-validée (URIs et
    scopes), puis soit le consentement manquant est affiché, soit
    ``/authorize`` est exécuté directement — le consentement étant déjà
    actif, point de nouvel aller-retour par la page. ``prompt=consent``
    (OIDC Core 1.0 §3.1.2.1) conserve l'écran forcé par ``/authorize``
    même quand le consentement stocké couvre la demande (la page est
    rendue, jamais court-circuitée). ``pushed_reference``
    accompagne la page et l'exécution pour consommer la demande poussée
    à l'émission du code (PAR) ; ``jarm_signer`` signe les erreurs de
    re-validation redirigeables (JARM Final 1.0 §3), ``issuer`` porte le
    ``iss`` des erreurs ``form_post`` (RFC 9207 §2).
    """
    if not request.redirect_uri:
        raise HTTPException(status_code=400, detail="redirect_uri requis")
    validated = await validate_authorization_request(request, client_repository)
    if isinstance(validated, AuthorizeError):
        return await error_response(validated, jarm_signer, issuer=issuer)
    request = AuthorizeRequest(
        response_type=request.response_type,
        client_id=request.client_id,
        redirect_uri=request.redirect_uri,
        scope=request.scope,
        subject=subject,
        state=request.state,
        nonce=request.nonce,
        code_challenge=request.code_challenge,
        code_challenge_method=request.code_challenge_method,
        response_mode=request.response_mode,
        prompt=request.prompt,
        acr_values=request.acr_values,
        claims=request.claims,
        dpop_jkt=request.dpop_jkt,
        authorization_details=request.authorization_details,
    )
    forced = "consent" in request.prompt.split()
    if not await consent_usecase.is_required(
        validated.client,
        subject,
        _requested_scopes(request),
        request.authorization_details,
        force=forced,
    ):
        return await _execution_redirect(
            authorize_usecase,
            request,
            par_usecase=par_usecase,
            pushed_reference=pushed_reference,
            jarm_signer=jarm_signer,
            issuer=issuer,
        )
    return _render_page(request, pushed_reference)


def _requested_scopes(request: AuthorizeRequest) -> frozenset[Scope]:
    """Scopes demandés par le client (ordre canonique par valeur)."""
    return Scope.from_space_separated(request.scope)


def _render_page(request: AuthorizeRequest, pushed_reference: str = "") -> str:
    """Rend l'écran de consentement (client, scopes et destination)."""
    label = html.escape(request.client_id)
    scopes = [
        f"<li>{html.escape(_SCOPE_LABELS.get(scope, scope.value))} "
        f"<code>{html.escape(scope.value)}</code></li>"
        for scope in sorted(_requested_scopes(request), key=lambda s: s.value)
    ]
    hidden = "\n".join(
        f'<input type="hidden" name="{name}" value="{html.escape(value)}">'
        for name, value in _consent_params(request, pushed_reference).items()
    )
    redirect_host = urlsplit(request.redirect_uri).netloc
    return _PAGE_TEMPLATE.format(
        client_id=label,
        scope_list="une liste de droits" if scopes else "aucun droit",
        scopes="".join(scopes) or "<li>Aucun scope demandé</li>",
        redirect_uri=html.escape(redirect_host),
        logout_url=f"/logout?next={quote(request.client_id, safe='')}",
        hidden=hidden,
    )


async def _execution_redirect(
    usecase: AuthorizeUseCase,
    request: AuthorizeRequest,
    *,
    par_usecase: PushedAuthorizationUseCase | None = None,
    pushed_reference: str = "",
    jarm_signer: JarmSigner | None = None,
    issuer: str = "",
) -> RedirectResponse | HTMLResponse:
    """Exécute la demande d'autorisation et redirige vers ``redirect_uri``.

    Sur émission réussie (code ou jetons), consomme la ``pushed_reference``
    (PAR) : la même référence ne peut plus être rejouée après l'approbation
    du consentement — invariant de ``_success_redirect`` de ``/authorize``.
    Une erreur d'exécution redirigeable suit ``response_mode`` (signée JARM
    pour un client signable via ``jarm_signer``, ``POST`` auto-soumis pour
    ``form_post`` avec ``iss`` via ``issuer`` — RFC 9207 §2). Le succès
    ``form_post`` rend la page auto-soumise de la même famille
    (Form Post Response Mode 1.0 §2).
    """
    result = await usecase.execute(request)
    if isinstance(result, AuthorizeError):
        return await error_response(result, jarm_signer, issuer=issuer)
    if par_usecase is not None and pushed_reference:
        await par_usecase.complete(pushed_reference)
    return authorization_response(result)
