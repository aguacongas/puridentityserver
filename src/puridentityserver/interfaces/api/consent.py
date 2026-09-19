"""Page de consentement OAuth (OIDC Core 1.0 §3.1.2.2).

``/authorize`` redirige ici (via ``consent_url``) dès qu'un client
marqué ``require_consent`` demande des scopes non encore couverts par le
consentement mémorisé de l'utilisateur connecté. ``GET /consent``
affiche l'écran (client, scopes, destination) et ``POST /consent``
applique la décision :

- autoriser → ``ConsentUseCase.grant`` puis exécution directe
  d'``AuthorizeUseCase`` : l'utilisateur récupère le code / les jetons
  dans sa ``redirect_uri`` sans repasser par ``/authorize`` (indispensable
  pour PAR, dont le ``request_uri`` est à usage unique) ;
- refuser → redirection d'erreur ``access_denied`` vers ``redirect_uri``.

Utilisateur non connecté : redirection vers le formulaire de connexion
(``/login?next=<consent>``), le consentement étant lié au ``subject``.
"""

from __future__ import annotations

import html
from typing import Annotated
from urllib.parse import quote, urlencode, urlsplit

from fastapi import APIRouter, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse

from puridentityserver.application.authorize import (
    AuthorizeError,
    AuthorizeRequest,
    AuthorizeUseCase,
    validate_authorization_request,
)
from puridentityserver.application.consent import ConsentUseCase
from puridentityserver.domain.authorization import ResponseMode, Scope
from puridentityserver.identity.config import CurrentUserOptional
from puridentityserver.interfaces.repositories.client_repository import ClientRepository

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


def _consent_params(request: AuthorizeRequest) -> dict[str, str]:
    """Paramètres d'autorisation portés par l'URL de consentement.

    Les champs sont énumérés explicitement (jamais ``getattr``) afin de
    garder un typage strict et un ordre stable pour les champs cachés du
    formulaire. Côté PAR, la ``request_uri`` (usage unique) n'est pas
    retransmise : la page travaille sur les paramètres poussés.
    """
    return {
        "response_type": request.response_type,
        "client_id": request.client_id,
        "redirect_uri": request.redirect_uri,
        "scope": request.scope,
        "state": request.state,
        "nonce": request.nonce,
        "code_challenge": request.code_challenge,
        "code_challenge_method": request.code_challenge_method,
        "response_mode": request.response_mode,
    }


def consent_url(request: AuthorizeRequest) -> str:
    """URL de la page de consentement portant les paramètres d'autorisation."""
    return "/consent?" + urlencode(_consent_params(request))


def consent_router(
    consent_usecase: ConsentUseCase,
    authorize_usecase: AuthorizeUseCase,
    client_repository: ClientRepository,
) -> APIRouter:
    """Construit le routeur FastAPI exposant la page de consentement ``/consent``."""
    router = APIRouter(tags=["consent"])

    @router.get(
        "/consent",
        response_class=HTMLResponse,
        response_model=None,
        summary="Page de consentement OAuth",
        responses={400: {"description": "redirect_uri requis"}},
    )
    async def consent_prompt(
        response_type: Annotated[str, Query()] = "",
        client_id: Annotated[str, Query()] = "",
        redirect_uri: Annotated[str, Query()] = "",
        scope: Annotated[str, Query()] = "",
        state: Annotated[str, Query()] = "",
        nonce: Annotated[str, Query()] = "",
        code_challenge: Annotated[str, Query()] = "",
        code_challenge_method: Annotated[str, Query()] = "S256",
        response_mode: Annotated[str, Query()] = "",
        user: CurrentUserOptional = None,
    ) -> RedirectResponse | str:
        request = AuthorizeRequest(
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
        if user is None:
            return RedirectResponse(f"/login?next={quote(consent_url(request))}", status_code=302)
        return await _handle_consent(
            consent_usecase, authorize_usecase, client_repository, request, str(user.id)
        )

    @router.post(
        "/consent",
        response_class=HTMLResponse,
        response_model=None,
        summary="Autorise ou refuse la demande d'autorisation",
        responses={400: {"description": "redirect_uri requis"}},
    )
    async def consent_decision(
        response_type: Annotated[str, Form()],
        client_id: Annotated[str, Form()],
        scope: Annotated[str, Form()],
        redirect_uri: Annotated[str, Form()] = "",
        state: Annotated[str, Form()] = "",
        nonce: Annotated[str, Form()] = "",
        code_challenge: Annotated[str, Form()] = "",
        code_challenge_method: Annotated[str, Form()] = "S256",
        response_mode: Annotated[str, Form()] = "",
        action: Annotated[str, Form()] = "authorize",
        user: CurrentUserOptional = None,
    ) -> RedirectResponse:
        request = AuthorizeRequest(
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
        if user is None:
            return RedirectResponse(f"/login?next={quote(consent_url(request))}", status_code=302)
        if not redirect_uri:
            raise HTTPException(status_code=400, detail="redirect_uri requis")
        validated = await validate_authorization_request(request, client_repository)
        if isinstance(validated, AuthorizeError):
            return _error_redirect(validated)
        if action == "deny":
            return _error_redirect(
                AuthorizeError(
                    error="access_denied",
                    error_description="L'utilisateur a refusé l'accès",
                    redirect_uri=request.redirect_uri,
                    state=request.state,
                    response_mode=validated.response_mode,
                )
            )
        await consent_usecase.grant(str(user.id), request.client_id, _requested_scopes(request))
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
            ),
        )

    return router


async def _handle_consent(
    consent_usecase: ConsentUseCase,
    authorize_usecase: AuthorizeUseCase,
    client_repository: ClientRepository,
    request: AuthorizeRequest,
    subject: str,
) -> RedirectResponse | str:
    """Affiche la page ou court-circuite quand le consentement est déjà couvert.

    Réutilisée par ``GET /consent`` : la demande est re-validée (URIs et
    scopes), puis soit le consentement manquant est affiché, soit
    ``/authorize`` est exécuté directement — le consentement étant déjà
    actif, point de nouvel aller-retour par la page.
    """
    if not request.redirect_uri:
        raise HTTPException(status_code=400, detail="redirect_uri requis")
    validated = await validate_authorization_request(request, client_repository)
    if isinstance(validated, AuthorizeError):
        return _error_redirect(validated)
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
    )
    if not await consent_usecase.is_required(validated.client, subject, _requested_scopes(request)):
        return await _execution_redirect(authorize_usecase, request)
    return _render_page(request)


def _requested_scopes(request: AuthorizeRequest) -> frozenset[Scope]:
    """Scopes demandés par le client (ordre canonique par valeur)."""
    return Scope.from_space_separated(request.scope)


def _render_page(request: AuthorizeRequest) -> str:
    """Rend l'écran de consentement (client, scopes et destination)."""
    label = html.escape(request.client_id)
    scopes = [
        f"<li>{html.escape(_SCOPE_LABELS.get(scope, scope.value))} "
        f"<code>{html.escape(scope.value)}</code></li>"
        for scope in sorted(_requested_scopes(request), key=lambda s: s.value)
    ]
    hidden = "\n".join(
        f'<input type="hidden" name="{name}" value="{html.escape(value)}">'
        for name, value in _consent_params(request).items()
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
    usecase: AuthorizeUseCase, request: AuthorizeRequest
) -> RedirectResponse:
    """Exécute la demande d'autorisation et redirige vers ``redirect_uri``."""
    result = await usecase.execute(request)
    if isinstance(result, AuthorizeError):
        return _error_redirect(result)
    return RedirectResponse(result.redirect_uri, status_code=302)


def _error_redirect(result: AuthorizeError) -> RedirectResponse:
    """Construit le redirect d'erreur vers ``redirect_uri`` (RF 6749 §4.1.2.1).

    Les erreurs des flows retournant des jetons (implicit/hybrid) sont
    placées dans le fragment de l'URL, les autres dans la query string —
    même comportement que ``/authorize``.
    """
    parts = [f"error={result.error}"]
    if result.error_description:
        parts.append(f"error_description={quote(result.error_description, safe='')}")
    if result.state:
        parts.append(f"state={result.state}")
    params = "&".join(parts)
    separator = "#" if result.response_mode is ResponseMode.FRAGMENT else "?"
    return RedirectResponse(f"{result.redirect_uri}{separator}{params}", status_code=302)
