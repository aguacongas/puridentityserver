"""Route FastAPI du RP-Initiated Logout (OIDC Core 1.0 §5.2).

Expose ``GET /end_session`` : le user agent est redirigé ici par le client
(``id_token_hint``, ``post_logout_redirect_uri``, ``state``) ; l'op purge
le cookie de session puis renvoie le navigateur vers l'URI de sortie
enregistrée, ou affiche une page de confirmation. Les clients ayant
enregistré une ``frontchannel_logout_uri`` sont chargés en iframe
(Front-Channel Logout 1.0) et ceux ayant enregistré une
``backchannel_logout_uri`` reçoivent un ``logout_token`` POST
(Back-Channel Logout 1.0).
"""

from __future__ import annotations

import html
from collections.abc import Sequence
from urllib.parse import quote

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from puridentityserver.application.logout import (
    LogoutError,
    LogoutRequest,
    LogoutUseCase,
)
from puridentityserver.identity.config import CurrentUserOptional, cookie_backend, session_sid

_END_SESSION_PAGE = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>PurIdentityServer — déconnexion</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 24rem; }}
    .ok {{ color: #116d8e; }}
    iframe.secret {{ display: none; }}
  </style>
  {redirect_meta}
</head>
<body>
  <h1>Vous êtes déconnecté</h1>
  <p class="ok">La session au serveur PurIdentityServer a été terminée.</p>
  <p>Les applications que vous utilisiez sont averties de la déconnexion.</p>
  <p><a href="{home}">Revenir à l'accueil</a></p>
  {iframes}
</body>
</html>
"""

_END_SESSION_ERROR_PAGE = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>PurIdentityServer — déconnexion</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 24rem; }}
    .error {{ color: #b00020; }}
  </style>
</head>
<body>
  <h1>Demande de déconnexion invalide</h1>
  <p class="error">{error}</p>
  <p><small>{description}</small></p>
  <p><a href="/">Accueil</a></p>
</body>
</html>
"""

_FRONT_CHANNEL_IFRAME = '<iframe class="secret" src="{uri}"></iframe>'
_FRONT_CHANNEL_REDIRECT_META = '<meta http-equiv="refresh" content="0.5; url={target}">'


def logout_router(usecase: LogoutUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``GET /end_session``."""
    router = APIRouter(tags=["logout"])

    @router.get(
        "/end_session",
        summary="RP-Initiated Logout (OIDC Core 1.0 §5.2)",
        response_model=None,
    )
    async def end_session(
        request: Request,
        id_token_hint: str = Query(default=""),
        post_logout_redirect_uri: str = Query(default=""),
        state: str = Query(default=""),
        user: CurrentUserOptional = None,
    ) -> RedirectResponse | HTMLResponse:
        """Termine la session de l'op et redirige vers l'URI de sortie du client.

        - ``id_token_hint`` : id_token courant de l'utilisateur (précédemment
          validé par ce client) ; s'il est présent et invalide, la demande
          est rejetée et la session n'est PAS terminée.
        - ``post_logout_redirect_uri`` : URI préréglée par le client ; toute
          valeur non enregistrée (ou client inconnu/inactif sans hint) est
          rejetée — pas de redirection vers l'extérieur.
        - ``state`` : renvoyé tel quel dans la redirection.
        - Front/back-channel : les clients concernés sont notifiés (iframes /
          ``logout_token``) une fois la session du ``sid`` courant terminée.
        """
        sid = await session_sid(request)
        result = await usecase.execute(
            LogoutRequest(
                id_token_hint=id_token_hint,
                post_logout_redirect_uri=post_logout_redirect_uri,
                state=state,
                session_id=sid,
            )
        )

        cleared_cookie = await _logout_cookie()
        if isinstance(result, LogoutError):
            return _error_page(result)

        subject = result.subject
        if not subject and user is not None:
            subject = str(user.id)
        await usecase.broadcast_backchannel_logout(subject=subject, session_id=sid)

        frontchannel = await usecase.frontchannel_uris(session_id=sid)
        target = result.post_logout_redirect_uri
        if target and result.state:
            target = f"{target}?state={quote(result.state, safe='')}"

        if target and not frontchannel:
            response: RedirectResponse | HTMLResponse = RedirectResponse(target, status_code=302)
        else:
            response = HTMLResponse(
                _logout_page(iframes=frontchannel, target=target), status_code=200
            )
        if cleared_cookie:
            response.headers["set-cookie"] = cleared_cookie
        return response

    return router


def _logout_page(*, iframes: Sequence[str], target: str) -> str:
    """Page de confirmation : notifications front-channel puis redirection.

    Les iframes (front-channel logout) sont chargés dans une zone non
    visible ; si une ``post_logout_redirect_uri`` validée existe, un
    ``<meta refresh>`` court renvoie ensuite le navigateur vers elle.
    """
    injected = "\n".join(
        _FRONT_CHANNEL_IFRAME.format(uri=html.escape(uri, quote=True)) for uri in iframes
    )
    redirect_meta = ""
    if target:
        redirect_meta = _FRONT_CHANNEL_REDIRECT_META.format(target=html.escape(target, quote=True))
    return _END_SESSION_PAGE.format(
        home=html.escape(target or "/"),
        redirect_meta=redirect_meta,
        iframes=injected,
    )


async def _logout_cookie() -> str:
    """Construit le ``Set-Cookie`` qui efface la session (idempotent, sans session requise)."""
    cleared = await cookie_backend.transport.get_logout_response()
    return cleared.headers.get("set-cookie", "")


def _error_page(error: LogoutError) -> HTMLResponse:
    """Page d'erreur HTML (400) pour une demande de logout rejetée."""
    return HTMLResponse(
        _END_SESSION_ERROR_PAGE.format(
            error=html.escape(error.error_description or error.error),
            description=html.escape(error.error),
        ),
        status_code=400,
    )
