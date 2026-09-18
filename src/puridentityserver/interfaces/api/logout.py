"""Route FastAPI du RP-Initiated Logout (OIDC Core 1.0 §5.2).

Expose ``GET /end_session`` : le user agent est redirigé ici par le client
(``id_token_hint``, ``post_logout_redirect_uri``, ``state``) ; l'op purge
le cookie de session puis renvoie le navigateur vers l'URI de sortie
enregistrée, ou affiche une page de confirmation.
"""

from __future__ import annotations

import html
from urllib.parse import quote

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, RedirectResponse

from puridentityserver.application.logout import (
    LogoutError,
    LogoutRequest,
    LogoutUseCase,
)
from puridentityserver.identity.config import cookie_backend

_END_SESSION_PAGE = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>PurIdentityServer — déconnexion</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 24rem; }}
    .ok {{ color: #116d8e; }}
  </style>
</head>
<body>
  <h1>Vous êtes déconnecté</h1>
  <p class="ok">La session au serveur PurIdentityServer a été terminée.</p>
  <p><a href="/login">Se reconnecter</a></p>
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


def logout_router(usecase: LogoutUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant ``GET /end_session``."""
    router = APIRouter(tags=["logout"])

    @router.get(
        "/end_session",
        summary="RP-Initiated Logout (OIDC Core 1.0 §5.2)",
        response_model=None,
    )
    async def end_session(
        id_token_hint: str = Query(default=""),
        post_logout_redirect_uri: str = Query(default=""),
        state: str = Query(default=""),
    ) -> RedirectResponse | HTMLResponse:
        """Termine la session de l'op et redirige vers l'URI de sortie du client.

        - ``id_token_hint`` : id_token courant de l'utilisateur (précédemment
          validé par ce client) ; s'il est présent et invalide, la demande
          est rejetée et la session n'est PAS terminée.
        - ``post_logout_redirect_uri`` : URI préréglée par le client ; toute
          valeur non enregistrée (ou client inconnu/inactif sans hint) est
          rejetée — pas de redirection vers l'extérieur.
        - ``state`` : renvoyé tel quel dans la redirection.
        """
        result = await usecase.execute(
            LogoutRequest(
                id_token_hint=id_token_hint,
                post_logout_redirect_uri=post_logout_redirect_uri,
                state=state,
            )
        )

        cleared_cookie = await _logout_cookie()
        if isinstance(result, LogoutError):
            return _error_page(result)

        if result.post_logout_redirect_uri:
            location = result.post_logout_redirect_uri
            if result.state:
                location = f"{location}?state={quote(result.state, safe='')}"
            response: RedirectResponse | HTMLResponse = RedirectResponse(location, status_code=302)
        else:
            response = HTMLResponse(_END_SESSION_PAGE, status_code=200)
        if cleared_cookie:
            response.headers["set-cookie"] = cleared_cookie
        return response

    return router


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
