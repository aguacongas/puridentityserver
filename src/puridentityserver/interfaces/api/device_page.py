"""Page de vérification du Device Authorization Grant (RFC 8628 §3.2).

``GET /device`` affiche le formulaire de saisie du ``user_code`` (prérempli
si reçu via ``verification_uri_complete``). ``POST /device`` applique la
décision de l'utilisateur connecté (cookie de session, ``fastapi_users``) :
autoriser ou refuser l'appareil. Un utilisateur non connecté est redirigé
vers le formulaire de connexion avant de pouvoir valider.
"""

from __future__ import annotations

import html
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse

from puridentityserver.application.device_authorize import DeviceAuthorizationUseCase
from puridentityserver.identity.config import CurrentUserOptional

_PAGE_TEMPLATE = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>PurIdentityServer — autoriser l'appareil</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 24rem; }}
    label {{ display: block; margin: 0.6rem 0 0.2rem; }}
    input {{ width: 100%; padding: 0.4rem; box-sizing: border-box; }}
    button {{ margin-top: 1rem; padding: 0.5rem 1.2rem; margin-right: 0.5rem; }}
    .hint {{ color: #666; font-size: 0.9rem; }}
    .action {{ color: #b00020; }}
  </style>
</head>
<body>
  <h1>Autoriser cet appareil</h1>
  <p class="hint">Saisissez le code à 8 caractères affiché par votre
  appareil (ex. <code>WDJB-MJHT</code>).</p>
  {notice}<form method="post" action="/device">
    <label>Code de l'appareil
      <input name="user_code" value="{user_code}" required autofocus>
    </label>
    <button type="submit" name="action" value="authorize">Autoriser</button>
    <button type="submit" name="action" value="deny" class="action">Refuser</button>
  </form>
  <p class="hint">{login_hint}</p>
</body>
</html>
"""

_DECISION_TEMPLATE = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>PurIdentityServer — appareil</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; max-width: 24rem; }}
    .ok {{ color: #0a7d33; }}
    .ko {{ color: #b00020; }}
  </style>
</head>
<body>
  <h1 class="{css}">{title}</h1>
  <p>{message}</p>
  <p><a href="/device">Autoriser un autre appareil</a></p>
</body>
</html>
"""


def device_page_router(usecase: DeviceAuthorizationUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant la page de vérification ``/device``."""
    router = APIRouter(tags=["device-authorization"])

    @router.get(
        "/device",
        response_class=HTMLResponse,
        summary="Page de vérification de l'appareil",
    )
    async def device_prompt(
        user_code: Annotated[str, Query()] = "",
    ) -> str:
        escaped_code = html.escape(user_code)
        return _PAGE_TEMPLATE.format(
            user_code=escaped_code,
            notice="",
            login_hint="Vous devez être connecté pour autoriser l'appareil : "
            f'<a href="/login?next=/device?user_code={quote(escaped_code)}">se connecter</a>',
        )

    @router.post(
        "/device",
        response_class=HTMLResponse,
        response_model=None,
        summary="Autorise ou refuse l'appareil",
    )
    async def device_decision(
        user_code: Annotated[str, Form()],
        action: Annotated[str, Form()] = "authorize",
        user: CurrentUserOptional = None,
    ) -> RedirectResponse | str:
        if user is None:
            next_url = f"/device?user_code={quote(user_code)}"
            return RedirectResponse(f"/login?next={quote(next_url)}", status_code=302)
        if action == "deny":
            decision = await usecase.deny(user_code)
        else:
            decision = await usecase.approve(user_code, str(user.id))
        css = "ok" if decision.accepted else "ko"
        title = "Appareil " + ("autorisé" if decision.accepted else "non validé")
        return _DECISION_TEMPLATE.format(
            css=css, title=title, message=html.escape(decision.message)
        )

    return router
