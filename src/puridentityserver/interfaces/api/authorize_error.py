"""Réponses d'erreur de l'endpoint d'autorisation (RFC 6749 §4.1.2.1).

Deux formats coexistent selon que l'erreur est **redirigeable** ou non :

- ``error_redirect`` : la redirection vers ``redirect_uri`` portant ``error``
  (query pour le code flow, fragment dès qu'un jeton est retourné,
  RFC 6749 §4.2.2.1) ;
- ``error_page`` : une page HTML d'erreur affichée dans le navigateur de
  l'utilisateur, exigée dès que la ``redirect_uri`` n'est pas de confiance
  (non enregistrée) ou que le ``client_id`` est invalide — la RFC 6749
  §4.1.2.1 interdit alors de rediriger ; c'est cette page que la suite de
  certification attend (module ``oidcc-ensure-registered-redirect-uri``).

``error_response`` applique l'un ou l'autre à partir du marqueur
``redirectable`` du ``AuthorizeError``.
"""

from __future__ import annotations

import html
from urllib.parse import quote

from fastapi.responses import HTMLResponse, RedirectResponse

from puridentityserver.application.authorize import AuthorizeError
from puridentityserver.domain.authorization import ResponseMode
from puridentityserver.interfaces.api.error_description import ascii_error_description

_DEFAULT_DESCRIPTIONS = {
    "invalid_redirect_uri": "La redirection demandée n'est pas enregistrée",
    "invalid_client": "Identifiant de client invalide ou inconnu",
}


def error_redirect(result: AuthorizeError) -> RedirectResponse:
    """Construit le redirect d'erreur vers ``redirect_uri``.

    Les erreurs des flows retournant des jetons (implicit/hybrid) sont
    placées dans le fragment de l'URL (RFC 6749 §4.2.2.1), les autres dans
    la query string (RFC 6749 §4.1.2.1).
    """
    parts = [f"error={result.error}"]
    if result.error_description:
        description = quote(ascii_error_description(result.error_description), safe="")
        parts.append(f"error_description={description}")
    if result.state:
        parts.append(f"state={result.state}")
    params = "&".join(parts)
    separator = "#" if result.response_mode is ResponseMode.FRAGMENT else "?"
    location = f"{result.redirect_uri}{separator}{params}"
    return RedirectResponse(location, status_code=302)


def error_page(result: AuthorizeError) -> HTMLResponse:
    """Page HTML d'erreur (HTTP 400) à afficher au lieu d'une redirection.

    Le code d'erreur OAuth y figure en clair pour que l'utilisateur (et la
    suite de certification, qui capture la page) puisse lire le motif du
    refus.
    """
    description = result.error_description or _DEFAULT_DESCRIPTIONS.get(
        result.error, "La demande d'autorisation a été refusée."
    )
    return HTMLResponse(
        status_code=400,
        content=(
            '<!doctype html><html lang="fr"><head>'
            '<meta charset="utf-8"><title>Erreur de la demande '
            "</title><style>body{font-family:"
            "sans-serif;margin:2rem;max-width:28rem}h1{font-size:"
            "1.3rem}.hint{color:#666;font-size:0.9rem}code{font-size:0.95rem}</style>"
            "</head><body><h1>Requête d'autorisation invalide</h1>"
            f'<p class="hint"><code>{html.escape(result.error)}</code> — '
            + html.escape(ascii_error_description(description))
            + ". La redirection vers l'URI fournie est interdite : elle n'est "
            "pas enregistrée pour ce client ou le client est inconnu "
            "(RFC 6749 §4.1.2.1).</p>"
            "</body></html>"
        ),
    )


def error_response(result: AuthorizeError) -> RedirectResponse | HTMLResponse:
    """Redirige vers ``redirect_uri`` si l'erreur l'autorise, sinon page d'erreur."""
    if not result.redirectable:
        return error_page(result)
    return error_redirect(result)
