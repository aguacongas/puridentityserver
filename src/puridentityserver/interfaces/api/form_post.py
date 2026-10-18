"""Transport des réponses d'autorisation en ``response_mode=form_post``.

Form Post Response Mode 1.0 (OIDF, Final 2015) : les paramètres de la
réponse sont encodés en champs d'un formulaire
``application/x-www-form-urlencoded`` soumis en ``POST`` vers la
``redirect_uri`` — ni l'historique du navigateur ni les logs serveur ne
captent le code ou les jetons (§4).
"""

from __future__ import annotations

import html
from collections.abc import Mapping

from fastapi.responses import HTMLResponse, RedirectResponse

from puridentityserver.application.authorize import AuthorizeRedirect
from puridentityserver.domain.authorization import ResponseMode


def form_post_page(redirect_uri: str, params: Mapping[str, str]) -> HTMLResponse:
    """Page 200 auto-soumise en ``POST`` vers ``redirect_uri`` (Form Post §2).

    L'``action`` du formulaire est la ``redirect_uri`` fournie — cible nue
    pour la réponse de succès, jamais enrichie de query : les paramètres
    voyagent dans le corps du ``POST``. L'auto-soumission s'appuie sur
    ``onload`` avec repli ``<noscript>`` : le client doit pouvoir traiter
    la réponse sans script (§2, « MUST be able to process the message
    without regard for the mechanism »). Les en-têtes
    ``Cache-Control: no-cache, no-store`` et ``Pragma: no-cache`` interdisent
    au user agent comme aux intermédiaires de conserver la réponse (§4,
    « MUST instruct the User Agent (and any intermediaries) not to store »).
    Les valeurs sont échappées ``html`` : le navigateur re-décodera les
    entités avant l'encodage ``x-www-form-urlencoded`` du corps.
    """
    inputs = "".join(
        '<input type="hidden" name="'
        + html.escape(name, quote=True)
        + '" value="'
        + html.escape(value, quote=True)
        + '">'
        for name, value in params.items()
    )
    return HTMLResponse(
        status_code=200,
        content=(
            '<!doctype html><html lang="fr"><head><meta charset="utf-8">'
            "<title>Réponse d'autorisation</title></head>"
            '<body onload="document.forms[0].submit()">'
            f'<form method="post" action="{html.escape(redirect_uri, quote=True)}">'
            f"{inputs}"
            '<noscript><button type="submit">Continuer</button></noscript>'
            "</form></body></html>"
        ),
        headers={"Cache-Control": "no-cache, no-store", "Pragma": "no-cache"},
    )


def authorization_response(result: AuthorizeRedirect) -> RedirectResponse | HTMLResponse:
    """Redirection 302 ou page auto-soumise selon le ``response_mode``.

    ``form_post`` (Form Post Response Mode 1.0 §2) rend la page de
    :func:`form_post_page` portant ``form_params`` ; les autres modes
    restent la redirection classique vers l'URL déjà encodée.
    """
    if result.response_mode is ResponseMode.FORM_POST:
        return form_post_page(result.redirect_uri, result.form_params)
    return RedirectResponse(result.redirect_uri, status_code=302)
