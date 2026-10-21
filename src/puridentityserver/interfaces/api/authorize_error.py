"""Réponses d'erreur de l'endpoint d'autorisation (RFC 6749 §4.1.2.1).

Deux formats coexistent selon que l'erreur est **redirigeable** ou non :

- ``error_redirect`` : la redirection vers ``redirect_uri`` portant ``error``
  (query pour le code flow, fragment dès qu'un jeton est retourné,
  RFC 6749 §4.2.2.1) — en ``response_mode=jwt``, l'erreur est au contraire
  signée dans l'enveloppe JARM portée par ``response`` (JARM Final 1.0 §3) ;
  en ``response_mode=form_post``, elle part dans le ``POST`` auto-soumis
  vers la ``redirect_uri`` avec ``iss`` (Form Post Response Mode 1.0 §2,
  RFC 9207 §2) ; les transports clairs ``query``/``fragment`` portent
  également ``iss`` (RFC 9207 §2 : « including error responses ») ;
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
from puridentityserver.application.jarm import JarmSigner
from puridentityserver.domain.authorization import ResponseMode
from puridentityserver.interfaces.api.error_description import ascii_error_description
from puridentityserver.interfaces.api.form_post import form_post_page

_DEFAULT_DESCRIPTIONS = {
    "invalid_redirect_uri": "La redirection demandée n'est pas enregistrée",
    "invalid_client": "Identifiant de client invalide ou inconnu",
}


def _jarm_error_params(result: AuthorizeError) -> dict[str, str]:
    """Paramètres d'erreur placés en claims de l'enveloppe JARM (valeurs brutes).

    Contrairement à l'encodage ``query``/``fragment``, les valeurs ne sont
    pas percentées : le JWT les porte en JSON (JARM Final 1.0 §3).
    """
    params = {"error": result.error}
    if result.error_description:
        params["error_description"] = ascii_error_description(result.error_description)
    if result.state:
        params["state"] = result.state
    return params


def _form_post_error_params(result: AuthorizeError, issuer: str) -> dict[str, str]:
    """Paramètres d'erreur soumis en ``POST`` (Form Post §2 + RFC 9207 §2).

    Valeurs brutes comme dans l'enveloppe JARM — ni percent-encodage ni
    ``#`` : le corps ``x-www-form-urlencoded`` fait ce travail. ``iss``
    accompagne l'erreur (RFC 9207 §2, « including error responses »), comme
    dans les transports clairs ``query``/``fragment``.
    """
    params = {"error": result.error}
    if result.error_description:
        params["error_description"] = ascii_error_description(result.error_description)
    if result.state:
        params["state"] = result.state
    if issuer:
        params["iss"] = issuer
    return params


def _clear_error_params(result: AuthorizeError, issuer: str) -> str:
    """Paramètres d'erreur du transport clair (``query`` / ``fragment``).

    ``iss`` accompagne l'erreur (RFC 9207 §2 : « including error
    responses »), avec la même valeur et la même règle d'omission que la
    réponse de succès (aucun émetteur configuré : pas de paramètre).
    """
    parts = [f"error={result.error}"]
    if result.error_description:
        description = quote(ascii_error_description(result.error_description), safe="")
        parts.append(f"error_description={description}")
    if result.state:
        parts.append(f"state={result.state}")
    if issuer:
        parts.append(f"iss={issuer}")
    return "&".join(parts)


async def error_redirect(
    result: AuthorizeError, signer: JarmSigner | None = None, *, issuer: str = ""
) -> RedirectResponse | HTMLResponse:
    """Construit le redirect d'erreur vers ``redirect_uri``.

    Les erreurs des flows retournant des jetons (implicit/hybrid) sont
    placées dans le fragment de l'URL (RFC 6749 §4.2.2.1), les autres dans
    la query string (RFC 6749 §4.1.2.1). Une ``redirect_uri`` déjà
    porteuse d'une query impose ``&`` pour ne pas créer une seconde query
    string (``CheckMatchingCallbackParameters`` de la suite).

    En ``response_mode=jwt``, l'erreur est signée dans l'enveloppe JARM
    portée par ``?response=<jwt>`` (JARM Final 1.0 §3) ; sans signeur ou
    si le ``client_id`` n'est pas signable (inconnu, algorithme non
    déclaré), la redirection retombe sur le transport clair en query.

    En ``response_mode=form_post`` (Form Post Response Mode 1.0 §4),
    l'erreur redirigeable part dans le ``POST`` auto-soumis vers la
    ``redirect_uri`` — mêmes paramètres ``error`` / ``error_description``
    / ``state`` / ``iss`` que la réponse de succès. ``issuer`` porte la
    valeur ``iss`` publiée par discovery (RFC 9207 §2) : présente dans les
    trois transports (query, fragment, form_post), absente quand aucun
    émetteur n'est configuré.
    """
    if result.response_mode is ResponseMode.FORM_POST:
        return form_post_page(result.redirect_uri, _form_post_error_params(result, issuer))
    if result.response_mode is ResponseMode.JWT:
        envelope = (
            await signer.sign_by_client_id(result.client_id, _jarm_error_params(result))
            if signer is not None
            else None
        )
        if envelope:
            separator = "&" if "?" in result.redirect_uri else "?"
            return RedirectResponse(
                f"{result.redirect_uri}{separator}response={envelope}", status_code=302
            )
    params = _clear_error_params(result, issuer)
    if result.response_mode is ResponseMode.FRAGMENT:
        separator = "#"
    else:
        separator = "&" if "?" in result.redirect_uri else "?"
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


async def error_response(
    result: AuthorizeError, signer: JarmSigner | None = None, *, issuer: str = ""
) -> RedirectResponse | HTMLResponse:
    """Redirige vers ``redirect_uri`` si l'erreur l'autorise, sinon page d'erreur."""
    if not result.redirectable:
        return error_page(result)
    return await error_redirect(result, signer, issuer=issuer)
