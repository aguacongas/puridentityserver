r"""Capture les pages de relecture de l'OP pour la certification (issue #90).

La suite officielle attend une capture d'écran pour 4 modules Core
(``oidcc-response-type-missing``, ``oidcc-ensure-registered-redirect-uri``,
``oidcc-max-age-1``, ``oidcc-prompt-login``) : sans elle le module reste en
``WAITING`` jusqu'au timeout. En mode witness, ``conformance-screenshots.patch``
remplit les placeholders avec un PNG 1x1 de secours — le verdict ``REVIEW``
tombe juste, mais la preuve est un artifice.

Ce script rejoue les 4 scénarios contre l'OP réellement déployé avec un
navigateur headless (Playwright/chromium) et produit, pour chaque module,
une capture authentique de la page servie par l'OP :

1. ``response_type`` absent → page d'erreur HTTP 400 (``<code>`` du motif) ;
2. ``redirect_uri`` non enregistrée (query ajoutée) → page d'erreur HTTP 400 ;
3. ``prompt=login`` → second formulaire de connexion (après un flux complet) ;
4. ``max_age=1`` → idem, une seconde plus tard.

Chaque capture est validée (statut, marqueurs de la page) avant export : un
échec sort avec un code non nul et la certification retombe sur le PNG de
secours, elle ne s'arrête jamais.

Usage (depuis la racine du dépôt, dans la certification CI) :

    python3 certification/capture_screenshots.py \
        --base-url https://puridentityserver-certification.onrender.com

Les fichiers produits sont ``<out>/<testName>.png`` ; ``fill_required_screenshots``
du driver les lit ensuite via la variable ``SCREENSHOTS_DIR``.
"""

from __future__ import annotations

import argparse
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

from playwright.sync_api import (
    APIRequestContext,
    Error,
    Page,
    Playwright,
    Response,
    sync_playwright,
)
from playwright.sync_api import (
    TimeoutError as PlaywrightTimeoutError,
)

_LOGGER = logging.getLogger("capture_screenshots")

# Marqueurs ASCII des pages de l'OP (évite toute dépendance à l'encodage).
_LOGIN_TITLE = "PurIdentityServer — connexion"
_CONSENT_FORM = 'form[action="/consent"]'
_LOGIN_FORM = 'form[action="/login"]'
# Délais d'attente des marqueurs (une fois la page chargée, ils sont présents).
_MARKER_TIMEOUT_MS = 5_000
# L'instance de certification ne seed aucun client : on s'enregistre nous-mêmes
# (RFC 7591 ouvert sur cette instance de démonstration, voir config.render.toml).
_REDIRECT_URI = "https://rp.example.invalid/callback"
# L'hôte est irrésolvable au choix (RFC 2606, domaine ``.invalid``) : le
# callback final ne dépend d'aucun réseau externe, la capture ne porte jamais
# sur lui.
_CLIENT_NAME = "certification-captures"
# Limite de l'ImageAPI de la suite : data URI <= 500 Ko.
_MAX_IMAGE_BYTES = 500 * 1024


@dataclass
class RegisteredClient:
    """Client enregistré dynamiquement le temps des captures."""

    client_id: str
    registration_access_token: str = ""


def _authorize_url(
    base_url: str, client_id: str, *, extra: dict[str, str | None] | None = None
) -> str:
    """Construit l'URL ``/authorize`` d'une demande ``code`` (PKCE absent).

    Une valeur ``None`` de ``extra`` supprime le paramètre (cas du
    ``response_type`` absent exigé par ``oidcc-response-type-missing``).
    """
    params: dict[str, str | None] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": _REDIRECT_URI,
        "scope": "openid profile",
        "state": "capture-state",
        "nonce": "capture-nonce",
    }
    params.update(extra or {})
    return f"{base_url.rstrip('/')}/authorize?{urlencode({k: v for k, v in params.items() if v})}"


def _register_client(request: APIRequestContext, base_url: str) -> RegisteredClient:
    """Enregistre le client de capture via ``POST /register`` (RFC 7591)."""
    response = request.post(
        f"{base_url.rstrip('/')}/register",
        data={
            "client_name": _CLIENT_NAME,
            "redirect_uris": [_REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "openid profile",
        },
    )
    if response.status != 201:
        raise RuntimeError(
            f"POST /register a répondu HTTP {response.status} : {response.text()[:300]}"
        )
    payload = response.json()
    client_id = str(payload.get("client_id", ""))
    if not client_id:
        raise RuntimeError(f"client_id absent de la réponse de registration : {payload}")
    return RegisteredClient(
        client_id=client_id,
        registration_access_token=str(payload.get("registration_access_token", "")),
    )


def _unregister_client(request: APIRequestContext, base_url: str, client: RegisteredClient) -> None:
    """Supprime le client de capture (RFC 7592), sans jamais faire échouer le run."""
    if not client.registration_access_token:
        return
    try:
        response = request.delete(
            f"{base_url.rstrip('/')}/register/{client.client_id}",
            headers={"Authorization": f"Bearer {client.registration_access_token}"},
        )
    except Exception as error:
        _LOGGER.warning("Suppression du client de capture impossible : %s", error)
        return
    if response.status not in (204, 404):
        _LOGGER.warning("DELETE /register/%s : HTTP %s", client.client_id, response.status)


def _attached(page: Page, selector: str) -> bool:
    """Attend l'apparition du marqueur ``selector`` ; vrai s'il est présent."""
    try:
        page.wait_for_selector(selector, state="attached", timeout=_MARKER_TIMEOUT_MS)
    except PlaywrightTimeoutError:
        return False
    return True


def _login_if_needed(page: Page, username: str, password: str) -> None:
    """Soumet le formulaire de connexion s'il est présenté par l'OP."""
    if not _attached(page, _LOGIN_FORM):
        return
    page.fill('input[name="username"]', username)
    page.fill('input[name="password"]', password)
    with page.expect_navigation(wait_until="load"):
        page.click(f'{_LOGIN_FORM} button[type="submit"]')


def _accept_consent_if_needed(page: Page) -> None:
    """Accepte le consentement s'il est présenté (``action=authorize``)."""
    if not _attached(page, _CONSENT_FORM):
        return
    with page.expect_navigation(wait_until="load"):
        page.click('button[name="action"][value="authorize"]')


def _goto(page: Page, url: str) -> Response | None:
    """Navigue vers ``url``, en tolérant la reprise après une page d'erreur.

    Un callback ``.invalid`` non résoluble laisse le navigateur sur
    ``chrome-error://`` : la navigation suivante peut être déclarée
    « interrompue » par cet en-cours, auquel cas elle est relancée une fois.
    """
    try:
        return page.goto(url, wait_until="load")
    except Error as error:
        if "interrupted by another navigation" not in str(error):
            raise
    page.wait_for_timeout(250)
    return page.goto(url, wait_until="load")


def _run_flow(page: Page, url: str, username: str, password: str) -> None:
    """Ouvre ``url`` puis enchaîne connexion et consentement si présent.

    Le callback est hébergé sur un domaine ``.invalid`` (RFC 2606) : quand le
    flux aboutit, la navigation finale échoue au DNS. Seule cette erreur est
    absorbée — tout autre plantage (OP hors service, page inattendue) est
    propagé.
    """
    try:
        _goto(page, url)
        _login_if_needed(page, username, password)
        _accept_consent_if_needed(page)
    except Error as error:
        if "ERR_NAME_NOT_RESOLVED" not in str(error):
            raise


def _assert_status(page: Page, url: str, expected: int) -> None:
    """Contrôle le statut HTTP de la page affichée (la navigation peut échouer)."""
    response = _goto(page, url)
    if response is None:
        raise RuntimeError(f"aucune réponse pour {url}")
    if response.status != expected:
        raise RuntimeError(
            f"HTTP {response.status} inattendu pour {url} (attendu {expected}) : "
            f"{page.content()[:200]}"
        )


def _capture_error_page(page: Page, url: str, error_code: str, path: Path) -> None:
    """Capture la page d'erreur HTTP 400 portant le ``<code>`` du motif."""
    _assert_status(page, url, 400)
    if f"<code>{error_code}</code>" not in page.content():
        raise RuntimeError(f"motif {error_code!r} absent de la page d'erreur {url}")
    _screenshot(page, path)


def _capture_error_after_flow(
    page: Page,
    url: str,
    error_code: str,
    username: str,
    password: str,
    path: Path,
) -> None:
    """Capture l'erreur servie **après** login/consentement, sans redirection.

    ``redirect_uri`` non enregistrée : l'OP doit afficher l'erreur au lieu de
    rediriger (RFC 6749 §4.1.2.1), ce que la vérification de l'URL finale
    garantit — la session est indispensable car le login précède cette
    vérification.
    """
    _run_flow(page, url, username, password)
    if not page.url.startswith(url.split("?", 1)[0]):
        raise RuntimeError(f"l'OP a redirigé au lieu d'afficher l'erreur : {page.url}")
    if f"<code>{error_code}</code>" not in page.content():
        raise RuntimeError(f"motif {error_code!r} absent de la page d'erreur {page.url}")
    _screenshot(page, path)


def _capture_login_page(page: Page, url: str, path: Path) -> None:
    """Capture le formulaire de connexion présenté par le second ``/authorize``."""
    _goto(page, url)
    if not _attached(page, _LOGIN_FORM):
        raise RuntimeError(
            f"aucun formulaire de connexion sur {url} "
            f"(titre : {page.title()!r}, URL : {page.url!r})"
        )
    if page.title() != _LOGIN_TITLE:
        raise RuntimeError(f"titre de connexion inattendu : {page.title()!r}")
    _screenshot(page, path)


def _capture_second_login(
    page: Page,
    base_url: str,
    client_id: str,
    username: str,
    password: str,
    extra: dict[str, str],
    path: Path,
) -> None:
    """Flux complet puis second ``/authorize`` : capture le second appel de login."""
    _run_flow(page, _authorize_url(base_url, client_id), username, password)
    if "max_age" in extra:
        # max_age=1 exige un auth_time plus ancienne d'au moins une seconde.
        time.sleep(1.2)
    _capture_login_page(page, _authorize_url(base_url, client_id, extra=extra), path)


def _screenshot(page: Page, path: Path) -> None:
    """Exporte la page et contrôle la limite de 500 Ko de l'ImageAPI."""
    page.screenshot(path=str(path), full_page=True)
    size = path.stat().st_size
    if size > _MAX_IMAGE_BYTES:
        raise RuntimeError(f"capture trop lourde pour l'ImageAPI : {path} fait {size} octets")
    _LOGGER.info("Capture %s (%d octets)", path, size)


def capture_all(
    playwright: Playwright,
    base_url: str,
    out: Path,
    username: str,
    password: str,
) -> list[Path]:
    """Rejoue les 4 scénarios et écrit les PNG nommés ``<testName>.png``."""
    out.mkdir(parents=True, exist_ok=True)
    browser = playwright.chromium.launch()
    try:
        context = browser.new_context(viewport={"width": 1024, "height": 768})
        client = _register_client(context.request, base_url)
        try:
            page = context.new_page()
            # `response_type` absent : la validation des paramètres précède le
            # login, la page d'erreur tombe même sur session vierge.
            _capture_error_page(
                page,
                _authorize_url(base_url, client.client_id, extra={"response_type": None}),
                "response_type",
                out / "oidcc-response-type-missing.png",
            )
            # Établissement de la session : `redirect_uri`, `prompt` et
            # `max_age` ne sont arbitrés qu'après login/consentement.
            _run_flow(page, _authorize_url(base_url, client.client_id), username, password)
            _capture_error_after_flow(
                page,
                _authorize_url(
                    base_url,
                    client.client_id,
                    extra={"redirect_uri": f"{_REDIRECT_URI}?unregistered=1"},
                ),
                "invalid_redirect_uri",
                username,
                password,
                out / "oidcc-ensure-registered-redirect-uri.png",
            )
            _capture_second_login(
                page,
                base_url,
                client.client_id,
                username,
                password,
                {"prompt": "login"},
                out / "oidcc-prompt-login.png",
            )
            _capture_second_login(
                page,
                base_url,
                client.client_id,
                username,
                password,
                {"max_age": "1"},
                out / "oidcc-max-age-1.png",
            )
        finally:
            _unregister_client(context.request, base_url, client)
    finally:
        browser.close()
    return sorted(out.glob("*.png"))


def main(argv: list[str] | None = None) -> int:
    """Capture les pages ; renvoie 0 si les 4 fichiers sont produits."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="https://puridentityserver-certification.onrender.com",
        help="URL publique de l'OP (défaut : instance de certification Render)",
    )
    parser.add_argument("--out", default="screenshots", help="répertoire des PNG")
    parser.add_argument("--username", default="alice@example.com", help="compte de connexion")
    parser.add_argument("--password", default="password", help="mot de passe du compte")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    out = Path(args.out)
    expected = {
        "oidcc-response-type-missing.png",
        "oidcc-ensure-registered-redirect-uri.png",
        "oidcc-prompt-login.png",
        "oidcc-max-age-1.png",
    }
    try:
        with sync_playwright() as playwright:
            produced = capture_all(playwright, args.base_url, out, args.username, args.password)
    except Exception as error:
        _LOGGER.error("Capture impossible : %s", error)
        return 1
    missing = expected - {path.name for path in produced}
    if missing:
        _LOGGER.error("Captures manquantes : %s", ", ".join(sorted(missing)))
        return 1
    _LOGGER.info("%d captures écrites dans %s", len(produced), out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
