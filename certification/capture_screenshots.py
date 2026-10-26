r"""Capture les pages de relecture de l'OP pour la certification (issues #90, #138).

La suite officielle attend une capture d'écran pour 4 modules Core
(``oidcc-response-type-missing``, ``oidcc-ensure-registered-redirect-uri``,
``oidcc-max-age-1``, ``oidcc-prompt-login``), 2 modules FAPI1 servis en page
HTML, 6 modules propres au plan dynamic et 1 module fédéré : sans image, le
mode witness remplit ces placeholders avec un PNG 1x1 de secours — le verdict
tombe juste, mais la preuve est un artifice (issue #161).

Un screenshot n'est utile **que** pour prouver l'affichage d'une page d'erreur
quand l'OP ne renvoie pas l'erreur par redirection : les 14 autres modules
FAPI1 et les 4 modules FAPI2 reçoivent leur erreur par 302 vers leur callback
(issues #160/#178) et passent sans capture (retrait des 18 captures devenues
inutiles, issue #214).

Ce script rejoue les scénarios contre l'OP réellement déployé avec un
navigateur headless (Playwright/chromium) et produit, pour chaque module,
une capture authentique de la page servie par l'OP — 13 PNG au total :

1. les 4 scénarios Core (paramètre absent, ``redirect_uri`` non enregistrée,
   second ``prompt=login``, second ``max_age=1``) ;
2. les 6 scénarios propres au plan dynamic (issue #168) : ``redirect_uri``
   absente / supplémentaire / non concordante et pages de connexion des
   clients DCR porteurs d'un ``logo_uri``/``policy_uri``/``tos_uri`` ;
3. les 2 scénarios FAPI1 servis en page HTML (issue #214) : ``redirect_uri``
   non enregistrée et ``redirect_uri`` retirée du transport — le request
   object (JAR, ``by_value``) est signé avec la clé privée du client statique
   seedé par ``certification/config.render.toml`` (l'enregistrement
   dynamique ne crée pas de client ``fapi_enabled``) ;
4. le scénario fédéré ``invalid-client-id-in-request-object`` (issue #212) :
   client_id d'Entity Identifier inconnu → trust chain injoignable → page
   400 ``invalid_client`` (RFC 6749 §4.1.2.1), rejouée sans request object.

Chaque capture est validée (statut, marqueurs de la page) avant export : un
échec logue l'erreur et le scénario suivant est tenté ; si un fichier attendu
manque, le code de sortie non nul fait retomber la certification sur le PNG
de secours, elle ne s'arrête jamais.

Usage (depuis la racine du dépôt, dans la certification CI) :

    python3 certification/capture_screenshots.py \
        --base-url https://puridentityserver-certification.onrender.com

Harness local (certification-local.yml, OP derrière le nginx mTLS auto-signé) :

    python3 certification/capture_screenshots.py \
        --base-url https://localhost:9443 \
        --suite-url https://localhost.emobix.co.uk:8443

Dans les deux cas, le claim ``aud`` des jetons signés porte l'issuer lu dans
le discovery (``_resolve_issuer``), pas l'URL de navigation.

Les fichiers produits sont ``<out>/<testName>.png`` ; ``fill_required_screenshots``
du driver les lit ensuite via la variable ``SCREENSHOTS_DIR``.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import jwt as pyjwt
from jwt import PyJWK
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
# Clients statiques FAPI seedés (certification/config.render.toml en hébergé,
# config OP locale du harness) : leur request object (JAR) exige une
# ``redirect_uri`` enregistrée — celle du callback de la suite pour le plan
# correspondant. Le préfixe dépend de l'instance de suite : --suite-url
# (hébergée : certification.openid.net ; locale : localhost.emobix.co.uk).
_FAPI1_CALLBACK_PATH = "/test/a/puridentityserver-fapi1/callback"

#: Modules Core laissés en REVIEW par la suite (placeholders de capture).
_CORE_TEST_NAMES = (
    "oidcc-response-type-missing",
    "oidcc-ensure-registered-redirect-uri",
    "oidcc-prompt-login",
    "oidcc-max-age-1",
)

#: Modules du plan dynamic laissés en REVIEW (placeholders de capture) —
#: arbitrages de ``redirect_uri`` et présentation du client DCR au login.
_DYNAMIC_TEST_NAMES = (
    "oidcc-ensure-redirect-uri-in-authorization-request",
    "oidcc-redirect-uri-query-mismatch",
    "oidcc-redirect-uri-query-added",
    "oidcc-registration-logo-uri",
    "oidcc-registration-policy-uri",
    "oidcc-registration-tos-uri",
)

#: Modules FAPI1 du plan fapi1-advanced-final laissés en REVIEW et servis en
#: **page HTML** (RFC 6749 §4.1.2.1, issue #214) : la query du scénario ne
#: porte aucune ``redirect_uri`` enregistrée (retirée du transport, ou
#: déclarée dans le request object mais inconnue du OP), l'OP affiche donc
#: la page d'erreur au lieu de rediriger. Les 14 autres modules FAPI1
#: reçoivent l'erreur par redirection 302 vers leur callback (issues
#: #160/#178) et n'attendent plus de capture — un request object défectueux
#: par module.
_FAPI1_PAGE_SCENARIOS: tuple[tuple[str, str, str], ...] = (
    (
        "fapi1-advanced-final-ensure-redirect-uri-in-authorization-request",
        "no-redirect-uri",
        "invalid_request_object",
    ),
    (
        "fapi1-advanced-final-ensure-registered-redirect-uri",
        "unregistered-redirect-uri",
        "invalid_redirect_uri",
    ),
)

#: Module fédéré du plan federation laissé en REVIEW (issue #211) : le
#: ``client_id`` d'Entity Identifier du request object est invalide ; sans
#: trust chain résolue, l'OP refuse en page HTML 400 portant ``invalid_client``
#: (RFC 6749 §4.1.2.1) au lieu de rediriger — capture de cette page.
_FEDERATION_PAGE_TEST_NAME = (
    "openid-federation-automatic-client-registration-invalid-client-id-in-request-object"
)

#: Alias du RP fédéré de la suite (.../test/a/<alias>), dont le chemin
#: ``/INVALID`` est le client_id hors entité envoyé par le module.
_FEDERATION_SUITE_PATH = "/test/a/puridentityserver-federation"


@dataclass
class RegisteredClient:
    """Client enregistré dynamiquement le temps des captures."""

    client_id: str
    registration_access_token: str = ""


@dataclass
class PlanSigningClient:
    """Client FAPI statique seedé par la config de certification.

    ``private_key`` / ``kid`` viennent du JWKS committé dans le plan de
    certification (membres privés ``d``) : l'enregistrement dynamique ne
    crée pas de client ``fapi_enabled`` / ``fapi2_enabled``, ces seeds sont
    les seuls clients du profil signé côté OP.
    """

    client_id: str
    private_key: object
    kid: str
    redirect_uri: str


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


def _register_client(
    request: APIRequestContext,
    base_url: str,
    *,
    redirect_uris: list[str] | None = None,
    metadata: dict[str, str] | None = None,
) -> RegisteredClient:
    """Enregistre le client de capture via ``POST /register`` (RFC 7591).

    ``redirect_uris`` et ``metadata`` couvrent les variantes des scénarios
    dynamic (issue #168) : plusieurs redirections, requête avec query
    enregistrée, métadonnées ``logo_uri``/``policy_uri``/``tos_uri``.
    """
    data: dict[str, object] = {
        "client_name": _CLIENT_NAME,
        "redirect_uris": redirect_uris or [_REDIRECT_URI],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "openid profile",
    }
    data.update(metadata or {})
    response = request.post(
        f"{base_url.rstrip('/')}/register",
        data=data,
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


def _load_plan_signing_client(plan_path: Path, redirect_uri: str) -> PlanSigningClient:
    """Charge le client statique d'un plan de certification et sa clé privée.

    Le plan commetté porte le JWKS complet du client seed (membres privés
    ``d``) : ``PyJWK`` en déduit la clé de signature PS256 utilisée pour
    signer les request objects des scénarios.
    """
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    client = payload["client"]
    key_data = client["jwks"]["keys"][0]
    return PlanSigningClient(
        client_id=str(client["client_id"]),
        private_key=PyJWK.from_dict(key_data).key,
        kid=str(key_data.get("kid", "")),
        redirect_uri=redirect_uri,
    )


def _now() -> int:
    """Horloge Unix courante en secondes."""
    return int(time.time())


def _fapi1_claims(client: PlanSigningClient, issuer: str, mode: str) -> dict[str, object]:
    """Claims du request object FAPI1, ajustés pour le défaut du scénario.

    La base porte les claims exigés par FAPI1-ADV-5.2.2 (``iss``/``aud``/
    ``exp``/``nbf``/``scope``/``nonce``/``redirect_uri``) ; ``aud`` reçoit
    l'issuer OP du discovery, qui peut différer de l'URL de navigation
    (harness local : navigation sur ``localhost:9443``, issuer ``https://op:9443``)
    ; ``mode`` applique
    le défaut module (``redirect_uri`` retirée du transport ou déclarée
    inconnue). Les valeurs ``None`` retirent le claim du jeton.
    """
    now = _now()
    claims: dict[str, object | None] = {
        "iss": client.client_id,
        "aud": issuer.rstrip("/"),
        "exp": now + 300,
        "nbf": now - 60,
        "scope": "openid profile",
        "nonce": "capture-nonce",
        "redirect_uri": client.redirect_uri,
        "response_type": "code id_token",
        "client_id": client.client_id,
        "state": "capture-state",
    }
    overrides: dict[str, object | None] = {
        "no-redirect-uri": {"redirect_uri": None},
        "unregistered-redirect-uri": {"redirect_uri": "https://rp.example.invalid/not-registered"},
    }.get(mode, {})
    claims.update(overrides)
    return {name: value for name, value in claims.items() if value is not None}


def _sign(claims: dict[str, object], key: object, kid: str, algorithm: str = "PS256") -> str:
    """Signe un request object avec PyJWT (jamais de crypto maison)."""
    return str(pyjwt.encode(claims, key, algorithm=algorithm, headers={"kid": kid}))


def _fapi1_request_url(base_url: str, client: PlanSigningClient, claims: dict[str, object]) -> str:
    """URL ``/authorize`` du scénario FAPI1 (``request`` par valeur).

    Comme l'envoie la suite pour ses scénarios « page » (issue #214) : la
    query ne porte que ``client_id`` et le request object signé PS256 — sans
    ``redirect_uri`` ni ``response_type`` transportés, l'OP sert la page
    d'erreur HTTP 400 (RFC 6749 §4.1.2.1) au lieu de rediriger.
    """
    jar = _sign(claims, client.private_key, client.kid, "PS256")
    params = {"client_id": client.client_id, "request": jar}
    return f"{base_url.rstrip('/')}/authorize?{urlencode(params)}"


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


def _capture_missing_param_page(page: Page, url: str, param: str, path: Path) -> None:
    """Capture la page 400 « paramètres requis manquants » (aucun code de motif).

    L'AS sert un rappel de la RFC 6749 §3.1.1 listant le paramètre absent —
    sans ``<code>`` de motif exploitable — quand ``redirect_uri`` manque à
    une demande portant plusieurs redirections enregistrées.
    """
    _assert_status(page, url, 400)
    marker = f"manquants : {param}"
    if marker not in page.content():
        raise RuntimeError(f"marqueur {marker!r} absent de la page d'erreur {url}")
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


def _screenshot(page: Page, path: Path, *, full_page: bool = True) -> None:
    """Exporte la page et contrôle la limite de 500 Ko de l'ImageAPI.

    ``full_page=False`` : capture le viewport seul — indispensable pour la
    page ``log-detail`` de la suite (les logs FAPI2 débordent largement des
    500 Ko en page entière).
    """
    page.screenshot(path=str(path), full_page=full_page)
    size = path.stat().st_size
    if size > _MAX_IMAGE_BYTES:
        raise RuntimeError(f"capture trop lourde pour l'ImageAPI : {path} fait {size} octets")
    _LOGGER.info("Capture %s (%d octets)", path, size)


def _capture_core_scenarios(
    page: Page,
    context_request: APIRequestContext,
    base_url: str,
    out: Path,
    username: str,
    password: str,
) -> None:
    """Rejoue les 4 scénarios Core (client enregistré dynamiquement)."""
    client = _register_client(context_request, base_url)
    try:
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
        _unregister_client(context_request, base_url, client)


def _capture_federation_scenarios(page: Page, base_url: str, suite_base: str, out: Path) -> None:
    """Rejoue le module fédéré « client_id invalide dans le request object » (issue #211).

    La requête de la suite porte un ``client_id`` d'Entity Identifier invalide ;
    sans trust chain résolue, l'OP sert la page d'erreur HTTP 400 portant
    ``invalid_client`` (RFC 6749 §4.1.2.1) au lieu de rediriger. La requête
    rejouée ici n'emporte pas de request object — le job captures ne détient
    pas la clé privée du RP de la suite pour le signer — mais sans JAR le OP
    suit le même chemin de validation pour le même ``client_id`` (vérifié sur
    l'app de test). La ``redirect_uri`` est requise pour atteindre ce
    contrôle : sans elle, l'OP sert la page « paramètres requis manquants »
    (RFC 6749 §3.1.1) à la place.
    """
    client_id = f"{suite_base.rstrip('/')}{_FEDERATION_SUITE_PATH}/INVALID"
    url = _authorize_url(
        base_url,
        client_id,
        extra={"scope": "openid", "state": None, "nonce": None},
    )
    _capture_error_page(
        page,
        url,
        "invalid_client",
        out / f"{_FEDERATION_PAGE_TEST_NAME}.png",
    )


def _capture_dynamic_scenarios(
    page: Page,
    context_request: APIRequestContext,
    base_url: str,
    out: Path,
) -> None:
    """Rejoue les 6 scénarios REVIEW du plan dynamic (issue #168).

    Trois arbitrages de ``redirect_uri`` (absente, supplémentaire,
    non concordante) servis en page d'erreur HTTP 400 avant login, puis
    trois pages de connexion présentant un client DCR porteur d'un
    ``logo_uri``/``policy_uri``/``tos_uri`` (session vidée au préalable).
    """
    two_uris = _register_client(
        context_request,
        base_url,
        redirect_uris=[_REDIRECT_URI, "https://rp.example.invalid/callback-alt"],
    )
    plain_client = _register_client(context_request, base_url)
    queried = f"{_REDIRECT_URI}?registered=1"
    queried_client = _register_client(context_request, base_url, redirect_uris=[queried])
    try:
        # `redirect_uri` absente : deux redirections enregistrées, l'AS ne
        # peut pas déduire la cible et doit afficher l'erreur (RFC 6749
        # §3.1.2.3 / §4.1.2.1) au lieu de rediriger.
        _capture_missing_param_page(
            page,
            _authorize_url(base_url, two_uris.client_id, extra={"redirect_uri": None}),
            "redirect_uri",
            out / "oidcc-ensure-redirect-uri-in-authorization-request.png",
        )
        # `redirect_uri` portant une query alors que la version enregistrée
        # n'en porte pas.
        _capture_error_page(
            page,
            _authorize_url(
                base_url,
                plain_client.client_id,
                extra={"redirect_uri": f"{_REDIRECT_URI}?added=1"},
            ),
            "invalid_redirect_uri",
            out / "oidcc-redirect-uri-query-added.png",
        )
        # `redirect_uri` dont la query diffère de celle enregistrée.
        _capture_error_page(
            page,
            _authorize_url(
                base_url,
                queried_client.client_id,
                extra={"redirect_uri": f"{_REDIRECT_URI}?registered=2"},
            ),
            "invalid_redirect_uri",
            out / "oidcc-redirect-uri-query-mismatch.png",
        )
    finally:
        _unregister_client(context_request, base_url, two_uris)
        _unregister_client(context_request, base_url, plain_client)
        _unregister_client(context_request, base_url, queried_client)
    # Présentation du client DCR au login : session vidée, chaque
    # ``/authorize`` retombe sur le formulaire de connexion.
    for test_name, field, value in (
        ("oidcc-registration-logo-uri", "logo_uri", "https://example.org/logo.png"),
        ("oidcc-registration-policy-uri", "policy_uri", "https://example.org/policy.html"),
        ("oidcc-registration-tos-uri", "tos_uri", "https://example.org/tos.html"),
    ):
        client = _register_client(context_request, base_url, metadata={field: value})
        try:
            page.context.clear_cookies()
            _capture_login_page(
                page,
                _authorize_url(base_url, client.client_id),
                out / f"{test_name}.png",
            )
        finally:
            _unregister_client(context_request, base_url, client)


def _capture_fapi1_scenarios(
    page: Page,
    base_url: str,
    issuer: str,
    plans_dir: Path,
    out: Path,
    redirect_uri: str,
) -> None:
    """Rejoue les 2 scénarios FAPI1 servis en page HTML (issue #214).

    Un request object (JAR, ``by_value``) signé avec la clé du client statique
    seedé (l'enregistrement dynamique ne crée pas de client ``fapi_enabled``) ;
    la query ne portant aucune ``redirect_uri`` enregistrée, l'OP sert la page
    d'erreur 400 (RFC 6749 §4.1.2.1) au lieu de rediriger. Les 14 autres
    modules FAPI1 reçoivent l'erreur par 302 vers leur callback et n'attendent
    plus de capture (issue #214).
    """
    client = _load_plan_signing_client(plans_dir / "fapi1.json", redirect_uri)
    for test_name, mode, error_code in _FAPI1_PAGE_SCENARIOS:
        url = _fapi1_request_url(base_url, client, _fapi1_claims(client, issuer, mode))
        _capture_error_page(page, url, error_code, out / f"{test_name}.png")


def _resolve_issuer(request: APIRequestContext, base_url: str) -> str:
    """Issuer OP lu dans le document de discovery, ``base_url`` en repli.

    Peut différer de l'URL de navigation : le harness local sert l'OP sur
    ``https://localhost:9443`` (nginx mTLS) alors que son issuer configuré
    est ``https://op:9443`` — sans ce repli, tous les ``aud`` signés
    (request objects FAPI1, assertions client FAPI2) sont refusés.
    """
    try:
        response = request.get(f"{base_url.rstrip('/')}/.well-known/openid-configuration")
        if response.ok:
            issuer = response.json().get("issuer")
            if isinstance(issuer, str) and issuer:
                return issuer.rstrip("/")
        _LOGGER.warning("discovery HTTP %s : aud = base_url", response.status)
    except Error as error:
        _LOGGER.warning("discovery inaccessible (%s) : aud = base_url", error)
    return base_url.rstrip("/")


def capture_all(
    playwright: Playwright,
    base_url: str,
    out: Path,
    username: str,
    password: str,
    *,
    plans_dir: Path,
    fapi1_redirect: str,
    suite_base: str,
) -> list[Path]:
    """Rejoue les scénarios et écrit les PNG nommés ``<testName>.png``.

    Les familles Core, FAPI1, fédération et dynamic sont indépendantes :
    l'échec d'une famille est logué sans interrompre les autres (la
    certification retombe sur le PNG de secours pour les fichiers manquants).
    """
    out.mkdir(parents=True, exist_ok=True)
    browser = playwright.chromium.launch()
    try:
        # ignore_https_errors : le harness local (certification-local.yml)
        # expose l'OP sur un certificat auto-signé (nginx mTLS) — sans effet
        # sur l'instance Render, dont le certificat est valide.
        context = browser.new_context(
            viewport={"width": 1024, "height": 768},
            ignore_https_errors=True,
        )
        page = context.new_page()
        issuer = _resolve_issuer(context.request, base_url)
        _LOGGER.info("issuer OP : %s", issuer)
        _capture_core_scenarios(page, context.request, base_url, out, username, password)
        try:
            _capture_fapi1_scenarios(page, base_url, issuer, plans_dir, out, fapi1_redirect)
        except Exception as error:
            _LOGGER.error("Captures fapi1 impossibles : %s", error)
        try:
            _capture_federation_scenarios(page, base_url, suite_base, out)
        except Exception as error:
            _LOGGER.error("Captures fédération impossibles : %s", error)
        # En dernier : les scénarios login vident les cookies du contexte,
        # sans effet sur les familles déjà jouées.
        try:
            _capture_dynamic_scenarios(page, context.request, base_url, out)
        except Exception as error:
            _LOGGER.error("Captures dynamic impossibles : %s", error)
    finally:
        browser.close()
    return sorted(out.glob("*.png"))


def main(argv: list[str] | None = None) -> int:
    """Capture les pages ; renvoie 0 si tous les fichiers attendus sont produits."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="https://puridentityserver-certification.onrender.com",
        help="URL publique de l'OP (défaut : instance de certification Render)",
    )
    parser.add_argument("--out", default="screenshots", help="répertoire des PNG")
    parser.add_argument(
        "--suite-url",
        default="https://www.certification.openid.net",
        help=(
            "Base des callbacks de la suite (.../test/a/<plan>/callback) : "
            "hébergée (défaut) ou harness local https://localhost.emobix.co.uk:8443"
        ),
    )
    parser.add_argument("--username", default="alice@example.com", help="compte de connexion")
    parser.add_argument("--password", default="password", help="mot de passe du compte")
    parser.add_argument(
        "--plans-dir",
        default="certification/plans",
        help="dossier des plans de certification (clés des clients FAPI statiques)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    out = Path(args.out)
    suite_base = args.suite_url.rstrip("/")
    fapi1_redirect = f"{suite_base}{_FAPI1_CALLBACK_PATH}"
    expected = {f"{name}.png" for name in _CORE_TEST_NAMES}
    expected |= {f"{name}.png" for name in _DYNAMIC_TEST_NAMES}
    expected |= {f"{name}.png" for name, _mode, _error in _FAPI1_PAGE_SCENARIOS}
    expected |= {f"{_FEDERATION_PAGE_TEST_NAME}.png"}
    try:
        with sync_playwright() as playwright:
            produced = capture_all(
                playwright,
                args.base_url,
                out,
                args.username,
                args.password,
                plans_dir=Path(args.plans_dir),
                fapi1_redirect=fapi1_redirect,
                suite_base=suite_base,
            )
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
