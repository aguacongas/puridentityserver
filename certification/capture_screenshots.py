r"""Capture les pages de relecture de l'OP pour la certification (issues #90, #138).

La suite officielle attend une capture d'écran pour 4 modules Core
(``oidcc-response-type-missing``, ``oidcc-ensure-registered-redirect-uri``,
``oidcc-max-age-1``, ``oidcc-prompt-login``) et laisse 20 modules FAPI
(``fapi1-advanced-final-*``, ``fapi2-security-profile-final-*``) en verdict
``REVIEW`` avec un placeholder « upload a screenshot of the error page » :
sans image, le mode witness remplit ces placeholders avec un PNG 1x1 de
secours — le verdict tombe juste, mais la preuve est un artifice.

Ce script rejoue les 30 scénarios contre l'OP réellement déployé avec un
navigateur headless (Playwright/chromium) et produit, pour chaque module,
une capture authentique de la page servie par l'OP :

1. les 4 scénarios Core (paramètre absent, ``redirect_uri`` non enregistrée,
   second ``prompt=login``, second ``max_age=1``) ;
2. les 6 scénarios propres au plan dynamic (issue #168) : ``redirect_uri``
   absente / supplémentaire / non concordante et pages de connexion des
   clients DCR porteurs d'un ``logo_uri``/``policy_uri``/``tos_uri`` ;
3. les 16 scénarios FAPI1 : un request object (JAR, ``by_value``) défectueux
   par module — claim absent, bornes ``exp``/``nbf``, ``aud``/signature,
   ``alg=none``/``RS256``, clé inconnue, request object absent, ``redirect_uri``
   non enregistrée — signé avec la clé privée du client statique seedé par
   ``certification/config.render.toml`` (l'enregistrement dynamique ne crée
   pas de client ``fapi_enabled``) ; la requête porte la ``redirect_uri``
   enregistrée et ``response_type=code id_token`` : l'erreur repart en
   fragment de la callback (RFC 6749 §4.2.2.1, issue #178), sauf pour les
   deux scénarios servis en page HTML (scénarios « page ») ;
4. les 4 scénarios FAPI2 : requête signée sans PAR, réutilisation d'un
   ``request_uri``, ``request_uri`` expiré, ``request_uri`` d'un autre client.

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
import base64
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
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
_FAPI2_CALLBACK_PATH = "/test/a/puridentityserver-fapi2/callback"

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

#: Modules FAPI1 du plan fapi1-advanced-final laissés en REVIEW : un request
#: object défectueux par module (RFC 6749 §4.1.2.1, RFC 9101 §6.3). Depuis
#: l'issue #178, l'erreur repart en redirection (fragment, response_type
#: ``code id_token``) quand la query porte une ``redirect_uri`` enregistrée.
_FAPI1_JAR_SCENARIOS: tuple[tuple[str, str, str], ...] = (
    (
        "fapi1-advanced-final-ensure-authorization-request-without-request-object-fails",
        "absent",
        "invalid_request",
    ),
    (
        "fapi1-advanced-final-ensure-expired-request-object-fails",
        "exp-past",
        "invalid_request_object",
    ),
    (
        "fapi1-advanced-final-ensure-matching-key-in-authorization-request",
        "foreign-key",
        "invalid_request_object",
    ),
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
    (
        "fapi1-advanced-final-ensure-request-object-signature-algorithm-is-not-none",
        "alg-none",
        "invalid_request_object",
    ),
    (
        "fapi1-advanced-final-ensure-request-object-with-bad-aud-fails",
        "bad-aud",
        "invalid_request_object",
    ),
    (
        "fapi1-advanced-final-ensure-request-object-with-exp-over-60-fails",
        "exp-over-60",
        "invalid_request_object",
    ),
    (
        "fapi1-advanced-final-ensure-request-object-with-invalid-signature-fails",
        "tampered",
        "invalid_request_object",
    ),
    (
        "fapi1-advanced-final-ensure-request-object-with-nbf-over-60-fails",
        "nbf-over-60",
        "invalid_request_object",
    ),
    (
        "fapi1-advanced-final-ensure-request-object-without-exp-fails",
        "no-exp",
        "invalid_request_object",
    ),
    (
        "fapi1-advanced-final-ensure-request-object-without-nbf-fails",
        "no-nbf",
        "invalid_request_object",
    ),
    (
        "fapi1-advanced-final-ensure-request-object-without-nonce-fails",
        "no-nonce",
        "invalid_request_object",
    ),
    (
        "fapi1-advanced-final-ensure-request-object-without-redirect-uri-fails",
        "no-redirect-uri",
        "invalid_request_object",
    ),
    (
        "fapi1-advanced-final-ensure-request-object-without-scope-fails",
        "no-scope",
        "invalid_request_object",
    ),
    (
        "fapi1-advanced-final-ensure-signed-request-object-with-RS256-fails",
        "rs256",
        "invalid_request_object",
    ),
)

#: Modules FAPI1 servis en **page HTML** (la query du scénario ne porte pas de
#: ``redirect_uri`` enregistrée, ou porte une URI non enregistrée — la RFC
#: 6749 §4.1.2.1 interdit alors de rediriger) ; tous les autres modes
#: repartent en fragment de la callback (issue #178). Les deux tests en mode
#: « sans redirect_uri » se distinguent par leur nom : la suite retire
#: l'URI du transport pour ``ensure-redirect-uri-in-authorization-request``,
#: elle ne retire que le claim du request object pour ``…-without-redirect-uri-fails``.
_FAPI1_PAGE_TEST_NAMES = frozenset(
    {
        "fapi1-advanced-final-ensure-redirect-uri-in-authorization-request",
        "fapi1-advanced-final-ensure-registered-redirect-uri",
    }
)

#: Modules FAPI2 du plan fapi2-security-profile-final laissés en REVIEW : les
#: erreurs de la voie poussée (PAR) sont transportées par la redirection 302
#: vers le callback du client poussé (RFC 6749 §4.1.2.1, issue #160).
_FAPI2_TEST_NAMES = (
    "fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails",
    "fapi2-security-profile-final-par-attempt-reuse-request_uri",
    "fapi2-security-profile-final-par-attempt-to-use-expired-request_uri",
    "fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client",
)


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


def _other_plan_client_id(plan_path: Path) -> str:
    """Retourne le ``client_id`` du second client seed d'un plan (« client2 »)."""
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    return str(payload["client2"]["client_id"])


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
    le défaut module (claim retiré, valeur hors borne, ``redirect_uri``
    inconnue…). Les valeurs ``None`` retirent le claim du jeton.
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
        "exp-past": {"exp": now - 120},
        "exp-over-60": {"exp": now + 3700},
        "nbf-over-60": {"nbf": now - 3700, "exp": now + 200},
        "bad-aud": {"aud": "https://rp.example.invalid/wrong-audience"},
        "no-exp": {"exp": None},
        "no-nbf": {"nbf": None},
        "no-nonce": {"nonce": None},
        "no-redirect-uri": {"redirect_uri": None},
        "no-scope": {"scope": None},
        "unregistered-redirect-uri": {"redirect_uri": "https://rp.example.invalid/not-registered"},
    }.get(mode, {})
    claims.update(overrides)
    return {name: value for name, value in claims.items() if value is not None}


def _sign(claims: dict[str, object], key: object, kid: str, algorithm: str = "PS256") -> str:
    """Signe un request object avec PyJWT (jamais de crypto maison)."""
    return str(pyjwt.encode(claims, key, algorithm=algorithm, headers={"kid": kid}))


def _sign_unsigned(claims: dict[str, object]) -> str:
    """Émet un request object ``alg=none`` (deux segments, sans signature)."""
    return str(pyjwt.encode(claims, key=None, algorithm="none"))


def _tamper(jar: str) -> str:
    """Altère la signature d'un JWT compact (dernier caractère changé)."""
    head, payload, signature = jar.rsplit(".", 2)
    replacement = "A" if not signature.endswith("A") else "B"
    return f"{head}.{payload}.{signature[:-1]}{replacement}"


def _fapi1_jar(
    client: PlanSigningClient,
    claims: dict[str, object],
    mode: str,
    foreign_key: object,
) -> str | None:
    """Construit le request object du scénario, ``None`` s'il est absent."""
    if mode == "absent":
        return None
    if mode == "foreign-key":
        return _sign(claims, foreign_key, "capture-foreign-key", "PS256")
    if mode == "alg-none":
        return _sign_unsigned(claims)
    if mode == "rs256":
        return _sign(claims, client.private_key, client.kid, "RS256")
    if mode == "tampered":
        return _tamper(_sign(claims, client.private_key, client.kid, "PS256"))
    return _sign(claims, client.private_key, client.kid, "PS256")


def _fapi1_request_url(
    base_url: str,
    client: PlanSigningClient,
    claims: dict[str, object],
    mode: str,
    foreign_key: object,
    page_mode: bool,
) -> str:
    """URL ``/authorize`` du scénario FAPI1 (``request`` par valeur, ou sans).

    Comme l'envoie la suite (issue #178) : la ``redirect_uri`` enregistrée et
    ``response_type=code id_token`` figurent dans la query des scénarios à
    redirection ; les scénarios « page » (:data:`_FAPI1_PAGE_TEST_NAMES`)
    n'en portent aucune de valide.
    """
    jar = _fapi1_jar(client, claims, mode, foreign_key)
    params = {"client_id": client.client_id}
    if not page_mode:
        params["redirect_uri"] = client.redirect_uri
        params["response_type"] = "code id_token"
    if jar is not None:
        params["request"] = jar
    return f"{base_url.rstrip('/')}/authorize?{urlencode(params)}"


def _pkce_pair() -> tuple[str, str]:
    """Génère le couple ``code_verifier`` / ``code_challenge`` S256 (RFC 7636)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _client_assertion(client: PlanSigningClient, issuer: str) -> str:
    """Assertion ``private_key_jwt`` du push PAR (RFC 7523 §2.2).

    FAPI2 n'admet que l'issuer comme ``audience`` (FAPI2-SP-FINAL-5.3.2.1-8).
    """
    now = _now()
    return _sign(
        {
            "iss": client.client_id,
            "sub": client.client_id,
            "aud": issuer.rstrip("/"),
            "jti": f"capture-{now}-{client.client_id}",
            "iat": now,
            "exp": now + 300,
        },
        client.private_key,
        client.kid,
    )


def _push_par(
    request: APIRequestContext,
    base_url: str,
    issuer: str,
    client: PlanSigningClient,
    code_challenge: str,
) -> str:
    """Pousse une demande valide (``POST /par``) et retourne son ``request_uri``."""
    response = request.post(
        f"{base_url.rstrip('/')}/par",
        form={
            "response_type": "code",
            "client_id": client.client_id,
            "redirect_uri": client.redirect_uri,
            "scope": "openid profile",
            "state": "capture-state",
            "nonce": "capture-nonce",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _client_assertion(client, issuer),
        },
    )
    if response.status not in (200, 201):
        raise RuntimeError(f"POST /par a répondu HTTP {response.status} : {response.text()[:300]}")
    request_uri = str(response.json().get("request_uri", ""))
    if not request_uri:
        raise RuntimeError(f"request_uri absente de la réponse PAR : {response.text()[:300]}")
    return request_uri


def _authorize_with_uri(base_url: str, client_id: str, request_uri: str) -> str:
    """URL ``/authorize`` d'une visite par référence poussée (RFC 9126 §4)."""
    query = urlencode({"client_id": client_id, "request_uri": request_uri})
    return f"{base_url.rstrip('/')}/authorize?{query}"


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


def _complete_flow_quietly(page: Page, url: str, username: str, password: str) -> None:
    """Consomme une demande poussée sans exiger le succès de la navigation finale.

    Le ``redirect_uri`` enregistré des clients FAPI est celui de la suite de
    certification (hébergé, joignable depuis la CI) : l'issue de la
    navigation finale est sans consommé pour la capture (seule la
    consommation du ``request_uri`` à l'émission compte), toute erreur de
    navigation y est donc absorbée.
    """
    try:
        _run_flow(page, url, username, password)
    except Error as error:
        _LOGGER.info("Navigation finale du push PAR absorbée : %s", error)


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


def _capture_redirect_error(
    page: Page, url: str, callback_uri: str, error_code: str, path: Path
) -> None:
    """Capture l'erreur transportée par la redirection vers le callback (RFC 6749 §4.1.2.1).

    Les erreurs de la voie poussée (obligation PAR, ``request_uri`` expiré,
    réutilisé ou d'un autre client) sont servies par une 302 vers la
    ``redirect_uri`` du client poussé : la redirection est contrôlée sur le
    premier saut (``max_redirects=0`` — la suite elle-même redirige son
    callback vers ``log-detail.html``), puis la page finale est capturée en
    viewport (la page ``log-detail`` déborde des 500 Ko en page entière).
    """
    response = page.request.get(url, max_redirects=0)
    if response.status != 302:
        raise RuntimeError(
            f"HTTP {response.status} inattendu pour {url} (attendu 302) : {response.text()[:200]}"
        )
    location = response.headers.get("location", "")
    callback_path = callback_uri.split("?", 1)[0]
    if not location.startswith(callback_path):
        raise RuntimeError(f"l'OP n'a pas redirigé vers {callback_path} : {location}")
    if f"error={error_code}" not in location:
        raise RuntimeError(f"motif {error_code!r} absent de la redirection : {location}")
    _goto(page, location)
    # Hors exécution de test, le callback de la suite ne retrouve pas son
    # test (« no test found ») : un bandeau injecté rend l'URL reçue (et le
    # motif ``error=`` transporté par la 302) visible sur la capture.
    page.evaluate(
        "(u) => { const d = document.createElement('pre'); d.textContent = u;"
        " d.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;"
        "margin:0;padding:.5rem;background:#fffbe6;border-bottom:2px solid #d4a017;"
        "font:bold .8rem monospace;white-space:pre-wrap;word-break:break-all';"
        " document.body.prepend(d); }",
        location,
    )
    _screenshot(page, path, full_page=False)


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
    """Rejoue les 16 scénarios FAPI1 (request object défectueux par module).

    Redirection vers la callback en fragment (``response_type`` hybride,
    issue #178) hors :data:`_FAPI1_PAGE_TEST_NAMES`, page HTML 400 pour les
    deux scénarios « page ».
    """
    client = _load_plan_signing_client(plans_dir / "fapi1.json", redirect_uri)
    foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for test_name, mode, error_code in _FAPI1_JAR_SCENARIOS:
        claims = _fapi1_claims(client, issuer, mode)
        page_mode = test_name in _FAPI1_PAGE_TEST_NAMES
        url = _fapi1_request_url(base_url, client, claims, mode, foreign_key, page_mode)
        path = out / f"{test_name}.png"
        if page_mode:
            _capture_error_page(page, url, error_code, path)
        else:
            _capture_redirect_error(page, url, redirect_uri, error_code, path)


def _capture_fapi2_scenarios(
    page: Page,
    request: APIRequestContext,
    base_url: str,
    issuer: str,
    plans_dir: Path,
    out: Path,
    par_ttl_seconds: int,
    username: str,
    password: str,
    redirect_uri: str,
) -> None:
    """Rejoue les 4 scénarios FAPI2 (demande poussée, ``request_uri``)."""
    client = _load_plan_signing_client(plans_dir / "fapi2.json", redirect_uri)
    other_client_id = _other_plan_client_id(plans_dir / "fapi2.json")
    _capture_unsigned_without_par(page, base_url, client.client_id, out, redirect_uri)
    _, challenge = _pkce_pair()
    _capture_par_reuse(
        page, request, base_url, issuer, client, challenge, out, username, password, redirect_uri
    )
    _capture_par_expired(
        page, request, base_url, issuer, client, challenge, out, par_ttl_seconds, redirect_uri
    )
    _capture_par_other_client(
        page, request, base_url, issuer, client, other_client_id, challenge, out, redirect_uri
    )


def _capture_unsigned_without_par(
    page: Page, base_url: str, client_id: str, out: Path, redirect_uri: str
) -> None:
    """FAPI2 n'admet que les demandes poussées : une requête directe est refusée."""
    url = _authorize_url(
        base_url,
        client_id,
        extra={"redirect_uri": redirect_uri, "code_challenge_method": "S256"},
    )
    _capture_redirect_error(
        page,
        url,
        redirect_uri,
        "invalid_request",
        out / f"{_FAPI2_TEST_NAMES[0]}.png",
    )


def _capture_par_reuse(
    page: Page,
    request: APIRequestContext,
    base_url: str,
    issuer: str,
    client: PlanSigningClient,
    code_challenge: str,
    out: Path,
    username: str,
    password: str,
    redirect_uri: str,
) -> None:
    """Le ``request_uri`` est à usage unique : la seconde visite est refusée."""
    request_uri = _push_par(request, base_url, issuer, client, code_challenge)
    url = _authorize_with_uri(base_url, client.client_id, request_uri)
    _complete_flow_quietly(page, url, username, password)
    _capture_redirect_error(
        page,
        url,
        redirect_uri,
        "invalid_request_uri",
        out / f"{_FAPI2_TEST_NAMES[1]}.png",
    )


def _capture_par_expired(
    page: Page,
    request: APIRequestContext,
    base_url: str,
    issuer: str,
    client: PlanSigningClient,
    code_challenge: str,
    out: Path,
    par_ttl_seconds: int,
    redirect_uri: str,
) -> None:
    """Un ``request_uri`` expiré (TTL PAR) est refusé (RFC 9126 §4)."""
    request_uri = _push_par(request, base_url, issuer, client, code_challenge)
    time.sleep(par_ttl_seconds + 2)
    url = _authorize_with_uri(base_url, client.client_id, request_uri)
    _capture_redirect_error(
        page,
        url,
        redirect_uri,
        "invalid_request_uri",
        out / f"{_FAPI2_TEST_NAMES[2]}.png",
    )


def _capture_par_other_client(
    page: Page,
    request: APIRequestContext,
    base_url: str,
    issuer: str,
    client: PlanSigningClient,
    other_client_id: str,
    code_challenge: str,
    out: Path,
    redirect_uri: str,
) -> None:
    """La référence poussée n'est résoluble que pour le client qui l'a émise."""
    request_uri = _push_par(request, base_url, issuer, client, code_challenge)
    url = _authorize_with_uri(base_url, other_client_id, request_uri)
    _capture_redirect_error(
        page,
        url,
        redirect_uri,
        "invalid_request",
        out / f"{_FAPI2_TEST_NAMES[3]}.png",
    )


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
    par_ttl_seconds: int,
    fapi1_redirect: str,
    fapi2_redirect: str,
) -> list[Path]:
    """Rejoue les 30 scénarios et écrit les PNG nommés ``<testName>.png``.

    Les familles FAPI et dynamic sont indépendantes : l'échec d'une famille
    est logué sans interrompre les autres (la certification retombe sur le
    PNG de secours pour les fichiers manquants).
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
            _capture_fapi2_scenarios(
                page,
                context.request,
                base_url,
                issuer,
                plans_dir,
                out,
                par_ttl_seconds,
                username,
                password,
                fapi2_redirect,
            )
        except Exception as error:
            _LOGGER.error("Captures fapi2 impossibles : %s", error)
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
    """Capture les pages ; renvoie 0 si les 30 fichiers sont produits."""
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
    parser.add_argument(
        "--par-ttl-seconds",
        type=int,
        default=30,
        help="TTL PAR de l'OP, aligné sur par_ttl_seconds (scénario request_uri expiré)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    out = Path(args.out)
    suite_base = args.suite_url.rstrip("/")
    fapi1_redirect = f"{suite_base}{_FAPI1_CALLBACK_PATH}"
    fapi2_redirect = f"{suite_base}{_FAPI2_CALLBACK_PATH}"
    expected = {f"{name}.png" for name in _CORE_TEST_NAMES}
    expected |= {f"{name}.png" for name in _DYNAMIC_TEST_NAMES}
    expected |= {f"{name}.png" for name, _mode, _error in _FAPI1_JAR_SCENARIOS}
    expected |= {f"{name}.png" for name in _FAPI2_TEST_NAMES}
    try:
        with sync_playwright() as playwright:
            produced = capture_all(
                playwright,
                args.base_url,
                out,
                args.username,
                args.password,
                plans_dir=Path(args.plans_dir),
                par_ttl_seconds=args.par_ttl_seconds,
                fapi1_redirect=fapi1_redirect,
                fapi2_redirect=fapi2_redirect,
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
