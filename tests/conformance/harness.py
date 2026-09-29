"""Mini-reliant-party (RP) local pour rejouer les checks de la certification.

Le harness joue le rôle du navigateur pilote de la suite officielle
(`openid/conformance-suite`, scripts ``browser`` des plans) contre
l'application locale :

- enchaîne ``/authorize`` → ``/login`` → ``/consent`` → callback en se
  reconnectant et en consentant automatiquement, tout en **comptant les pages
  de connexion présentées** — c'est l'observable du check
  ``ExpectSecondLoginPage`` de la suite (la suite matche l'URL de la réponse
  finale sur ``{OPURL}/login*``) ;
- capture les paramètres du callback en query **et** en fragment
  (RFC 6749 §4.1.2.1 / §4.2.2.1) ;
- échange le code (PKCE) et décode les claims de l'id_token pour lire
  ``auth_time``, sujet des checks ``CheckSecondIdTokenAuthTimeIsLaterIfPresent``
  et ``CheckIdTokenAuthTimeClaimPresentDueToMaxAge``.

Deux cibles : l'application locale montée en ``TestClient`` (défaut) ou, si
``PURIDENTITYSERVER_CONFORMANCE_URL`` est défini, un OP réel déjà démarré
(``httpx`` contre ce serveur) — même pilote, seul le transport change.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

CLIENT_ID = "web-app"
CLIENT_SECRET = "super-secret"
REDIRECT_URI = "https://app.example/callback"
USERNAME = "alice@example.com"
PASSWORD = "password"
CODE_VERIFIER = "conformance-code-verifier-0123456789abcdefgh"
MAX_HOPS = 12
_REDIRECT_STATUSES = (302, 303, 307, 308)
_HIDDEN_INPUT = r'<input type="hidden" name="([^"]+)" value="([^"]*)">'


@dataclass
class FlowResult:
    """Issue d'un enchaînement ``/authorize`` jusqu'au callback ou une erreur."""

    status_code: int = 0
    body: str = ""
    login_pages: int = 0
    consent_pages: int = 0
    hops: list[str] = field(default_factory=list)
    callback_url: str = ""
    query: dict[str, str] = field(default_factory=dict)
    fragment: dict[str, str] = field(default_factory=dict)

    @property
    def error(self) -> str:
        """``error`` du callback (fragment, sinon query) ; vide s'il n'y en a pas."""
        return self.fragment.get("error", self.query.get("error", ""))

    @property
    def code(self) -> str:
        """Code d'autorisation porté par le callback, vide sinon."""
        return self.query.get("code", "")


def pkce_challenge(verifier: str) -> str:
    """Défi PKCE S256 (RFC 7636 §4.2) d'un ``code_verifier`` donné."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def new_verifier() -> str:
    """Nouveau ``code_verifier`` aléatoire (43 à 128 caractères, RFC 7636 §4.1)."""
    return secrets.token_urlsafe(48)


class ConformanceHarness:
    """Pilote un parcours ``/authorize`` complet comme le navigateur de la suite."""

    def __init__(
        self,
        app: FastAPI,
        *,
        username: str = USERNAME,
        password: str = PASSWORD,
        client_id: str = CLIENT_ID,
        client_secret: str = CLIENT_SECRET,
        redirect_uri: str = REDIRECT_URI,
    ) -> None:
        """Prépare le transport : ``TestClient`` local ou OP distant (env var)."""
        remote = os.environ.get("PURIDENTITYSERVER_CONFORMANCE_URL", "").rstrip("/")
        self._username = username
        self._password = password
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._client: httpx.Client = (
            httpx.Client(base_url=remote, follow_redirects=False, timeout=30.0)
            if remote
            else TestClient(app, follow_redirects=False)
        )

    def __enter__(self) -> ConformanceHarness:
        """Démarre le lifespan de l'application (seed des comptes)."""
        if isinstance(self._client, TestClient):
            self._client.__enter__()
        return self

    def __exit__(self, *_exc: object) -> None:
        """Arrête le transport (fermeture différée de l'OP distant)."""
        if isinstance(self._client, TestClient):
            self._client.__exit__(None, None, None)
        else:
            self._client.close()

    def authorize_params(self, verifier: str, **extra: str) -> dict[str, str]:
        """Paramètres PKCE/nonce/state d'une demande ``response_type=code``."""
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "scope": "openid profile",
            "state": secrets.token_urlsafe(8),
            "nonce": secrets.token_urlsafe(8),
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
        params.update(extra)
        return params

    def run_flow(self, **params: str) -> FlowResult:
        """Enchaîne ``/authorize`` jusqu'au callback, en gérant login et consent.

        Une réponse non redirigeante (page d'erreur HTTP 400 par exemple) est
        retournée telle quelle dans :attr:`FlowResult.body`. Les redirections
        vers ``/login`` et ``/consent`` sont résolues automatiquement — les
        pages présentées sont comptées, c'est ce que les checks
        ``ExpectSecondLoginPage`` observent.
        """
        return self._navigate("GET", params)

    def run_flow_post(self, **params: str) -> FlowResult:
        """Parcours identique mais la demande d'autorisation part en HTTP POST.

        Rejoue ``oidcc-ensure-post-request-succeeds`` : la suite envoie la
        requête d'autorisation en POST (RFC 6749 §4.1.2 note), les étapes
        suivantes (login/consent) restent des GET.
        """
        return self._navigate("POST", params)

    def reset_session(self) -> None:
        """Oublie les cookies de session : l'utilisateur est à nouveau anonyme."""
        self._client.cookies.clear()

    def login(self) -> None:
        """Établit la session utilisateur (POST ``/login`` sans ``next``).

        Utilisé pour les parcours qui exigent une session **avant** la demande
        d'autorisation (ex. ``oidcc-ensure-post-request-succeeds``).
        """
        self._client.get("/login")
        response = self._client.post(
            "/login", data={"username": self._username, "password": self._password}
        )
        if response.status_code != 302:
            raise AssertionError(
                f"connexion refusée ({response.status_code}) : {response.text[:300]}"
            )

    def _navigate(self, method: str, params: dict[str, str]) -> FlowResult:
        """Boucle de redirections ; la première requête utilise ``method``."""
        result = FlowResult()
        clean = {key: value for key, value in params.items() if value}
        url = "/authorize?" + urlencode(clean)
        first = True
        for _ in range(MAX_HOPS):
            if first and method == "POST":
                response = self._client.post("/authorize", data=clean)
            else:
                response = self._client.get(url)
            first = False
            location = response.headers.get("location", "")
            result.hops.append(f"{response.status_code} {location}")
            if response.status_code not in _REDIRECT_STATUSES:
                result.status_code = response.status_code
                result.body = response.text
                return result
            target = _path_of(location)
            if target.startswith("/login"):
                result.login_pages += 1
                url = self._submit_login(location)
                continue
            if target.startswith("/consent"):
                result.consent_pages += 1
                location = self._submit_consent(target)
                target = _path_of(location)
                if not target.startswith(("/login", "/consent", "/authorize")):
                    return _record_callback(result, location)
                url = target
                continue
            if target.startswith("/authorize"):
                url = target
                continue
            return _record_callback(result, location)
        raise AssertionError(f"redirections en boucle : {result.hops}")

    def exchange_code(
        self,
        result: FlowResult,
        verifier: str,
        auth_method: str = "basic",
    ) -> dict[str, Any]:
        """Échange le code du callback contre les jetons (PKCE, RFC 6749 §4.1.3).

        ``auth_method`` rejoue la variante ``ClientAuthType`` du plan :
        ``basic`` (header ``Authorization``), ``post`` (``client_id`` et
        ``client_secret`` dans le corps, check ``AddFormBasedClientSecretToRequest``)
        ou ``none`` (client public, ``client_id`` seul dans le corps).
        """
        if not result.code:
            raise AssertionError(f"aucun code dans le callback : {result.callback_url!r}")
        response = self.token_request(
            {
                "grant_type": "authorization_code",
                "code": result.code,
                "redirect_uri": self._redirect_uri,
                "code_verifier": verifier,
            },
            auth_method,
        )
        if response.status_code != 200:
            raise AssertionError(
                f"échange du code refusé ({response.status_code}) : {response.text[:300]}"
            )
        return dict(response.json())

    def token_request(self, data: dict[str, str], auth_method: str = "basic") -> httpx.Response:
        """POST ``/token`` avec la méthode d'authentification client demandée."""
        payload = dict(data)
        auth: tuple[str, str] | None = (self._client_id, self._client_secret)
        if auth_method == "post":
            payload["client_id"] = self._client_id
            payload["client_secret"] = self._client_secret
            auth = None
        elif auth_method == "none":
            payload["client_id"] = self._client_id
            auth = None
        return self._client.post("/token", data=payload, auth=auth)

    def userinfo(self, method: str, access_token: str) -> httpx.Response:
        """Appelle ``/userinfo`` (check ``CallUserInfoEndpoint``).

        ``method`` : ``get`` (GET + Bearer), ``post_header`` (POST + Bearer) ou
        ``post_body`` (POST form sans header, ``access_token`` dans le corps —
        check ``CallUserInfoEndpointWithBearerTokenInBody``).
        """
        headers = {"Authorization": f"Bearer {access_token}"}
        if method == "get":
            return self._client.get("/userinfo", headers=headers)
        if method == "post_header":
            return self._client.post("/userinfo", headers=headers)
        if method == "post_body":
            return self._client.post("/userinfo", data={"access_token": access_token})
        raise AssertionError(f"méthode userinfo inconnue : {method}")

    @staticmethod
    def id_token_header(token_response: dict[str, Any]) -> dict[str, Any]:
        """Décode le header JWT (``alg``, ``kid``) de l'id_token."""
        id_token = str(token_response.get("id_token", ""))
        if not id_token:
            raise AssertionError(f"aucun id_token dans la réponse : {sorted(token_response)}")
        header = id_token.split(".")[0]
        header += "=" * (-len(header) % 4)
        return dict(json.loads(base64.urlsafe_b64decode(header)))

    @staticmethod
    def id_token_claims(token_response: dict[str, Any]) -> dict[str, Any]:
        """Décode les claims de l'id_token retourné par ``/token``.

        Seul le payload décodé est lu ici : la vérification de signature est
        l'affaire des modules ``idtoken-*`` (PR certification suivante).
        """
        id_token = str(token_response.get("id_token", ""))
        if not id_token:
            raise AssertionError(f"aucun id_token dans la réponse : {sorted(token_response)}")
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims: dict[str, Any] = json.loads(base64.urlsafe_b64decode(payload))
        return claims

    def _submit_login(self, login_location: str) -> str:
        """Soumet le formulaire de connexion et renvoie la prochaine ``/authorize``."""
        query = parse_qs(urlparse(login_location).query)
        next_url = query.get("next", [""])[0] or "/"
        self._client.get("/login")
        response = self._client.post(
            "/login",
            data={"username": self._username, "password": self._password, "next": next_url},
        )
        if response.status_code != 302:
            raise AssertionError(
                f"connexion refusée ({response.status_code}) : {response.text[:300]}"
            )
        return _path_of(response.headers.get("location", "/"))

    def _submit_consent(self, consent_url: str) -> str:
        """Approuve l'écran de consentement et renvoie la redirection obtenue."""
        page = self._client.get(consent_url)
        hidden = {
            name: html.unescape(value) for name, value in re.findall(_HIDDEN_INPUT, page.text)
        }
        hidden["action"] = "authorize"
        response = self._client.post("/consent", data=hidden)
        if response.status_code != 302:
            raise AssertionError(
                f"consentement refusé ({response.status_code}) : {response.text[:300]}"
            )
        return response.headers.get("location", "")


def _path_of(location: str) -> str:
    """Chemin + query d'une URL (relative ou absolue) : le host est toujours le client."""
    parsed = urlparse(location)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


def _first_values(raw: str) -> dict[str, str]:
    """Première valeur de chaque paramètre (query ou fragment)."""
    return {key: values[0] for key, values in parse_qs(raw).items() if values}


def _record_callback(result: FlowResult, location: str) -> FlowResult:
    """Conserve l'URL du callback et ses paramètres (query et fragment)."""
    parsed = urlparse(location)
    result.status_code = 302
    result.callback_url = location
    result.query = _first_values(parsed.query)
    result.fragment = _first_values(parsed.fragment)
    return result
