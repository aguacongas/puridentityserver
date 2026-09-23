"""Tests du RP-Initiated Logout (OIDC Core 1.0 §5) — usecase + endpoint.

- Unitaires : ``LogoutUseCase`` piloté par de faux ports (TokenManager,
  ClientRepository) pour couvrir ses règles métier sans infra réelle.
- Intégration HTTP : ``GET /end_session`` via TestClient sur l'app réelle
  (login E2E → id_token → logout), contrôle du cookie de session et des
  redirections.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterable
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.logout import (
    LogoutConfig,
    LogoutError,
    LogoutRequest,
    LogoutResult,
    LogoutUseCase,
)
from puridentityserver.domain.authorization import Client
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_ISSUER = "https://id.example"

_CLIENT_JSON = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "post_logout_redirect_uris": ["https://app.example/post-logout"],
    "scopes": "openid profile email",
    "client_type": "confidential",
}

_POST_LOGOUT_URI = "https://app.example/post-logout"

_IDENTITY_SEED = {
    "alice": {"email": "alice@example.com", "password": "password"},
}


def _app(**settings: object) -> FastAPI:
    merged: dict[str, object] = {
        "issuer": _ISSUER,
        "base_url": _ISSUER,
        "jwks_algorithms": ("RS256",),
        "clients_seed": (_CLIENT_JSON,),
        "identity_seed_users": _IDENTITY_SEED,
    }
    merged.update(settings)
    return create_app(Settings(**merged))


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _redirect_query(redirect_url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(redirect_url).query)


# ───── Ports de substitution ──────────────────────────────────────────────── #


class FakeTokenManager:
    """Renvoie des claims prédéfinis à ``validate_id_token`` (ou None)."""

    def __init__(self, claims: dict[str, object] | None) -> None:
        """Mémorise les claims à renvoyer (None = jeton refusé)."""
        self._claims = claims
        self.logout_tokens: list[dict[str, object]] = []

    async def validate_id_token(self, *, token: str, issuer: str) -> dict[str, object] | None:
        del token, issuer
        return None if self._claims is None else dict(self._claims)

    async def create_logout_token(
        self,
        *,
        issuer: str,
        subject: str,
        audience: str,
        sid: str,
        expires_at: int,
        issued_at: int,
        jwt_id: str,
    ) -> str:
        """Mémorise les arguments et renvoie un jeton factice."""
        self.logout_tokens.append(
            {
                "issuer": issuer,
                "subject": subject,
                "audience": audience,
                "sid": sid,
                "expires_at": expires_at,
                "issued_at": issued_at,
                "jwt_id": jwt_id,
            }
        )
        return f"logout-token-{audience}"


class FakeBackchannelNotifier:
    """Notifieur de test : enregistre les (URI, logout_token) notifiées."""

    def __init__(self) -> None:
        """Initialise la liste des notifications reçues."""
        self.notified: list[tuple[str, str]] = []

    async def notify(self, *, url: str, logout_token: str) -> None:
        """Consigne la notification sans réseau ni échec."""
        self.notified.append((url, logout_token))
        return None


class FakeClientRepository:
    """Registre de clients en mémoire pour les tests unitaires."""

    def __init__(self, clients: Iterable[Client]) -> None:
        """Mémorise le registre de clients fourni."""
        self._clients = list(clients)

    async def find_by_id(self, client_id: str) -> Client | None:
        return next((c for c in self._clients if c.client_id == client_id), None)

    async def find_all(self) -> list[Client]:
        return list(self._clients)

    async def save(self, client: Client) -> None:  # pragma: no cover
        del client

    async def initialise(self) -> None:  # pragma: no cover
        """Rien à initialiser : registre fourni à la construction."""

    async def close(self) -> None:  # pragma: no cover
        """Aucune ressource à libérer."""


def _client(
    client_id: str = "web-app",
    *,
    post_logout: Iterable[str] = (),
    is_active: bool = True,
    frontchannel_logout_uri: str = "",
    frontchannel_logout_session_required: bool = False,
    backchannel_logout_uri: str = "",
) -> Client:
    return Client(
        client_id=client_id,
        redirect_uris=frozenset(),
        post_logout_redirect_uris=frozenset(post_logout),
        is_active=is_active,
        frontchannel_logout_uri=frontchannel_logout_uri,
        frontchannel_logout_session_required=frontchannel_logout_session_required,
        backchannel_logout_uri=backchannel_logout_uri,
    )


def _usecase(
    claims: dict[str, object] | None,
    clients: list[Client],
    notifier: FakeBackchannelNotifier | None = None,
) -> LogoutUseCase:
    return LogoutUseCase(
        LogoutConfig(issuer=_ISSUER),
        FakeClientRepository(clients),
        FakeTokenManager(claims),
        backchannel_notifier=notifier,
    )


# ───── Unitaires du usecase ───────────────────────────────────────────────── #


@pytest.mark.anyio
async def test_valid_hint_registered_uri_returns_result() -> None:
    """Hint valide (aud résout le client) + URI enregistrée → redirection OK."""
    claims: dict[str, object] = {"iss": _ISSUER, "aud": "web-app", "sub": "u-1"}
    usecase = _usecase(claims, [_client(post_logout=(_POST_LOGOUT_URI,))])

    result = await usecase.execute(
        LogoutRequest(
            id_token_hint="hint",
            post_logout_redirect_uri=_POST_LOGOUT_URI,
            state="s-42",
        )
    )

    assert isinstance(result, LogoutResult)
    assert result.post_logout_redirect_uri == _POST_LOGOUT_URI
    assert result.state == "s-42"
    assert result.subject == "u-1"
    assert result.client_id == "web-app"


@pytest.mark.anyio
async def test_valid_hint_unregistered_uri_rejected() -> None:
    """URI de sortie hors ``post_logout_redirect_uris`` → invalid_request."""
    claims: dict[str, object] = {"iss": _ISSUER, "aud": "web-app", "sub": "u-1"}
    usecase = _usecase(claims, [_client(post_logout=(_POST_LOGOUT_URI,))])

    result = await usecase.execute(
        LogoutRequest(
            id_token_hint="hint",
            post_logout_redirect_uri="https://evil.example/steal",
            state="s",
        )
    )

    assert isinstance(result, LogoutError)
    assert result.error == "invalid_request"


@pytest.mark.anyio
async def test_invalid_hint_rejected() -> None:
    """Hint rejeté par le TokenManager (signature/iss/exp) → invalid_request."""
    usecase = _usecase(None, [_client(post_logout=(_POST_LOGOUT_URI,))])

    result = await usecase.execute(
        LogoutRequest(id_token_hint="forged", post_logout_redirect_uri=_POST_LOGOUT_URI)
    )

    assert isinstance(result, LogoutError)
    assert result.error == "invalid_request"


@pytest.mark.anyio
async def test_hint_unknown_client_rejected() -> None:
    """``aud`` ne résout vers aucun client enregistré → invalid_request."""
    claims: dict[str, object] = {"iss": _ISSUER, "aud": "ghost-client", "sub": "u-1"}
    usecase = _usecase(claims, [_client()])

    result = await usecase.execute(LogoutRequest(id_token_hint="hint"))

    assert isinstance(result, LogoutError)
    assert result.error == "invalid_request"


@pytest.mark.anyio
async def test_hint_inactive_client_rejected() -> None:
    """Client trouvé mais désactivé → invalid_request (ni logout ni redirection)."""
    claims: dict[str, object] = {"iss": _ISSUER, "aud": "web-app", "sub": "u-1"}
    usecase = _usecase(claims, [_client(post_logout=(_POST_LOGOUT_URI,), is_active=False)])

    result = await usecase.execute(
        LogoutRequest(id_token_hint="hint", post_logout_redirect_uri=_POST_LOGOUT_URI)
    )

    assert isinstance(result, LogoutError)
    assert result.error == "invalid_request"


@pytest.mark.anyio
async def test_no_hint_uri_resolved_via_registry() -> None:
    """Sans hint, l'URI enregistrée est retrouvée dans le registre clients."""
    usecase = _usecase(
        None,
        [
            _client("other-client"),
            _client(post_logout=(_POST_LOGOUT_URI,)),
        ],
    )

    result = await usecase.execute(
        LogoutRequest(post_logout_redirect_uri=_POST_LOGOUT_URI, state="s")
    )

    assert isinstance(result, LogoutResult)
    assert result.post_logout_redirect_uri == _POST_LOGOUT_URI
    assert result.client_id == "web-app"
    assert result.subject == ""
    assert result.state == "s"


@pytest.mark.anyio
async def test_no_hint_uri_unregistered_rejected() -> None:
    """Sans hint, toute URI non enregistrée est rejetée (pas d'open-redirect)."""
    usecase = _usecase(None, [_client(post_logout=(_POST_LOGOUT_URI,))])

    result = await usecase.execute(
        LogoutRequest(post_logout_redirect_uri="https://evil.example/steal")
    )

    assert isinstance(result, LogoutError)
    assert result.error == "invalid_request"


@pytest.mark.anyio
async def test_no_hint_no_uri_html_page_path() -> None:
    """Sans hint ni URI → résultat vide : l'op affiche la page de confirmation."""
    usecase = _usecase(None, [_client()])

    result = await usecase.execute(LogoutRequest())

    assert isinstance(result, LogoutResult)
    assert result.post_logout_redirect_uri == ""
    assert result.client_id == ""
    assert result.subject == ""


@pytest.mark.anyio
async def test_hint_without_uri_still_ends_session() -> None:
    """Hint valide sans URI → session terminée, state conservé, sujet identifié."""
    claims: dict[str, object] = {"iss": _ISSUER, "aud": "web-app", "sub": "u-1"}
    usecase = _usecase(claims, [_client(post_logout=(_POST_LOGOUT_URI,))])

    result = await usecase.execute(LogoutRequest(id_token_hint="hint", state="s"))

    assert isinstance(result, LogoutResult)
    assert result.post_logout_redirect_uri == ""
    assert result.subject == "u-1"
    assert result.client_id == "web-app"
    assert result.state == "s"


# ───── Front/Back-Channel Logout 1.0 ──────────────────────────────────────── #


@pytest.mark.anyio
async def test_frontchannel_uris_with_sid_when_required() -> None:
    """`frontchannel_logout_session_required` → `?sid=` ; sinon URI nue."""
    usecase = _usecase(
        None,
        [
            _client(
                "session-client",
                frontchannel_logout_uri="https://spa.example/front",
                frontchannel_logout_session_required=True,
            ),
            _client(
                "plain-client",
                frontchannel_logout_uri="https://ssr.example/logout",
                frontchannel_logout_session_required=False,
            ),
            _client("no-uri-client"),
            _client(
                "inactive-client",
                frontchannel_logout_uri="https://gone.example/front",
                is_active=False,
            ),
        ],
    )

    uris = await usecase.frontchannel_uris(session_id="sid-1")

    assert uris == (
        "https://spa.example/front?sid=sid-1",
        "https://ssr.example/logout",
    )


@pytest.mark.anyio
async def test_frontchannel_uris_append_sid_existing_query() -> None:
    """Une URI avec query garde son `?` et ajoute `&sid=`."""
    usecase = _usecase(
        None,
        [
            _client(
                "query-client",
                frontchannel_logout_uri="https://spa.example/front?tenant=a",
                frontchannel_logout_session_required=True,
            )
        ],
    )

    uris = await usecase.frontchannel_uris(session_id="sid-9")

    assert uris == ("https://spa.example/front?tenant=a&sid=sid-9",)


@pytest.mark.anyio
async def test_backchannel_broadcast_posts_logout_token_per_client() -> None:
    """Un logout_token par client enregistré et actif, avec sub/sid/events signalés."""
    notifier = FakeBackchannelNotifier()
    token_manager = FakeTokenManager(None)
    usecase = LogoutUseCase(
        LogoutConfig(issuer=_ISSUER),
        FakeClientRepository(
            [
                _client(
                    "bc-1",
                    backchannel_logout_uri="https://ssr1.example/bc",
                ),
                _client(
                    "bc-2",
                    backchannel_logout_uri="https://ssr2.example/bc",
                ),
                _client("no-bc-client"),
                _client(
                    "bc-inactive", backchannel_logout_uri="https://gone.example/bc", is_active=False
                ),
            ]
        ),
        token_manager,
        backchannel_notifier=notifier,
    )

    await usecase.broadcast_backchannel_logout(subject="u-1", session_id="sid-1")

    assert notifier.notified == [
        ("https://ssr1.example/bc", "logout-token-bc-1"),
        ("https://ssr2.example/bc", "logout-token-bc-2"),
    ]
    assert token_manager.logout_tokens == [
        {
            "issuer": _ISSUER,
            "subject": "u-1",
            "audience": "bc-1",
            "sid": "sid-1",
            "jwt_id": token_manager.logout_tokens[0]["jwt_id"],
            "expires_at": token_manager.logout_tokens[0]["expires_at"],
            "issued_at": token_manager.logout_tokens[0]["issued_at"],
        },
        {
            "issuer": _ISSUER,
            "subject": "u-1",
            "audience": "bc-2",
            "sid": "sid-1",
            "jwt_id": token_manager.logout_tokens[1]["jwt_id"],
            "expires_at": token_manager.logout_tokens[1]["expires_at"],
            "issued_at": token_manager.logout_tokens[1]["issued_at"],
        },
    ]
    for issued in token_manager.logout_tokens:
        assert issued["expires_at"] - issued["issued_at"] == 60


@pytest.mark.anyio
async def test_backchannel_broadcast_skips_without_subject() -> None:
    """Sans sujet identifiable, aucune notification back-channel n'est émise."""
    notifier = FakeBackchannelNotifier()
    usecase = _usecase(
        None,
        [_client("bc-1", backchannel_logout_uri="https://ssr1.example/bc")],
        notifier=notifier,
    )

    await usecase.broadcast_backchannel_logout(subject="", session_id="sid-1")

    assert notifier.notified == []


@pytest.mark.anyio
async def test_backchannel_broadcast_skips_when_no_notifier() -> None:
    """Pas de notifieur injecté → aucune notification et aucune exception."""
    usecase = _usecase(
        None,
        [_client("bc-1", backchannel_logout_uri="https://ssr1.example/bc")],
    )

    await usecase.broadcast_backchannel_logout(subject="u-1", session_id="sid-1")


# ───── Intégration HTTP : GET /end_session ───────────────────────────────── #


def _login_and_get_id_token(client: TestClient) -> str:
    """Flow E2E raccourci : login → /authorize (PKCE) → /token → id_token."""
    verifier = "verifier-verifier"
    login_resp = client.post(
        "/login",
        data={"username": "alice@example.com", "password": "password", "next": "/"},
        follow_redirects=False,
    )
    assert login_resp.status_code == 302

    auth_resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "web-app",
            "redirect_uri": "https://app.example/callback",
            "scope": "openid profile email",
            "nonce": "n-spiked",
            "code_challenge": _s256_challenge(verifier),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert auth_resp.status_code == 302
    code = _redirect_query(auth_resp.headers["location"])["code"][0]

    token_resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://app.example/callback",
            "client_id": "web-app",
            "client_secret": "super-secret",
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200
    return token_resp.json()["id_token"]


def test_end_session_valid_hint_redirects_and_clears_cookie() -> None:
    """Hint valide + URI enregistrée : 302 vers l'URI (state rejoué) + cookie purgé."""
    with TestClient(_app()) as client:
        id_token = _login_and_get_id_token(client)

        response = client.get(
            "/end_session",
            params={
                "id_token_hint": id_token,
                "post_logout_redirect_uri": _POST_LOGOUT_URI,
                "state": "st-1",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"].startswith(_POST_LOGOUT_URI)
    assert _redirect_query(response.headers["location"])["state"] == ["st-1"]
    set_cookie = response.headers.get("set-cookie", "")
    assert "fastapiusersauth" in set_cookie
    assert "Max-Age=0" in set_cookie


def test_end_session_no_args_shows_page_and_clears_cookie() -> None:
    """Sans hint ni URI : page de confirmation HTML, cookie purgé quand même."""
    with TestClient(_app()) as client:
        response = client.get("/end_session", follow_redirects=False)

    assert response.status_code == 200
    assert "déconnecté" in response.text
    assert "fastapiusersauth" in response.headers.get("set-cookie", "")
    assert "Max-Age=0" in response.headers.get("set-cookie", "")


def test_end_session_no_hint_registered_uri_resolved() -> None:
    """Sans hint, l'URI enregistrée est retrouvée dans le registre clients."""
    with TestClient(_app()) as client:
        response = client.get(
            "/end_session",
            params={"post_logout_redirect_uri": _POST_LOGOUT_URI, "state": "st-2"},
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert _redirect_query(response.headers["location"])["state"] == ["st-2"]


def test_end_session_unregistered_uri_rejected() -> None:
    """Hint valide + URI non enregistrée : 400, la session n'est PAS purgée."""
    with TestClient(_app()) as client:
        id_token = _login_and_get_id_token(client)

        response = client.get(
            "/end_session",
            params={
                "id_token_hint": id_token,
                "post_logout_redirect_uri": "https://evil.example/steal",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "invalide" in response.text
    assert "set-cookie" not in response.headers


def test_end_session_forged_hint_rejected() -> None:
    """Hint non signé par le serveur : 400 sans purger la session."""
    with TestClient(_app()) as client:
        response = client.get(
            "/end_session",
            params={
                "id_token_hint": ("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.forged.signature"),
                "post_logout_redirect_uri": _POST_LOGOUT_URI,
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "set-cookie" not in response.headers


def test_end_session_valid_hint_without_uri_shows_page() -> None:
    """Hint valide sans URI : session terminée, page de confirmation, cookie purgé."""
    with TestClient(_app()) as client:
        id_token = _login_and_get_id_token(client)

        response = client.get(
            "/end_session", params={"id_token_hint": id_token}, follow_redirects=False
        )

    assert response.status_code == 200
    assert "déconnecté" in response.text
    assert "fastapiusersauth" in response.headers.get("set-cookie", "")
    assert "Max-Age=0" in response.headers.get("set-cookie", "")


def test_end_session_renders_frontchannel_iframe_with_sid() -> None:
    """Client front-channel enregistré : page avec iframe `?sid=` + cookie purgé."""
    front_client = {
        **_CLIENT_JSON,
        "frontchannel_logout_uri": "https://spa.example/front",
        "frontchannel_logout_session_required": True,
    }
    with TestClient(_app(clients_seed=(front_client,))) as client:
        id_token = _login_and_get_id_token(client)

        response = client.get(
            "/end_session", params={"id_token_hint": id_token}, follow_redirects=False
        )

    assert response.status_code == 200
    assert 'src="https://spa.example/front?sid=' in response.text
    assert 'class="secret"' in response.text
    assert "fastapiusersauth" in response.headers.get("set-cookie", "")
    assert "Max-Age=0" in response.headers.get("set-cookie", "")


def test_end_session_frontchannel_page_redirects_to_registered_uri() -> None:
    """Front-channel + URI enregistrée : page avec iframes et meta-redirect, pas de 302 direct."""
    front_client = {
        **_CLIENT_JSON,
        "frontchannel_logout_uri": "https://spa.example/front",
        "frontchannel_logout_session_required": False,
    }
    with TestClient(_app(clients_seed=(front_client,))) as client:
        id_token = _login_and_get_id_token(client)

        response = client.get(
            "/end_session",
            params={
                "id_token_hint": id_token,
                "post_logout_redirect_uri": _POST_LOGOUT_URI,
                "state": "st-fc",
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert 'src="https://spa.example/front"' in response.text
    assert f"{_POST_LOGOUT_URI}?state=st-fc" in response.text
    assert 'http-equiv="refresh"' in response.text
