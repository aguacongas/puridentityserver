"""Tests de la feature Authorization Code + PKCE (RFC 6749, RFC 7636)."""

import asyncio
import hashlib
from collections.abc import Awaitable
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import TypeVar
from urllib.parse import parse_qs, unquote, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.authorize import (
    AuthorizeConfig,
    AuthorizeRedirect,
    AuthorizeRequest,
    AuthorizeUseCase,
)
from puridentityserver.domain.authorization import Client, Scope
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.persistence.memory.codes import (
    InMemoryAuthorizationCodeRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.interfaces.api import authorize as authorize_api
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_CLIENT_JSON = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
}


def _app(seed: tuple[dict[str, object], ...] | None = None, **settings: object) -> FastAPI:
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=tuple(seed or (_CLIENT_JSON,)),
            **settings,
        )
    )


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    import base64

    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _redirect_query(redirect_url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(redirect_url).query)


def test_authorize_redirects_with_code() -> None:
    settings = Settings(
        issuer=_ISSUER,
        base_url=_ISSUER,
        jwks_algorithms=("RS256",),
        clients_seed=(_CLIENT_JSON,),
    )
    with TestClient(create_app(settings)) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "state": "xyz",
                "code_challenge": _s256_challenge("verifier-verifier"),
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://app.example/callback?")
    query = _redirect_query(location)
    assert query["code"]
    assert query["state"] == ["xyz"]


def test_authorize_redirect_carries_iss_parameter() -> None:
    """RFC 9207 §2.3 : la réponse de succès porte ``iss`` = issuer (F2-1)."""
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "code_challenge": _s256_challenge("verifier-verifier"),
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert _redirect_query(response.headers["location"])["iss"] == [_ISSUER]


def test_authorize_rejects_unknown_client() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "unknown",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid",
            },
            follow_redirects=False,
        )

    # RFC 6749 §4.1.2.1 : un client inconnu interdit toute redirection —
    # la page d'erreur est servie au lieu d'un 302 vers l'URI fournie.
    assert response.status_code == 400
    assert "location" not in response.headers
    assert "invalid_client" in response.text


def test_authorize_rejects_unregistered_redirect_uri() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://evil.example/phish",
                "scope": "openid",
            },
            follow_redirects=False,
        )

    # RFC 6749 §4.1.2.1 : rediriger vers une URI non enregistrée détournerait
    # la réponse — page d'erreur, jamais un 302 (OIDCC-3.1.2.1).
    assert response.status_code == 400
    assert "location" not in response.headers
    assert "invalid_redirect_uri" in response.text


def test_authorize_rejects_missing_openid_scope() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "profile",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert _redirect_query(response.headers["location"])["error"] == ["invalid_scope"]


def test_authorize_rejects_invalid_code_challenge_method() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid",
                "state": "st-1",
                "code_challenge": _s256_challenge("verifier-verifier"),
                "code_challenge_method": "unsupported",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = _redirect_query(response.headers["location"])
    assert query["error"] == ["invalid_request"]
    assert query["state"] == ["st-1"]


def test_authorize_error_redirect_includes_state() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "foo",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid",
                "state": "some-state",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = _redirect_query(response.headers["location"])
    assert query["error"] == ["unsupported_response_type"]
    assert query["state"] == ["some-state"]


def test_authorize_rejects_unsupported_response_type() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "foo",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert _redirect_query(response.headers["location"])["error"] == ["unsupported_response_type"]


def test_token_exchange_issues_id_and_access_tokens() -> None:
    settings = Settings(
        issuer=_ISSUER,
        base_url=_ISSUER,
        jwks_algorithms=("RS256",),
        clients_seed=(_CLIENT_JSON,),
    )
    with TestClient(create_app(settings)) as client:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "nonce": "n-0S6_WzA2Mj",
                "code_challenge": _s256_challenge("verifier-verifier"),
            },
            follow_redirects=False,
        )
        code = _redirect_query(auth.headers["location"])["code"][0]
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example/callback",
                "client_id": "web-app",
                "client_secret": "super-secret",
                "code_verifier": "verifier-verifier",
            },
        )
        payload = response.json()
        assert response.status_code == 200
        assert payload["token_type"] == "Bearer"
        assert payload["expires_in"] == 3600
        assert payload["id_token"]
        assert payload["access_token"]


def test_token_exchange_replays_consumed_code() -> None:
    settings = Settings(
        issuer=_ISSUER,
        base_url=_ISSUER,
        jwks_algorithms=("RS256",),
        clients_seed=(_CLIENT_JSON,),
    )
    with TestClient(create_app(settings)) as client:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid",
                "code_challenge": _s256_challenge("verifier-verifier"),
            },
            follow_redirects=False,
        )
        code = _redirect_query(auth.headers["location"])["code"][0]
        token_kwargs = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://app.example/callback",
            "client_id": "web-app",
            "client_secret": "super-secret",
            "code_verifier": "verifier-verifier",
        }
        first = client.post("/token", data=token_kwargs)
        second = client.post("/token", data=token_kwargs)

    assert first.status_code == 200
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


def test_token_exchange_rejects_wrong_verifier() -> None:
    with TestClient(_app()) as client:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid",
                "code_challenge": _s256_challenge("verifier-verifier"),
            },
            follow_redirects=False,
        )
        code = _redirect_query(auth.headers["location"])["code"][0]
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example/callback",
                "client_id": "web-app",
                "client_secret": "super-secret",
                "code_verifier": "wrong-verifier",
            },
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_token_exchange_rejects_wrong_client_secret() -> None:
    with TestClient(_app()) as client:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid",
            },
            follow_redirects=False,
        )
        code = _redirect_query(auth.headers["location"])["code"][0]
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example/callback",
                "client_id": "web-app",
                "client_secret": "wrong-secret",
            },
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"


def test_token_exchange_rejects_wrong_redirect_uri() -> None:
    with TestClient(_app()) as client:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid",
            },
            follow_redirects=False,
        )
        code = _redirect_query(auth.headers["location"])["code"][0]
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example/other",
                "client_id": "web-app",
                "client_secret": "super-secret",
            },
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_token_rejects_unsupported_grant_type() -> None:
    with TestClient(_app()) as client:
        response = client.post(
            "/token",
            data={
                "grant_type": "password",
                "code": "dummy",
                "redirect_uri": "https://app.example/callback",
                "client_id": "web-app",
                "client_secret": "super-secret",
            },
        )

    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


def test_token_client_credentials_issues_access_token() -> None:
    with TestClient(_app()) as client:
        response = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "web-app",
                "client_secret": "super-secret",
            },
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["access_token"]
    assert body["token_type"] == "Bearer"
    assert body["scope"] == "openid profile"
    assert "id_token" not in body
    assert "refresh_token" not in body


def test_public_client_without_pkce_still_requires_verifier() -> None:
    public = {"client_id": "spa", "redirect_uris": ["https://spa.example/cb"], "scopes": "openid"}
    with TestClient(_app((public,))) as client:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "spa",
                "redirect_uri": "https://spa.example/cb",
                "scope": "openid",
            },
            follow_redirects=False,
        )
        code = _redirect_query(auth.headers["location"])["code"][0]
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://spa.example/cb",
                "client_id": "spa",
            },
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_public_client_with_pkce_succeeds() -> None:
    public = {"client_id": "spa", "redirect_uris": ["https://spa.example/cb"], "scopes": "openid"}
    with TestClient(_app((public,))) as client:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "spa",
                "redirect_uri": "https://spa.example/cb",
                "scope": "openid",
                "code_challenge": _s256_challenge("verifier-verifier"),
            },
            follow_redirects=False,
        )
        code = _redirect_query(auth.headers["location"])["code"][0]
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://spa.example/cb",
                "client_id": "spa",
                "code_verifier": "verifier-verifier",
            },
        )

    assert response.status_code == 200
    assert response.json()["id_token"]


def _authorize_code(app: object, client_id: str, redirect_uri: str) -> str:
    with TestClient(app) as client:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": "openid",
            },
            follow_redirects=False,
        )
        return _redirect_query(auth.headers["location"])["code"][0]


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests unitaires du use case)."""
    return asyncio.run(awaitable)


class _NoopTokenManager:
    """Émetteur de jetons factice : jamais sollicité pour le code flow."""

    async def create_id_token(self, **_kwargs: object) -> str:
        return ""

    async def create_access_token(self, **_kwargs: object) -> str:
        return ""

    async def validate_access_token(self, **_kwargs: object) -> dict[str, object] | None:
        return None


def _authorize_code_ttl(client: Client, server_ttl: int = 600) -> float:
    """Durée de vie effective d'un code émis pour ``client`` (en secondes)."""
    clients = InMemoryClientRepository()
    codes = InMemoryAuthorizationCodeRepository()
    run(clients.save(client))
    usecase = AuthorizeUseCase(
        AuthorizeConfig(code_ttl_seconds=server_ttl),
        clients,
        codes,
        _NoopTokenManager(),
    )
    result = run(
        usecase.execute(
            AuthorizeRequest(
                response_type="code",
                client_id=client.client_id,
                redirect_uri=next(iter(client.redirect_uris)),
                scope="openid",
            )
        )
    )
    assert isinstance(result, AuthorizeRedirect)
    code = run(codes.find_by_code(result.code))
    assert code is not None
    return (code.expires_at - datetime.now(timezone.utc)).total_seconds()


def test_code_lifetime_uses_client_setting() -> None:
    client = Client(
        client_id="web-app",
        redirect_uris=frozenset({"https://app.example/callback"}),
        scopes=frozenset({Scope.OPENID}),
        authorization_code_lifetime_seconds=30,
    )

    delta = _authorize_code_ttl(client)

    assert 28 <= delta <= 32


def test_code_lifetime_defaults_to_server_ttl() -> None:
    client = Client(
        client_id="web-app",
        redirect_uris=frozenset({"https://app.example/callback"}),
        scopes=frozenset({Scope.OPENID}),
    )

    delta = _authorize_code_ttl(client)

    assert 598 <= delta <= 602


def _require_login_app() -> FastAPI:
    """App avec login obligatoire à /authorize + compte seed ``alice``."""
    return _app(
        require_login=True,
        identity_seed_users={"alice": {"email": "alice@example.com", "password": "password"}},
    )


def _authorize_login_params() -> dict[str, str]:
    """Paramètres d'une demande valide (Authorization Code + PKCE)."""
    return {
        "response_type": "code",
        "client_id": "web-app",
        "redirect_uri": "https://app.example/callback",
        "scope": "openid profile",
        "state": "st-auth",
        "code_challenge": _s256_challenge("verifier-verifier"),
        "code_challenge_method": "S256",
    }


def test_require_login_redirects_anonymous_to_login_page() -> None:
    with TestClient(_require_login_app()) as client:
        response = client.get(
            "/authorize", params=_authorize_login_params(), follow_redirects=False
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("/login?next=")
    assert "client_id=web-app" in unquote(location)
    assert "state=st-auth" in unquote(location)


def test_require_login_prompt_none_returns_login_required() -> None:
    with TestClient(_require_login_app()) as client:
        response = client.get(
            "/authorize",
            params={**_authorize_login_params(), "prompt": "none"},
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = _redirect_query(response.headers["location"])
    assert query["error"] == ["login_required"]
    assert query["state"] == ["st-auth"]


def test_require_login_issues_code_after_authentication() -> None:
    with TestClient(_require_login_app()) as client:
        login = client.post(
            "/login",
            data={"username": "alice@example.com", "password": "password", "next": "/"},
            follow_redirects=False,
        )
        assert login.status_code == 302

        response = client.get(
            "/authorize", params=_authorize_login_params(), follow_redirects=False
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://app.example/callback?")
    assert _redirect_query(location)["state"] == ["st-auth"]


def test_require_login_post_keeps_parameters_in_login_next() -> None:
    """RFC 6749 §4.1.2 note : le POST ne doit pas perdre ses paramètres au login.

    La demande arrive dans le corps form, la redirection vers ``/login`` part
    en query string : sans mémorisation du corps, ``next`` vaut ``/authorize``
    et le retour après connexion produit une page d'erreur (warning
    ``oidcc-ensure-post-request-succeeds``).
    """
    with TestClient(_require_login_app()) as client:
        response = client.post(
            "/authorize",
            data=_authorize_login_params(),
            follow_redirects=False,
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("/login?next=")
    target = urlparse(_redirect_query(location)["next"][0])
    assert (target.scheme, target.netloc, target.path) == ("https", "id.example", "/authorize")
    assert "client_id=web-app" in target.query
    assert "state=st-auth" in target.query


def test_require_login_post_issues_code_after_authentication() -> None:
    """Le POST d'un utilisateur anonyme finit sur le callback après connexion."""
    with TestClient(_require_login_app()) as client:
        post = client.post(
            "/authorize",
            data=_authorize_login_params(),
            follow_redirects=False,
        )
        assert post.status_code == 302
        next_target = _redirect_query(post.headers["location"])["next"][0]

        login = client.post(
            "/login",
            data={
                "username": "alice@example.com",
                "password": "password",
                "next": next_target,
            },
            follow_redirects=False,
        )
        assert login.status_code == 302
        assert login.headers["location"] == next_target

        # Même hôte que la session : `next` porte l'autorité explicite, la
        # suite rejoue en chemin relatif (le cookie de session la suit).
        target = urlparse(next_target)
        response = client.get(
            f"{target.path}?{target.query}" if target.query else target.path,
            follow_redirects=False,
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://app.example/callback?")
    assert _redirect_query(location)["state"] == ["st-auth"]


def _advance_clock(monkeypatch: pytest.MonkeyPatch, seconds: float) -> None:
    """Simule une latence ``/login`` → ``/authorize`` de ``seconds`` secondes.

    Seule l'horloge vue par le contrôle ``max_age`` de l'API authorize est
    décalée : ``auth_time`` (posé au login) garde l'heure réelle, l'écart
    mesuré à l'autorisation vaut donc ``seconds``.
    """
    real_time = authorize_api.time.time
    monkeypatch.setattr(
        authorize_api,
        "time",
        SimpleNamespace(time=lambda: real_time() + seconds),
    )


def test_max_age_expired_on_unrelated_session_reprompts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``max_age=1`` dépassé sur une session d'une autre URL : reconnexion."""
    with TestClient(_require_login_app()) as client:
        login = client.post(
            "/login",
            data={"username": "alice@example.com", "password": "password", "next": "/"},
            follow_redirects=False,
        )
        assert login.status_code == 302
        _advance_clock(monkeypatch, 5)

        response = client.get(
            "/authorize",
            params={**_authorize_login_params(), "max_age": "1"},
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"].startswith("/login?next=")


def test_max_age_fresh_session_does_not_reprompt() -> None:
    """``max_age=1`` non dépassé : le code est émis sans reconnexion."""
    with TestClient(_require_login_app()) as client:
        login = client.post(
            "/login",
            data={"username": "alice@example.com", "password": "password", "next": "/"},
            follow_redirects=False,
        )
        assert login.status_code == 302

        response = client.get(
            "/authorize",
            params={**_authorize_login_params(), "max_age": "1"},
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"].startswith("https://app.example/callback?")


def test_max_age_expired_login_for_this_request_does_not_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#137 : le login déclenché par la demande valide un ``max_age>0`` expiré.

    Sans l'anti-boucle, la latence simulée (5 s > ``max_age=1``) rendrait
    chaque relogin suivi d'un ``/authorize`` déjà trop vieux : boucle
    infinie (module ``oidcc-max-age-1`` de la suite de certification).
    """
    with TestClient(_require_login_app()) as client:
        first = client.get(
            "/authorize",
            params={**_authorize_login_params(), "max_age": "1"},
            follow_redirects=False,
        )
        assert first.status_code == 302
        assert first.headers["location"].startswith("/login?next=")
        next_target = _redirect_query(first.headers["location"])["next"][0]
        _advance_clock(monkeypatch, 5)

        login = client.post(
            "/login",
            data={
                "username": "alice@example.com",
                "password": "password",
                "next": next_target,
            },
            follow_redirects=False,
        )
        assert login.status_code == 302

        target = urlparse(next_target)
        response = client.get(
            f"{target.path}?{target.query}",
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"].startswith("https://app.example/callback?")


def test_authorize_post_issues_code_for_authenticated_user() -> None:
    """``POST /authorize`` d'un utilisateur déjà connecté part au callback."""
    with TestClient(_require_login_app()) as client:
        login = client.post(
            "/login",
            data={"username": "alice@example.com", "password": "password", "next": "/"},
            follow_redirects=False,
        )
        assert login.status_code == 302

        response = client.post(
            "/authorize",
            data=_authorize_login_params(),
            follow_redirects=False,
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://app.example/callback?")
    assert _redirect_query(location)["state"] == ["st-auth"]
