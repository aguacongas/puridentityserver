"""Tests de la feature Authorization Code + PKCE (RFC 6749, RFC 7636)."""

import asyncio
import hashlib
from collections.abc import Awaitable
from datetime import datetime, timezone
from typing import TypeVar
from urllib.parse import parse_qs, urlparse

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

    assert response.status_code == 302
    assert _redirect_query(response.headers["location"])["error"] == ["invalid_client"]


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

    assert response.status_code == 302
    query = _redirect_query(response.headers["location"])
    assert query["error"] == ["invalid_redirect_uri"]


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
                "response_type": "code",
                "client_id": "unknown",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid",
                "state": "some-state",
            },
            follow_redirects=False,
        )

    assert response.status_code == 302
    query = _redirect_query(response.headers["location"])
    assert query["error"] == ["invalid_client"]
    assert query["state"] == ["some-state"]


def test_authorize_rejects_unsupported_response_type() -> None:
    with TestClient(_app()) as client:
        response = client.get(
            "/authorize",
            params={
                "response_type": "token",
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


def _authorize_code_ttl(client: Client, server_ttl: int = 600) -> float:
    """Durée de vie effective d'un code émis pour ``client`` (en secondes)."""
    clients = InMemoryClientRepository()
    codes = InMemoryAuthorizationCodeRepository()
    run(clients.save(client))
    usecase = AuthorizeUseCase(AuthorizeConfig(code_ttl_seconds=server_ttl), clients, codes)
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
