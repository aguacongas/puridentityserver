"""Tests de la feature Introspection (RFC 7662) : use case + endpoint /introspect."""

import asyncio
import hashlib
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from typing import TypeVar

from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.introspect import (
    IntrospectConfig,
    IntrospectError,
    IntrospectRequest,
    IntrospectResponse,
    IntrospectUseCase,
)
from puridentityserver.domain.authorization import Client, ClientType, Scope
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.domain.revocation import RevokedToken, token_hash
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.memory.revoked_tokens import (
    InMemoryRevokedTokenRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_CLIENT_SECRET = "super-secret"

_GARBAGE = "garbage"

_WRONG_SECRET = "wrong"

_CLIENT_JSON = {
    "client_id": "web-app",
    "client_secret": _CLIENT_SECRET,
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
}

_CONFIDENTIAL_CLIENT = Client(
    client_id="web-app",
    redirect_uris=frozenset({"https://app.example/callback"}),
    scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
    client_type=ClientType.CONFIDENTIAL,
    client_secret_hash=hashlib.sha256(_CLIENT_SECRET.encode("utf-8")).hexdigest(),
)

_PUBLIC_CLIENT = Client(
    client_id="spa",
    redirect_uris=frozenset({"https://spa.example/cb"}),
    scopes=frozenset({Scope.OPENID}),
    client_type=ClientType.PUBLIC,
)


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


def _make_usecase(
    client: Client | None = None,
    key_manager: DefaultKeyManager | None = None,
) -> tuple[IntrospectUseCase, PyJWTTokenManager]:
    """Construit un IntrospectUseCase avec des repos et clés en mémoire."""
    clients = InMemoryClientRepository()
    km = key_manager or DefaultKeyManager(InMemoryKeyPairRepository())
    token_manager = PyJWTTokenManager(km)
    run(clients.save(client or _CONFIDENTIAL_CLIENT))
    usecase = IntrospectUseCase(
        IntrospectConfig(issuer=_ISSUER), clients, token_manager, InMemoryRevokedTokenRepository()
    )
    return usecase, token_manager


def _access_token(
    token_manager: PyJWTTokenManager,
    *,
    subject: str = "alice",
    issuer: str = _ISSUER,
) -> str:
    """Émet un access_token signé par ``token_manager``."""
    return run(
        token_manager.create_access_token(
            algorithm=JWTAlgorithm.RS256,
            issuer=issuer,
            subject=subject,
            audience="web-app",
            expires_at=9999999999,
            issued_at=1000000000,
            scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
        )
    )


def _introspect(
    usecase: IntrospectUseCase,
    token: str,
    *,
    client_id: str = "web-app",
    secret: str = _CLIENT_SECRET,
) -> IntrospectResponse | IntrospectError:
    """Exécute l'introspection via le client confidentiel par défaut."""
    request = IntrospectRequest(token=token, client_id=client_id, client_secret=secret)
    return run(usecase.execute(request))


class TestIntrospectUseCase:
    """Couvre les branches de IntrospectUseCase.execute."""

    def test_returns_active_claims_for_valid_token(self) -> None:
        uc, tm = _make_usecase()
        token = _access_token(tm)

        result = _introspect(uc, token)

        assert isinstance(result, IntrospectResponse)
        assert result.active is True
        assert result.claims["sub"] == "alice"
        assert result.claims["aud"] == "web-app"
        assert result.claims["client_id"] == "web-app"
        assert result.claims["username"] == "alice"
        assert result.claims["iss"] == _ISSUER
        assert result.claims["scope"] == "openid profile"
        assert result.claims["token_type"] == "Bearer"
        assert result.claims["iat"] < result.claims["exp"]

    def test_returns_inactive_for_unknown_token(self) -> None:
        uc, _ = _make_usecase()

        result = _introspect(uc, _GARBAGE)

        assert isinstance(result, IntrospectResponse)
        assert result.active is False
        assert result.claims == {}

    def test_returns_inactive_for_wrong_issuer(self) -> None:
        uc, tm = _make_usecase()
        token = _access_token(tm, issuer="https://other.example")

        result = _introspect(uc, token)

        assert isinstance(result, IntrospectResponse)
        assert result.active is False

    def test_rejects_unknown_client(self) -> None:
        uc, tm = _make_usecase()
        token = _access_token(tm)

        result = _introspect(uc, token, client_id="ghost")

        assert isinstance(result, IntrospectError)
        assert result.error == "invalid_client"
        assert result.status_code == 401

    def test_rejects_wrong_secret(self) -> None:
        uc, tm = _make_usecase()
        token = _access_token(tm)

        result = _introspect(uc, token, secret=_WRONG_SECRET)

        assert isinstance(result, IntrospectError)
        assert result.error == "invalid_client"

    def test_rejects_inactive_client(self) -> None:
        import dataclasses

        inactive = dataclasses.replace(_CONFIDENTIAL_CLIENT, is_active=False)
        uc, tm = _make_usecase(inactive)
        token = _access_token(tm)

        result = _introspect(uc, token)

        assert isinstance(result, IntrospectError)
        assert result.error == "invalid_client"

    def test_rejects_public_client_caller(self) -> None:
        uc, tm = _make_usecase(_PUBLIC_CLIENT)
        token = _access_token(tm)

        result = _introspect(uc, token, client_id="spa", secret="")

        assert isinstance(result, IntrospectError)
        assert result.error == "invalid_client"

    def test_rejects_missing_token(self) -> None:
        uc, _ = _make_usecase()

        result = _introspect(uc, "")

        assert isinstance(result, IntrospectError)
        assert result.error == "invalid_request"
        assert result.status_code == 400

    def test_returns_inactive_for_token_signed_with_foreign_keys(self) -> None:
        signer_km = DefaultKeyManager(InMemoryKeyPairRepository())
        signer = PyJWTTokenManager(signer_km)
        token = _access_token(signer)

        uc, _ = _make_usecase()
        result = _introspect(uc, token)

        assert isinstance(result, IntrospectResponse)
        assert result.active is False

    def test_returns_inactive_for_revoked_token(self) -> None:
        blacklist = InMemoryRevokedTokenRepository()
        km = DefaultKeyManager(InMemoryKeyPairRepository())
        tm = PyJWTTokenManager(km)
        token = _access_token(tm)
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        run(blacklist.save(RevokedToken(token_hash=token_hash(token), expires_at=expires)))
        clients = InMemoryClientRepository()
        run(clients.save(_CONFIDENTIAL_CLIENT))
        uc = IntrospectUseCase(IntrospectConfig(issuer=_ISSUER), clients, tm, blacklist)

        result = _introspect(uc, token)

        assert isinstance(result, IntrospectResponse)
        assert result.active is False


class TestIntrospectEndpoint:
    """Couvre l'endpoint HTTP ``POST /introspect`` (RFC 7662)."""

    def _app(self) -> FastAPI:
        return create_app(
            Settings(
                issuer=_ISSUER,
                base_url=_ISSUER,
                jwks_algorithms=("RS256",),
                clients_seed=(_CLIENT_JSON,),
            )
        )

    def _access_token(self, client: TestClient) -> str:
        from urllib.parse import parse_qs, urlparse

        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
            },
            follow_redirects=False,
        )
        code = parse_qs(urlparse(auth.headers["location"]).query)["code"][0]
        response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example/callback",
                "client_id": "web-app",
                "client_secret": _CLIENT_SECRET,
            },
        )
        return str(response.json()["access_token"])

    def test_returns_active_for_valid_token(self) -> None:
        with TestClient(self._app()) as client:
            token = self._access_token(client)
            response = client.post(
                "/introspect",
                data={"token": token, "client_id": "web-app", "client_secret": _CLIENT_SECRET},
            )

        assert response.status_code == 200
        body = response.json()
        assert body["active"] is True
        assert body["client_id"] == "web-app"
        assert body["iss"] == _ISSUER
        assert body["token_type"] == "Bearer"

    def test_returns_inactive_for_invalid_token(self) -> None:
        with TestClient(self._app()) as client:
            response = client.post(
                "/introspect",
                data={"token": _GARBAGE, "client_id": "web-app", "client_secret": _CLIENT_SECRET},
            )

        assert response.status_code == 200
        assert response.json() == {"active": False}

    def test_rejects_wrong_secret(self) -> None:
        with TestClient(self._app()) as client:
            response = client.post(
                "/introspect",
                data={"token": _GARBAGE, "client_id": "web-app", "client_secret": "wrong"},
            )

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"

    def test_rejects_missing_client_credentials(self) -> None:
        with TestClient(self._app()) as client:
            response = client.post("/introspect", data={"token": _GARBAGE, "client_id": "ghost"})

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"

    def test_rejects_empty_token(self) -> None:
        with TestClient(self._app()) as client:
            response = client.post(
                "/introspect",
                data={"token": "", "client_id": "web-app", "client_secret": _CLIENT_SECRET},
            )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_discovery_advertises_introspection_endpoint(self) -> None:
        with TestClient(self._app()) as client:
            metadata = client.get("/.well-known/openid-configuration").json()

        assert metadata["introspection_endpoint"] == f"{_ISSUER}/introspect"
