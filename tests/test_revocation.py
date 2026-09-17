"""Tests de la feature Révocation (RFC 7009) : use case + endpoint + denylist."""

import asyncio
import hashlib
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.revocation import (
    RevocationConfig,
    RevocationError,
    RevocationRequest,
    RevocationSuccess,
    RevocationUseCase,
)
from puridentityserver.domain.authorization import Client, ClientType, Scope
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.domain.revocation import RevokedToken, token_hash
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.factory import (
    build_revoked_token_repository,
)
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.memory.revoked_tokens import (
    InMemoryRevokedTokenRepository,
)
from puridentityserver.infrastructure.persistence.sql.revoked_tokens import (
    SQLRevokedTokenRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_CLIENT_SECRET = "super-secret"

_WRONG_SECRET = "wrong-secret"

_UNKNOWN_TOKEN = "token-inconnu"

_KEPT_HASH = "hash-conserve"

_EXPIRED_HASH = "hash-expiree"

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
) -> tuple[RevocationUseCase, PyJWTTokenManager, InMemoryRevokedTokenRepository]:
    """Construit un RevocationUseCase avec des repos et clés en mémoire."""
    clients = InMemoryClientRepository()
    blacklist = InMemoryRevokedTokenRepository()
    km = DefaultKeyManager(InMemoryKeyPairRepository())
    token_manager = PyJWTTokenManager(km)
    run(clients.save(client or _CONFIDENTIAL_CLIENT))
    usecase = RevocationUseCase(RevocationConfig(issuer=_ISSUER), clients, token_manager, blacklist)
    return usecase, token_manager, blacklist


def _access_token(
    token_manager: PyJWTTokenManager,
    *,
    subject: str = "alice",
    issuer: str = _ISSUER,
    expires_at: int = 9999999999,
) -> str:
    """Émet un access_token signé par ``token_manager``."""
    return run(
        token_manager.create_access_token(
            algorithm=JWTAlgorithm.RS256,
            issuer=issuer,
            subject=subject,
            audience="web-app",
            expires_at=expires_at,
            issued_at=1000000000,
            scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
        )
    )


def _execute(
    usecase: RevocationUseCase,
    token: str,
    *,
    client_id: str = "web-app",
    secret: str = _CLIENT_SECRET,
) -> RevocationSuccess | RevocationError:
    """Exécute la révocation avec les paramètres donnés."""
    request = RevocationRequest(token=token, client_id=client_id, client_secret=secret)
    return run(usecase.execute(request))


class TestRevocationUseCase:
    """Couvre les branches de RevocationUseCase.execute."""

    def test_revokes_valid_token(self) -> None:
        uc, tm, blacklist = _make_usecase()
        token = _access_token(tm)

        result = _execute(uc, token)

        assert isinstance(result, RevocationSuccess)
        assert run(blacklist.is_revoked(token_hash(token))) is True

    def test_revoke_is_idempotent(self) -> None:
        uc, tm, _ = _make_usecase()
        token = _access_token(tm)

        first = _execute(uc, token)
        second = _execute(uc, token)

        assert isinstance(first, RevocationSuccess)
        assert isinstance(second, RevocationSuccess)

    def test_unknown_token_is_silent_success(self) -> None:
        uc, _, blacklist = _make_usecase()

        result = _execute(uc, _UNKNOWN_TOKEN)

        assert isinstance(result, RevocationSuccess)
        assert run(blacklist.is_revoked(token_hash(_UNKNOWN_TOKEN))) is False

    def test_expired_token_is_not_blacklisted(self) -> None:
        uc, tm, blacklist = _make_usecase()
        expired = datetime.now(timezone.utc) - timedelta(minutes=5)
        token = _access_token(tm, expires_at=int(expired.timestamp()))

        result = _execute(uc, token)

        assert isinstance(result, RevocationSuccess)
        assert run(blacklist.is_revoked(token_hash(token))) is False

    def test_rejects_missing_token(self) -> None:
        uc, _, _ = _make_usecase()

        result = _execute(uc, "")

        assert isinstance(result, RevocationError)
        assert result.error == "invalid_request"
        assert result.status_code == 400

    def test_rejects_unknown_client(self) -> None:
        uc, tm, _ = _make_usecase()
        token = _access_token(tm)

        result = _execute(uc, token, client_id="ghost")

        assert isinstance(result, RevocationError)
        assert result.error == "invalid_client"
        assert result.status_code == 401

    def test_rejects_wrong_secret(self) -> None:
        uc, tm, _ = _make_usecase()
        token = _access_token(tm)

        result = _execute(uc, token, secret=_WRONG_SECRET)

        assert isinstance(result, RevocationError)
        assert result.error == "invalid_client"

    def test_rejects_public_client(self) -> None:
        uc, tm, _ = _make_usecase(_PUBLIC_CLIENT)
        token = _access_token(tm)

        result = _execute(uc, token, client_id="spa", secret="")

        assert isinstance(result, RevocationError)
        assert result.error == "invalid_client"

    def test_purge_expired_cleans_denylist(self) -> None:
        uc, tm, blacklist = _make_usecase()
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        run(blacklist.save(RevokedToken(token_hash=_EXPIRED_HASH, expires_at=past)))
        run(blacklist.save(RevokedToken(token_hash=_KEPT_HASH, expires_at=future)))
        token = _access_token(tm)

        result = _execute(uc, token)

        assert isinstance(result, RevocationSuccess)
        assert result.purged == 1
        assert run(blacklist.is_revoked(_EXPIRED_HASH)) is False
        assert run(blacklist.is_revoked(_KEPT_HASH)) is True


class TestRevokeEndpoint:
    """Couvre l'endpoint HTTP ``POST /revoke`` (RFC 7009 §2.2)."""

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

    def _revoke(
        self, client: TestClient, *, value: str, secret: str = _CLIENT_SECRET
    ) -> TestClient:
        return client.post(
            "/revoke",
            data={"token": value, "client_id": "web-app", "client_secret": secret},
        )

    def test_revokes_token_then_introspection_marks_inactive(self) -> None:
        with TestClient(self._app()) as client:
            token = self._access_token(client)
            response = self._revoke(client, value=token)

            assert response.status_code == 200
            assert response.content == b""

            introspection = client.post(
                "/introspect",
                data={"token": token, "client_id": "web-app", "client_secret": _CLIENT_SECRET},
            )

        assert introspection.status_code == 200
        assert introspection.json() == {"active": False}

    def test_unknown_token_returns_empty_200(self) -> None:
        with TestClient(self._app()) as client:
            response = self._revoke(client, value=_UNKNOWN_TOKEN)

        assert response.status_code == 200
        assert response.content == b""

    def test_rejects_wrong_secret(self) -> None:
        with TestClient(self._app()) as client:
            response = self._revoke(client, value=_UNKNOWN_TOKEN, secret=_WRONG_SECRET)

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"

    def test_rejects_empty_token(self) -> None:
        with TestClient(self._app()) as client:
            response = client.post(
                "/revoke",
                data={"token": "", "client_id": "web-app", "client_secret": _CLIENT_SECRET},
            )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_discovery_advertises_revocation_endpoint(self) -> None:
        with TestClient(self._app()) as client:
            metadata = client.get("/.well-known/openid-configuration").json()

        assert metadata["revocation_endpoint"] == f"{_ISSUER}/revoke"
        assert metadata["introspection_endpoint"] == f"{_ISSUER}/introspect"


class TestRevokedTokenRepositories:
    """Couvre les implémentations mémoire et SQL du denylist."""

    def test_memory_round_trip_and_purge(self) -> None:
        repo = InMemoryRevokedTokenRepository()
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        future = datetime.now(timezone.utc) + timedelta(hours=1)

        run(repo.save(RevokedToken(token_hash=_KEPT_HASH, expires_at=future)))
        run(repo.save(RevokedToken(token_hash=_EXPIRED_HASH, expires_at=past)))

        assert run(repo.is_revoked(_KEPT_HASH)) is True
        assert run(repo.is_revoked("absent")) is False
        assert run(repo.purge_expired()) == 1
        assert run(repo.is_revoked(_EXPIRED_HASH)) is False
        assert run(repo.is_revoked(_KEPT_HASH)) is True

    def test_sql_round_trip_and_purge(self, tmp_path: Path) -> None:
        repo = SQLRevokedTokenRepository(f"sqlite+aiosqlite:///{tmp_path / 'revoked.db'}")
        run(repo.initialise())
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        future = datetime.now(timezone.utc) + timedelta(hours=1)

        run(repo.save(RevokedToken(token_hash=_KEPT_HASH, expires_at=future)))
        run(repo.save(RevokedToken(token_hash=_EXPIRED_HASH, expires_at=past)))

        assert run(repo.is_revoked(_KEPT_HASH)) is True
        assert run(repo.is_revoked("absent")) is False
        assert run(repo.purge_expired()) == 1
        assert run(repo.is_revoked(_EXPIRED_HASH)) is False
        assert run(repo.is_revoked(_KEPT_HASH)) is True
        run(repo.close())

    def test_factory_builds_memory(self) -> None:
        repo = build_revoked_token_repository(Settings(storage_type="memory"))

        assert isinstance(repo, InMemoryRevokedTokenRepository)

    def test_factory_builds_sql(self) -> None:
        repo = build_revoked_token_repository(
            Settings(storage_type="sql", storage_dsn="sqlite:///memory")
        )

        assert isinstance(repo, SQLRevokedTokenRepository)

    def test_factory_rejects_unknown_store_type(self) -> None:
        settings = Settings.model_construct(storage_type="cassandra")

        with pytest.raises(ValueError, match="non supporté"):
            build_revoked_token_repository(settings)
