"""Tests du Device Authorization Grant (RFC 8628)."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar

from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.device_authorize import (
    DeviceAuthorizationError,
    DeviceAuthorizationRequest,
    DeviceAuthorizationResult,
    DeviceAuthorizationUseCase,
    DeviceConfig,
)
from puridentityserver.application.token import (
    TokenConfig,
    TokenError,
    TokenRequest,
    TokenResponse,
    TokenUseCase,
)
from puridentityserver.domain.authorization import (
    Client,
    ClientType,
    DeviceAuthorization,
    DeviceAuthorizationStatus,
    Scope,
    format_user_code,
    normalize_user_code,
)
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.domain.revocation import token_hash
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.factory import (
    build_device_authorization_repository,
)
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.persistence.memory.codes import (
    InMemoryAuthorizationCodeRepository,
)
from puridentityserver.infrastructure.persistence.memory.device_authorizations import (
    InMemoryDeviceAuthorizationRepository,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.memory.refresh_tokens import (
    InMemoryRefreshTokenRepository,
)
from puridentityserver.infrastructure.persistence.sql.device_authorizations import (
    SQLDeviceAuthorizationRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_CLIENT_SECRET = "super-secret"
_CLIENT_ID = "device-app"

_IDENTITY_SEED = {
    "alice": {"email": "alice@example.com", "password": "password"},
}

_CONFIDENTIAL_CLIENT = Client(
    client_id="web-app",
    redirect_uris=frozenset({"https://app.example/callback"}),
    scopes=frozenset({Scope.OPENID}),
    client_type=ClientType.CONFIDENTIAL,
    client_secret_hash=hashlib.sha256(_CLIENT_SECRET.encode("utf-8")).hexdigest(),
)

_PUBLIC_CLIENT = Client(
    client_id=_CLIENT_ID,
    scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
    client_type=ClientType.PUBLIC,
)


def run(awaitable: Awaitable[_T]) -> _T:
    return asyncio.run(awaitable)


def _future_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=10)


def _make_usecase(
    client: Client | None = None,
    key_manager: DefaultKeyManager | None = None,
) -> tuple[
    DeviceAuthorizationUseCase,
    InMemoryDeviceAuthorizationRepository,
    TokenUseCase,
]:
    clients = InMemoryClientRepository()
    device_codes = InMemoryDeviceAuthorizationRepository()
    km = key_manager or DefaultKeyManager(InMemoryKeyPairRepository())
    token_manager = PyJWTTokenManager(km)
    config = DeviceConfig(
        issuer=_ISSUER,
        base_url=_ISSUER,
        ttl_seconds=600,
        interval_seconds=5,
    )
    device_uc = DeviceAuthorizationUseCase(config, clients, device_codes)
    token_uc = TokenUseCase(
        TokenConfig(issuer=_ISSUER, signing_algorithm=JWTAlgorithm.RS256),
        clients,
        InMemoryAuthorizationCodeRepository(),
        token_manager,
        InMemoryRefreshTokenRepository(),
        device_codes,
    )
    resolved = client or _PUBLIC_CLIENT
    run(clients.save(resolved))
    return device_uc, device_codes, token_uc


def _app(**settings: object) -> FastAPI:
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(
                {
                    "client_id": _CLIENT_ID,
                    "scopes": "openid profile",
                    "client_type": "public",
                },
            ),
            identity_seed_users=_IDENTITY_SEED,
            **settings,
        )
    )


class TestDeviceAuthorizationUseCaseUnit:
    """Tests unitaires de DeviceAuthorizationUseCase."""

    def test_rejects_unknown_client(self) -> None:
        uc, _, _ = _make_usecase()
        result = run(uc.execute(DeviceAuthorizationRequest(client_id="unknown")))
        assert isinstance(result, DeviceAuthorizationError)
        assert result.error == "invalid_client"

    def test_rejects_inactive_client(self) -> None:
        from dataclasses import replace

        clients = InMemoryClientRepository()
        device_codes = InMemoryDeviceAuthorizationRepository()
        uc = DeviceAuthorizationUseCase(DeviceConfig(issuer=_ISSUER), clients, device_codes)
        inactive = replace(_PUBLIC_CLIENT, is_active=False)
        run(clients.save(inactive))
        result = run(uc.execute(DeviceAuthorizationRequest(client_id=_CLIENT_ID)))
        assert isinstance(result, DeviceAuthorizationError)
        assert result.error == "invalid_client"

    def test_rejects_bad_secret_for_confidential(self) -> None:
        uc, _, _ = _make_usecase(_CONFIDENTIAL_CLIENT)
        result = run(
            uc.execute(DeviceAuthorizationRequest(client_id="web-app", client_secret="wrong"))
        )
        assert isinstance(result, DeviceAuthorizationError)
        assert result.error == "invalid_client"

    def test_rejects_out_of_scope(self) -> None:
        uc, _, _ = _make_usecase()
        result = run(
            uc.execute(
                DeviceAuthorizationRequest(client_id=_CLIENT_ID, scope="openid email address")
            )
        )
        assert isinstance(result, DeviceAuthorizationError)
        assert result.error == "invalid_scope"

    def test_issues_device_code_and_user_code(self) -> None:
        uc, _, _ = _make_usecase()
        result = run(uc.execute(DeviceAuthorizationRequest(client_id=_CLIENT_ID, scope="openid")))
        assert isinstance(result, DeviceAuthorizationResult)
        assert len(result.device_code) > 20
        assert len(result.user_code) == 9  # "WDJB-MJHT"
        assert result.user_code[4] == "-"
        assert result.expires_in == 600
        assert result.interval == 5
        assert result.verification_uri == f"{_ISSUER}/device"

    def test_approve_sets_subject(self) -> None:
        uc, repos, _ = _make_usecase()
        res = run(uc.execute(DeviceAuthorizationRequest(client_id=_CLIENT_ID)))
        assert isinstance(res, DeviceAuthorizationResult)
        decision = run(uc.approve(res.user_code, "alice-sub"))
        assert decision.accepted is True
        assert "autorisé" in decision.message
        stored = run(repos.find_by_device_code_hash(token_hash(res.device_code)))
        assert stored is not None
        assert stored.status == DeviceAuthorizationStatus.APPROVED
        assert stored.subject == "alice-sub"

    def test_deny_sets_status(self) -> None:
        uc, repos, _ = _make_usecase()
        res = run(uc.execute(DeviceAuthorizationRequest(client_id=_CLIENT_ID)))
        assert isinstance(res, DeviceAuthorizationResult)
        decision = run(uc.deny(res.user_code))
        assert decision.accepted is True
        assert "refusé" in decision.message
        stored = run(repos.find_by_device_code_hash(token_hash(res.device_code)))
        assert stored is not None
        assert stored.status == DeviceAuthorizationStatus.DENIED

    def test_approve_rejects_unknown_code(self) -> None:
        uc, _, _ = _make_usecase()
        decision = run(uc.approve("XXXX-XXXX", "sub"))
        assert decision.accepted is False
        assert "Code inconnu" in decision.message

    def test_approve_rejects_expired_code(self) -> None:
        uc, repos, _ = _make_usecase()
        res = run(uc.execute(DeviceAuthorizationRequest(client_id=_CLIENT_ID)))
        assert isinstance(res, DeviceAuthorizationResult)
        expired = DeviceAuthorization(
            device_code_hash=token_hash(res.device_code),
            user_code=normalize_user_code(res.user_code),
            client_id=_CLIENT_ID,
            scopes=frozenset({Scope.OPENID}),
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        run(repos.save(expired))
        decision = run(uc.approve(res.user_code, "sub"))
        assert decision.accepted is False
        assert "expiré" in decision.message

    def test_approve_rejects_already_approved(self) -> None:
        uc, _, _ = _make_usecase()
        res = run(uc.execute(DeviceAuthorizationRequest(client_id=_CLIENT_ID)))
        assert isinstance(res, DeviceAuthorizationResult)
        run(uc.approve(res.user_code, "first-sub"))
        decision = run(uc.approve(res.user_code, "second-sub"))
        assert decision.accepted is False
        assert "déjà autorisé" in decision.message

    def test_deny_rejects_already_approved(self) -> None:
        uc, _, _ = _make_usecase()
        res = run(uc.execute(DeviceAuthorizationRequest(client_id=_CLIENT_ID)))
        assert isinstance(res, DeviceAuthorizationResult)
        run(uc.approve(res.user_code, "sub"))
        decision = run(uc.deny(res.user_code))
        assert decision.accepted is False
        assert "déjà autorisé" in decision.message


class TestDeviceTokenGrant:
    """Tests du poll device_code dans TokenUseCase."""

    def test_rejects_missing_device_code(self) -> None:
        _, _, token_uc = _make_usecase()
        result = run(
            token_uc.execute(
                TokenRequest(
                    grant_type="urn:ietf:params:oauth:grant-type:device_code",
                    client_id=_CLIENT_ID,
                )
            )
        )
        assert isinstance(result, TokenError)
        assert result.error == "invalid_grant"
        assert "Paramètre device_code manquant" in result.error_description

    def test_rejects_unknown_device_code(self) -> None:
        _, _, token_uc = _make_usecase()
        result = run(
            token_uc.execute(
                TokenRequest(
                    grant_type="urn:ietf:params:oauth:grant-type:device_code",
                    client_id=_CLIENT_ID,
                    device_code="unknown-value",
                )
            )
        )
        assert isinstance(result, TokenError)
        assert result.error == "invalid_grant"
        assert "invalide ou d'un autre client" in result.error_description

    def test_rejects_expired_token(self) -> None:
        device_uc, device_codes, token_uc = _make_usecase()
        res = run(device_uc.execute(DeviceAuthorizationRequest(client_id=_CLIENT_ID)))
        assert isinstance(res, DeviceAuthorizationResult)
        run(
            device_codes.save(
                DeviceAuthorization(
                    device_code_hash=token_hash(res.device_code),
                    user_code=normalize_user_code(res.user_code),
                    client_id=_CLIENT_ID,
                    scopes=frozenset({Scope.OPENID}),
                    expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),
                )
            )
        )
        result = run(
            token_uc.execute(
                TokenRequest(
                    grant_type="urn:ietf:params:oauth:grant-type:device_code",
                    client_id=_CLIENT_ID,
                    device_code=res.device_code,
                )
            )
        )
        assert isinstance(result, TokenError)
        assert result.error == "expired_token"

    def test_returns_access_denied(self) -> None:
        device_uc, _device_codes, token_uc = _make_usecase()
        res = run(device_uc.execute(DeviceAuthorizationRequest(client_id=_CLIENT_ID)))
        assert isinstance(res, DeviceAuthorizationResult)
        run(device_uc.deny(res.user_code))
        result = run(
            token_uc.execute(
                TokenRequest(
                    grant_type="urn:ietf:params:oauth:grant-type:device_code",
                    client_id=_CLIENT_ID,
                    device_code=res.device_code,
                )
            )
        )
        assert isinstance(result, TokenError)
        assert result.error == "access_denied"

    def test_returns_authorization_pending(self) -> None:
        device_uc, _device_codes, token_uc = _make_usecase()
        res = run(device_uc.execute(DeviceAuthorizationRequest(client_id=_CLIENT_ID)))
        assert isinstance(res, DeviceAuthorizationResult)
        result = run(
            token_uc.execute(
                TokenRequest(
                    grant_type="urn:ietf:params:oauth:grant-type:device_code",
                    client_id=_CLIENT_ID,
                    device_code=res.device_code,
                )
            )
        )
        assert isinstance(result, TokenError)
        assert result.error == "authorization_pending"

    def test_returns_slow_down_on_rapid_polls(self) -> None:
        device_uc, device_codes, token_uc = _make_usecase()
        res = run(device_uc.execute(DeviceAuthorizationRequest(client_id=_CLIENT_ID)))
        assert isinstance(res, DeviceAuthorizationResult)
        # First poll — pending
        r1 = run(
            token_uc.execute(
                TokenRequest(
                    grant_type="urn:ietf:params:oauth:grant-type:device_code",
                    client_id=_CLIENT_ID,
                    device_code=res.device_code,
                )
            )
        )
        assert isinstance(r1, TokenError)
        assert r1.error == "authorization_pending"
        # Second immediate poll — slow_down
        r2 = run(
            token_uc.execute(
                TokenRequest(
                    grant_type="urn:ietf:params:oauth:grant-type:device_code",
                    client_id=_CLIENT_ID,
                    device_code=res.device_code,
                )
            )
        )
        assert isinstance(r2, TokenError)
        assert r2.error == "slow_down"
        # Interval should have increased
        stored = run(device_codes.find_by_device_code_hash(token_hash(res.device_code)))
        assert stored is not None
        assert stored.interval == 10

    def test_issues_tokens_on_approved(self) -> None:
        device_uc, _, token_uc = _make_usecase()
        res = run(device_uc.execute(DeviceAuthorizationRequest(client_id=_CLIENT_ID)))
        assert isinstance(res, DeviceAuthorizationResult)
        run(device_uc.approve(res.user_code, "user-sub"))
        result = run(
            token_uc.execute(
                TokenRequest(
                    grant_type="urn:ietf:params:oauth:grant-type:device_code",
                    client_id=_CLIENT_ID,
                    device_code=res.device_code,
                )
            )
        )
        assert isinstance(result, TokenResponse)
        assert result.access_token
        assert result.id_token
        assert result.scope == "openid profile"


class TestDeviceCodeRepositories:
    """Round-trip mémoire et SQL du repository DeviceAuthorization."""

    def test_memory_round_trip(self) -> None:
        repo = InMemoryDeviceAuthorizationRepository()
        session = DeviceAuthorization(
            device_code_hash="h1",
            user_code="ABCDEF12",
            client_id=_CLIENT_ID,
            scopes=frozenset({Scope.OPENID}),
            expires_at=_future_expiry(),
        )
        run(repo.save(session))
        found = run(repo.find_by_device_code_hash("h1"))
        assert found is not None
        assert found.user_code == "ABCDEF12"

        by_uc = run(repo.find_by_user_code("ABCDEF12"))
        assert by_uc is not None
        assert by_uc.device_code_hash == "h1"

        run(repo.approve("h1", "subject-1"))
        approved = run(repo.find_by_device_code_hash("h1"))
        assert approved is not None
        assert approved.status == DeviceAuthorizationStatus.APPROVED
        assert approved.subject == "subject-1"

        run(repo.deny("h1"))
        denied = run(repo.find_by_device_code_hash("h1"))
        assert denied is not None
        assert denied.status == DeviceAuthorizationStatus.DENIED

        run(repo.delete("h1"))
        assert run(repo.find_by_device_code_hash("h1")) is None

    def test_sql_round_trip(self, tmp_path: Path) -> None:
        db = tmp_path / "device.db"
        repo = SQLDeviceAuthorizationRepository(f"sqlite+aiosqlite:///{db}")
        run(repo.initialise())
        session = DeviceAuthorization(
            device_code_hash="sql-h1",
            user_code="XYZW7890",
            client_id=_CLIENT_ID,
            scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
            expires_at=_future_expiry(),
            interval=10,
        )
        run(repo.save(session))
        found = run(repo.find_by_device_code_hash("sql-h1"))
        assert found is not None
        assert found.user_code == "XYZW7890"
        assert found.interval == 10
        assert found.scopes == frozenset({Scope.OPENID, Scope.PROFILE})

        by_uc = run(repo.find_by_user_code("XYZW7890"))
        assert by_uc is not None

        run(repo.approve("sql-h1", "sql-subject"))
        approved = run(repo.find_by_device_code_hash("sql-h1"))
        assert approved is not None
        assert approved.status == DeviceAuthorizationStatus.APPROVED
        assert approved.subject == "sql-subject"

        run(repo.deny("sql-h1"))
        denied = run(repo.find_by_device_code_hash("sql-h1"))
        assert denied.status == DeviceAuthorizationStatus.DENIED

        run(repo.delete("sql-h1"))
        assert run(repo.find_by_device_code_hash("sql-h1")) is None
        run(repo.close())

    def test_factory_memory(self) -> None:
        repo = build_device_authorization_repository(Settings(storage_type="memory"))
        assert isinstance(repo, InMemoryDeviceAuthorizationRepository)

    def test_factory_sql(self, tmp_path: Path) -> None:
        db = tmp_path / "factory.db"
        repo = build_device_authorization_repository(
            Settings(storage_type="sql", storage_dsn=f"sqlite+aiosqlite:///{db}")
        )
        assert isinstance(repo, SQLDeviceAuthorizationRepository)


class TestUserCodesHelpers:
    """Tests des helpers de formatage de code utilisateur."""

    def test_normalize_removes_separators(self) -> None:
        assert normalize_user_code("wdjb-mjht") == "WDJBMJHT"
        assert normalize_user_code("WDJB MJHT ") == "WDJBMJHT"
        assert normalize_user_code("wdjbmjht") == "WDJBMJHT"

    def test_format_user_code_adds_dash(self) -> None:
        assert format_user_code("WDJBMJHT") == "WDJB-MJHT"


class TestDeviceIntegrationHTTP:
    """Tests d'intégration HTTP du flow device (TestClient FastAPI)."""

    def test_full_flow_approve_and_tokens(self) -> None:
        with TestClient(_app()) as client:
            resp = client.post("/device_authorization", data={"client_id": _CLIENT_ID})
            assert resp.status_code == 200
            data = resp.json()
            user_code = data["user_code"]
            device_code = data["device_code"]

            login = client.post(
                "/login",
                data={
                    "username": "alice@example.com",
                    "password": "password",
                    "next": "/device",
                    "client_id": _CLIENT_ID,
                },
                follow_redirects=True,
            )
            assert login.status_code == 200

            decision = client.post(
                "/device",
                data={"user_code": user_code, "action": "authorize"},
            )
            assert decision.status_code == 200
            assert "autorisé" in decision.text

            resp = client.post(
                "/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": _CLIENT_ID,
                },
            )
            assert resp.status_code == 200
            body = resp.json()
            assert "access_token" in body
            assert "id_token" in body

    def test_full_flow_deny_and_poll_denied(self) -> None:
        with TestClient(_app()) as client:
            resp = client.post("/device_authorization", data={"client_id": _CLIENT_ID})
            assert resp.status_code == 200
            data = resp.json()
            user_code = data["user_code"]
            device_code = data["device_code"]

            client.post(
                "/login",
                data={
                    "username": "alice@example.com",
                    "password": "password",
                    "next": "/device",
                    "client_id": _CLIENT_ID,
                },
                follow_redirects=True,
            )
            decision = client.post(
                "/device",
                data={"user_code": user_code, "action": "deny"},
            )
            assert decision.status_code == 200
            assert "refusé" in decision.text

            resp = client.post(
                "/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": _CLIENT_ID,
                },
            )
            assert resp.status_code == 400
            assert resp.json()["error"] == "access_denied"

    def test_slow_down_on_rapid_poll(self) -> None:
        with TestClient(_app()) as client:
            resp = client.post("/device_authorization", data={"client_id": _CLIENT_ID})
            assert resp.status_code == 200
            device_code = resp.json()["device_code"]

            # First poll — pending
            r1 = client.post(
                "/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": _CLIENT_ID,
                },
            )
            assert r1.status_code == 400
            assert r1.json()["error"] == "authorization_pending"

            # Immediate second poll — slow_down
            r2 = client.post(
                "/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": _CLIENT_ID,
                },
            )
            assert r2.status_code == 400
            assert r2.json()["error"] == "slow_down"
