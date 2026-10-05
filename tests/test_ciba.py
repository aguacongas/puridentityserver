"""Tests du Client-Initiated Backchannel Authentication (OIDC CIBA 1.0)."""

from __future__ import annotations

import asyncio
import hashlib
import threading
from collections.abc import Awaitable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar, TypeVar

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.backchannel_authorize import (
    AuthenticationAck,
    BackchannelAuthenticationConfig,
    BackchannelAuthenticationError,
    BackchannelAuthenticationParams,
    BackchannelAuthenticationUseCase,
    CibaApprovalUseCase,
)
from puridentityserver.application.token import (
    TokenConfig,
    TokenError,
    TokenRequest,
    TokenResponse,
    TokenUseCase,
)
from puridentityserver.domain.authorization import (
    CIBA_GRANT_TYPE,
    BackchannelAuthenticationRequest,
    BackchannelAuthenticationStatus,
    Client,
    ClientType,
    Scope,
)
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.domain.revocation import token_hash
from puridentityserver.domain.userinfo import UserClaims
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.factory import (
    build_backchannel_authentication_repository,
)
from puridentityserver.infrastructure.persistence.memory.backchannel_authentications import (
    InMemoryBackchannelAuthenticationRepository,
)
from puridentityserver.infrastructure.persistence.memory.clients import (
    InMemoryClientRepository,
)
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
from puridentityserver.infrastructure.persistence.memory.users import InMemoryUserRepository
from puridentityserver.infrastructure.persistence.sql.backchannel_authentications import (
    SQLBackchannelAuthenticationRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.interfaces.domain.client_assertions import LoginHintTokenResult
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_CLIENT_ID = "ciba-app"
_CLIENT_SECRET = "super-secret"
_USER_SUBJECT = "alice"
_USER_EMAIL = "alice@example.com"
# ``users_seed`` du config.toml (pont identité) : le hint HTTP est résolu
# contre les claims du user store, pas contre le compte de login.
_DEMO_HINT_EMAIL = "alice.martin@example.com"
_NOTIFY_ENDPOINT = "https://rp.example/notify"

_CIBA_CLIENT = Client(
    client_id=_CLIENT_ID,
    scopes=frozenset({Scope.OPENID, Scope.PROFILE, Scope.OFFLINE_ACCESS}),
    client_type=ClientType.CONFIDENTIAL,
    client_secret_hash=hashlib.sha256(_CLIENT_SECRET.encode("utf-8")).hexdigest(),
    backchannel_token_delivery_mode="poll",
)


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine synchrone (les tests ne sont pas async)."""
    return asyncio.run(awaitable)


def _future_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=10)


def _seeded_users() -> InMemoryUserRepository:
    users = InMemoryUserRepository()
    run(
        users.save(
            UserClaims(subject=_USER_SUBJECT, claims={"email": _USER_EMAIL, "name": "Alice"})
        )
    )
    return users


def _params(**kwargs: str) -> BackchannelAuthenticationParams:
    base: dict[str, str] = {
        "client_id": _CLIENT_ID,
        "client_secret": _CLIENT_SECRET,
        "scope": "openid profile",
    }
    base.update(kwargs)
    return BackchannelAuthenticationParams(**base)


def _make_usecase(
    client: Client | None = None,
    *,
    users: InMemoryUserRepository | None = None,
    assertions: object | None = None,
    token_manager: object | None = None,
) -> tuple[
    BackchannelAuthenticationUseCase,
    InMemoryBackchannelAuthenticationRepository,
    TokenUseCase,
    CibaApprovalUseCase,
]:
    clients = InMemoryClientRepository()
    requests = InMemoryBackchannelAuthenticationRepository()
    uc = BackchannelAuthenticationUseCase(
        BackchannelAuthenticationConfig(
            issuer=_ISSUER,
            base_url=_ISSUER,
            ttl_seconds=600,
            interval_seconds=5,
        ),
        clients,
        users or _seeded_users(),
        requests,
        client_assertions=assertions,  # type: ignore[arg-type]
        token_manager=token_manager,  # type: ignore[arg-type]
    )
    token_uc = TokenUseCase(
        TokenConfig(issuer=_ISSUER, signing_algorithm=JWTAlgorithm.RS256),
        clients,
        InMemoryAuthorizationCodeRepository(),
        PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository())),
        InMemoryRefreshTokenRepository(),
        InMemoryDeviceAuthorizationRepository(),
        requests,
    )
    approval = CibaApprovalUseCase(requests)
    run(clients.save(client or _CIBA_CLIENT))
    return uc, requests, token_uc, approval


def _store_request(
    requests: InMemoryBackchannelAuthenticationRepository,
    *,
    auth_req_id: str = "req-1",
    status: BackchannelAuthenticationStatus = BackchannelAuthenticationStatus.PENDING,
    delivery_mode: str = "poll",
    client_id: str = _CLIENT_ID,
    scopes: frozenset[Scope] = frozenset({Scope.OPENID, Scope.PROFILE}),
    expires_in: int = 600,
    interval: int = 5,
    notification_token: str = "",
    notification_endpoint: str = "",
) -> BackchannelAuthenticationRequest:
    stored = BackchannelAuthenticationRequest(
        auth_req_id_hash=token_hash(auth_req_id),
        client_id=client_id,
        scopes=scopes,
        subject=_USER_SUBJECT,
        status=status,
        delivery_mode=delivery_mode,
        client_notification_token=notification_token,
        client_notification_endpoint=notification_endpoint,
        interval=interval,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
    )
    run(requests.save(stored))
    return stored


def _poll(
    token_uc: TokenUseCase, *, auth_req_id: str, client_secret: str = _CLIENT_SECRET
) -> TokenResponse | TokenError:
    return run(
        token_uc.execute(
            TokenRequest(
                grant_type=CIBA_GRANT_TYPE,
                client_id=_CLIENT_ID,
                client_secret=client_secret,
                auth_req_id=auth_req_id,
            )
        )
    )


def _app(**settings: object) -> FastAPI:
    # Les comptes/profils viennent du config.toml du dépôt : le hint HTTP
    # s'y réfère (email ``alice.martin@example.com``), l'identité étant
    # pontée sous un subject UUID (le scan par email le résout).
    values: dict[str, object] = {
        "issuer": _ISSUER,
        "base_url": _ISSUER,
        "jwks_algorithms": ("RS256",),
        "ciba_enabled": True,
        "ciba_approval_enabled": True,
        "clients_seed": (
            {
                "client_id": _CLIENT_ID,
                "client_secret": _CLIENT_SECRET,
                "scopes": "openid profile offline_access",
                "client_type": "confidential",
                "backchannel_token_delivery_mode": "poll",
            },
        ),
    }
    values.update(settings)
    return create_app(Settings(**values))  # type: ignore[arg-type]


class _FakeAssertions:
    """Remplace le vérificateur d'assertions : décodage ``login_hint_token`` piloté par le test."""

    def __init__(self, result: LoginHintTokenResult) -> None:
        self._result = result

    async def decode_login_hint_token(self, *, token: str, client: Client) -> LoginHintTokenResult:
        return self._result


class _FakeTokenManager:
    """Remplace le token manager : ``id_token_hint`` valide uniquement pour ``valid-hint``."""

    def __init__(self, claims: dict[str, object] | None) -> None:
        self._claims = claims

    async def validate_id_token(
        self, *, token: str, issuer: str, allow_expired: bool = False
    ) -> dict[str, object] | None:
        return self._claims if token == "valid-hint" else None


class _RecordingPingNotifier:
    """Enregistre les notifications ping reçues par le cas d'utilisation d'approbation."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    async def notify_ping(
        self, *, url: str, client_notification_token: str, auth_req_id: str
    ) -> None:
        self.calls.append((url, client_notification_token, auth_req_id))


class TestBackchannelAuthorizeUseCase:
    """Tests unitaires de BackchannelAuthenticationUseCase (``/bc-authorize``)."""

    def test_rejects_unknown_client(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(client_id="unknown")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_client"
        assert result.status_code == 401

    def test_rejects_inactive_client(self) -> None:
        uc, *_ = _make_usecase(replace(_CIBA_CLIENT, is_active=False))
        result = run(uc.execute(_params()))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_client"

    def test_rejects_bad_secret(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(client_secret="wrong")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_client"
        assert result.status_code == 401

    def test_rejects_client_without_ciba_registration(self) -> None:
        uc, *_ = _make_usecase(replace(_CIBA_CLIENT, backchannel_token_delivery_mode=""))
        result = run(uc.execute(_params()))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "unauthorized_client"

    def test_rejects_push_delivery_mode(self) -> None:
        uc, *_ = _make_usecase(replace(_CIBA_CLIENT, backchannel_token_delivery_mode="push"))
        result = run(uc.execute(_params()))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "unauthorized_client"

    def test_rejects_missing_scope(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(scope="")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_request"

    def test_rejects_scope_without_openid(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(scope="profile")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_scope"

    def test_rejects_scope_never_registered(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(scope="openid email")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_scope"

    def test_rejects_missing_hint(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params()))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_request"
        assert "un (et un seul) hint" in result.error_description

    def test_rejects_two_hints(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(login_hint=_USER_EMAIL, id_token_hint="x")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_request"

    def test_rejects_unknown_login_hint(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(login_hint="nobody@example.com")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "unknown_user_id"

    def test_accepts_login_hint_email_and_persists_request(self) -> None:
        uc, requests, *_ = _make_usecase()
        result = run(uc.execute(_params(login_hint=_USER_EMAIL)))
        assert isinstance(result, AuthenticationAck)
        assert len(result.auth_req_id) >= 43
        assert result.expires_in == 600
        assert result.interval == 5
        stored = run(requests.find_by_auth_req_id_hash(token_hash(result.auth_req_id)))
        assert stored is not None
        assert stored.status == BackchannelAuthenticationStatus.PENDING
        assert stored.subject == _USER_SUBJECT
        assert stored.delivery_mode == "poll"

    def test_accepts_login_hint_subject(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(login_hint=_USER_SUBJECT)))
        assert isinstance(result, AuthenticationAck)

    def test_honors_requested_expiry(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(login_hint=_USER_SUBJECT, requested_expiry="10")))
        assert isinstance(result, AuthenticationAck)
        assert result.expires_in == 10

    def test_bounds_requested_expiry_to_server_ttl(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(login_hint=_USER_SUBJECT, requested_expiry="100000")))
        assert isinstance(result, AuthenticationAck)
        assert result.expires_in == 600

    def test_rejects_invalid_requested_expiry(self) -> None:
        uc, *_ = _make_usecase()
        for value in ("abc", "0", "-5"):
            result = run(uc.execute(_params(login_hint=_USER_SUBJECT, requested_expiry=value)))
            assert isinstance(result, BackchannelAuthenticationError)
            assert result.error == "invalid_request"

    def test_ping_requires_notification_token(self) -> None:
        uc, *_ = _make_usecase(replace(_CIBA_CLIENT, backchannel_token_delivery_mode="ping"))
        result = run(uc.execute(_params(login_hint=_USER_SUBJECT)))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_request"
        assert "client_notification_token" in result.error_description

    def test_rejects_malformed_notification_token(self) -> None:
        uc, *_ = _make_usecase(replace(_CIBA_CLIENT, backchannel_token_delivery_mode="ping"))
        result = run(
            uc.execute(_params(login_hint=_USER_SUBJECT, client_notification_token="bad token"))
        )
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_request"

    def test_accepts_ping_with_notification_token(self) -> None:
        uc, requests, *_ = _make_usecase(
            replace(_CIBA_CLIENT, backchannel_token_delivery_mode="ping")
        )
        result = run(
            uc.execute(_params(login_hint=_USER_SUBJECT, client_notification_token="ntok-1"))
        )
        assert isinstance(result, AuthenticationAck)
        stored = run(requests.find_by_auth_req_id_hash(token_hash(result.auth_req_id)))
        assert stored is not None
        assert stored.delivery_mode == "ping"
        assert stored.client_notification_token == "ntok-1"

    def test_rejects_long_binding_message(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(login_hint=_USER_SUBJECT, binding_message="x" * 513)))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_binding_message"

    def test_accepts_binding_message(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(login_hint=_USER_SUBJECT, binding_message="code 1234")))
        assert isinstance(result, AuthenticationAck)

    def test_rejects_request_object(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(login_hint=_USER_SUBJECT, request="eyJhbGciOiJub25lIn0.x")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_request_object"

    def test_rejects_request_uri(self) -> None:
        uc, *_ = _make_usecase()
        result = run(uc.execute(_params(login_hint=_USER_SUBJECT, request_uri="urn:x:y")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_request_object"

    def test_expired_login_hint_token(self) -> None:
        assertions = _FakeAssertions(LoginHintTokenResult(claims=None, expired=True))
        uc, *_ = _make_usecase(assertions=assertions)
        result = run(uc.execute(_params(login_hint_token="tok")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "expired_login_hint_token"

    def test_unreadable_login_hint_token(self) -> None:
        assertions = _FakeAssertions(LoginHintTokenResult(claims=None, expired=False))
        uc, *_ = _make_usecase(assertions=assertions)
        result = run(uc.execute(_params(login_hint_token="tok")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "unknown_user_id"

    def test_login_hint_token_resolves_subject(self) -> None:
        assertions = _FakeAssertions(
            LoginHintTokenResult(claims={"sub": _USER_SUBJECT}, expired=False)
        )
        uc, *_ = _make_usecase(assertions=assertions)
        result = run(uc.execute(_params(login_hint_token="tok")))
        assert isinstance(result, AuthenticationAck)

    def test_id_token_hint_resolves_subject(self) -> None:
        manager = _FakeTokenManager({"sub": _USER_SUBJECT, "aud": _CLIENT_ID})
        uc, *_ = _make_usecase(token_manager=manager)
        result = run(uc.execute(_params(id_token_hint="valid-hint")))
        assert isinstance(result, AuthenticationAck)

    def test_rejects_id_token_hint_for_other_client(self) -> None:
        manager = _FakeTokenManager({"sub": _USER_SUBJECT, "aud": "another-client"})
        uc, *_ = _make_usecase(token_manager=manager)
        result = run(uc.execute(_params(id_token_hint="valid-hint")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_request"

    def test_rejects_invalid_id_token_hint(self) -> None:
        manager = _FakeTokenManager({"sub": _USER_SUBJECT})
        uc, *_ = _make_usecase(token_manager=manager)
        result = run(uc.execute(_params(id_token_hint="forged")))
        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_request"


class TestCibaApprovalUseCase:
    """Tests unitaires de CibaApprovalUseCase (``/ciba/approve``)."""

    def test_approve_flips_status(self) -> None:
        _, requests, *_ = _make_usecase()
        _store_request(requests)
        approval = CibaApprovalUseCase(requests)
        assert run(approval.execute("req-1", allow=True)) is True
        stored = run(requests.find_by_auth_req_id_hash(token_hash("req-1")))
        assert stored is not None
        assert stored.status == BackchannelAuthenticationStatus.APPROVED

    def test_deny_flips_status(self) -> None:
        _, requests, *_ = _make_usecase()
        _store_request(requests)
        approval = CibaApprovalUseCase(requests)
        assert run(approval.execute("req-1", allow=False)) is True
        stored = run(requests.find_by_auth_req_id_hash(token_hash("req-1")))
        assert stored is not None
        assert stored.status == BackchannelAuthenticationStatus.DENIED

    def test_unknown_auth_req_id_returns_false(self) -> None:
        _, requests, *_ = _make_usecase()
        approval = CibaApprovalUseCase(requests)
        assert run(approval.execute("nope", allow=True)) is False
        assert run(approval.execute("", allow=True)) is False

    def test_second_decision_is_idempotent(self) -> None:
        _, requests, *_ = _make_usecase()
        _store_request(requests)
        approval = CibaApprovalUseCase(requests)
        run(approval.execute("req-1", allow=True))
        assert run(approval.execute("req-1", allow=False)) is True
        stored = run(requests.find_by_auth_req_id_hash(token_hash("req-1")))
        assert stored is not None
        assert stored.status == BackchannelAuthenticationStatus.APPROVED

    def test_notifies_ping_client_once(self) -> None:
        _, requests, *_ = _make_usecase()
        _store_request(
            requests,
            delivery_mode="ping",
            notification_token="ntok-1",
            notification_endpoint=_NOTIFY_ENDPOINT,
        )
        notifier = _RecordingPingNotifier()
        approval = CibaApprovalUseCase(requests, ping_notifier=notifier)
        run(approval.execute("req-1", allow=True))
        run(approval.execute("req-1", allow=False))
        assert notifier.calls == [(_NOTIFY_ENDPOINT, "ntok-1", "req-1")]

    def test_skips_notification_for_poll_mode(self) -> None:
        _, requests, *_ = _make_usecase()
        _store_request(requests)
        notifier = _RecordingPingNotifier()
        approval = CibaApprovalUseCase(requests, ping_notifier=notifier)
        run(approval.execute("req-1", allow=True))
        assert notifier.calls == []

    def test_skips_notification_without_endpoint(self) -> None:
        _, requests, *_ = _make_usecase()
        _store_request(requests, delivery_mode="ping", notification_token="ntok-1")
        notifier = _RecordingPingNotifier()
        approval = CibaApprovalUseCase(requests, ping_notifier=notifier)
        run(approval.execute("req-1", allow=True))
        assert notifier.calls == []


class TestCibaGrant:
    """Tests du poll CIBA dans TokenUseCase (grant ``urn:openid:params:grant-type:ciba``)."""

    def test_rejects_missing_auth_req_id(self) -> None:
        _, _, token_uc, _ = _make_usecase()
        result = run(
            token_uc.execute(TokenRequest(grant_type=CIBA_GRANT_TYPE, client_id=_CLIENT_ID))
        )
        assert isinstance(result, TokenError)
        assert result.error == "invalid_grant"
        assert "auth_req_id manquant" in result.error_description

    def test_rejects_unknown_auth_req_id(self) -> None:
        _, _, token_uc, _ = _make_usecase()
        result = _poll(token_uc, auth_req_id="unknown-id")
        assert isinstance(result, TokenError)
        assert result.error == "invalid_grant"
        assert "invalide ou d'un autre client" in result.error_description

    def test_rejects_auth_req_id_of_another_client(self) -> None:
        _, requests, token_uc, _ = _make_usecase()
        _store_request(requests, client_id="other-app")
        result = _poll(token_uc, auth_req_id="req-1")
        assert isinstance(result, TokenError)
        assert result.error == "invalid_grant"

    def test_rejects_bad_client_secret(self) -> None:
        _, requests, token_uc, _ = _make_usecase()
        _store_request(requests)
        result = _poll(token_uc, auth_req_id="req-1", client_secret="wrong")
        assert isinstance(result, TokenError)
        assert result.error == "invalid_client"

    def test_returns_authorization_pending(self) -> None:
        _, requests, token_uc, _ = _make_usecase()
        _store_request(requests)
        result = _poll(token_uc, auth_req_id="req-1")
        assert isinstance(result, TokenError)
        assert result.error == "authorization_pending"

    def test_returns_slow_down_on_rapid_polls(self) -> None:
        _, requests, token_uc, _ = _make_usecase()
        _store_request(requests)
        first = _poll(token_uc, auth_req_id="req-1")
        assert isinstance(first, TokenError)
        assert first.error == "authorization_pending"
        second = _poll(token_uc, auth_req_id="req-1")
        assert isinstance(second, TokenError)
        assert second.error == "slow_down"
        stored = run(requests.find_by_auth_req_id_hash(token_hash("req-1")))
        assert stored is not None
        assert stored.interval == 10

    def test_returns_access_denied(self) -> None:
        _, requests, token_uc, _ = _make_usecase()
        _store_request(requests, status=BackchannelAuthenticationStatus.DENIED)
        result = _poll(token_uc, auth_req_id="req-1")
        assert isinstance(result, TokenError)
        assert result.error == "access_denied"

    def test_returns_expired_token_and_consumes_request(self) -> None:
        _, requests, token_uc, _ = _make_usecase()
        _store_request(requests, expires_in=-10)
        result = _poll(token_uc, auth_req_id="req-1")
        assert isinstance(result, TokenError)
        assert result.error == "expired_token"
        assert run(requests.find_by_auth_req_id_hash(token_hash("req-1"))) is None

    def test_rejects_push_client_on_token_endpoint(self) -> None:
        _, requests, token_uc, _ = _make_usecase(
            replace(_CIBA_CLIENT, backchannel_token_delivery_mode="push")
        )
        _store_request(requests, delivery_mode="push")
        result = _poll(token_uc, auth_req_id="req-1")
        assert isinstance(result, TokenError)
        assert result.error == "unauthorized_client"

    def test_issues_tokens_on_approved(self) -> None:
        _, requests, token_uc, _ = _make_usecase()
        _store_request(requests, status=BackchannelAuthenticationStatus.APPROVED)
        result = _poll(token_uc, auth_req_id="req-1")
        assert isinstance(result, TokenResponse)
        assert result.access_token
        assert result.id_token
        assert result.scope == "openid profile"
        assert result.refresh_token == ""
        assert run(requests.find_by_auth_req_id_hash(token_hash("req-1"))) is None

    def test_issues_refresh_token_with_offline_access(self) -> None:
        _, requests, token_uc, _ = _make_usecase()
        _store_request(
            requests,
            status=BackchannelAuthenticationStatus.APPROVED,
            scopes=frozenset({Scope.OPENID, Scope.OFFLINE_ACCESS}),
        )
        result = _poll(token_uc, auth_req_id="req-1")
        assert isinstance(result, TokenResponse)
        assert result.refresh_token

    def test_second_poll_after_success_is_invalid_grant(self) -> None:
        _, requests, token_uc, _ = _make_usecase()
        _store_request(requests, status=BackchannelAuthenticationStatus.APPROVED)
        first = _poll(token_uc, auth_req_id="req-1")
        assert isinstance(first, TokenResponse)
        second = _poll(token_uc, auth_req_id="req-1")
        assert isinstance(second, TokenError)
        assert second.error == "invalid_grant"

    def test_unsupported_when_store_not_injected(self) -> None:
        token_uc = TokenUseCase(
            TokenConfig(issuer=_ISSUER, signing_algorithm=JWTAlgorithm.RS256),
            InMemoryClientRepository(),
            InMemoryAuthorizationCodeRepository(),
            PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository())),
            InMemoryRefreshTokenRepository(),
            InMemoryDeviceAuthorizationRepository(),
        )
        result = run(
            token_uc.execute(TokenRequest(grant_type=CIBA_GRANT_TYPE, client_id=_CLIENT_ID))
        )
        assert isinstance(result, TokenError)
        assert result.error == "unsupported_grant_type"


class TestBackchannelRepositories:
    """Round-trip mémoire et SQL du repository des demandes CIBA."""

    def test_memory_round_trip(self) -> None:
        repo = InMemoryBackchannelAuthenticationRepository()
        request = BackchannelAuthenticationRequest(
            auth_req_id_hash="h1",
            client_id=_CLIENT_ID,
            scopes=frozenset({Scope.OPENID}),
            subject=_USER_SUBJECT,
            expires_at=_future_expiry(),
        )
        run(repo.save(request))
        found = run(repo.find_by_auth_req_id_hash("h1"))
        assert found is not None
        assert found.subject == _USER_SUBJECT

        run(repo.approve("h1"))
        approved = run(repo.find_by_auth_req_id_hash("h1"))
        assert approved is not None
        assert approved.status == BackchannelAuthenticationStatus.APPROVED

        run(repo.deny("h1"))
        denied = run(repo.find_by_auth_req_id_hash("h1"))
        assert denied is not None
        assert denied.status == BackchannelAuthenticationStatus.DENIED

        run(repo.delete("h1"))
        assert run(repo.find_by_auth_req_id_hash("h1")) is None

    def test_sql_round_trip(self, tmp_path: Path) -> None:
        db = tmp_path / "ciba.db"
        repo = SQLBackchannelAuthenticationRepository(f"sqlite+aiosqlite:///{db}")
        run(repo.initialise())
        request = BackchannelAuthenticationRequest(
            auth_req_id_hash="sql-h1",
            client_id=_CLIENT_ID,
            scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
            subject=_USER_SUBJECT,
            delivery_mode="ping",
            client_notification_token="ntok-1",
            client_notification_endpoint=_NOTIFY_ENDPOINT,
            binding_message="code 1234",
            acr="urn:x:acr",
            interval=10,
            expires_at=_future_expiry(),
        )
        run(repo.save(request))
        found = run(repo.find_by_auth_req_id_hash("sql-h1"))
        assert found is not None
        assert found.delivery_mode == "ping"
        assert found.client_notification_token == "ntok-1"
        assert found.client_notification_endpoint == _NOTIFY_ENDPOINT
        assert found.binding_message == "code 1234"
        assert found.acr == "urn:x:acr"
        assert found.interval == 10
        assert found.scopes == frozenset({Scope.OPENID, Scope.PROFILE})

        run(repo.approve("sql-h1"))
        approved = run(repo.find_by_auth_req_id_hash("sql-h1"))
        assert approved is not None
        assert approved.status == BackchannelAuthenticationStatus.APPROVED

        run(repo.deny("sql-h1"))
        denied = run(repo.find_by_auth_req_id_hash("sql-h1"))
        assert denied is not None
        assert denied.status == BackchannelAuthenticationStatus.DENIED

        run(repo.delete("sql-h1"))
        assert run(repo.find_by_auth_req_id_hash("sql-h1")) is None
        run(repo.close())

    def test_factory_memory(self) -> None:
        repo = build_backchannel_authentication_repository(Settings(storage_type="memory"))
        assert isinstance(repo, InMemoryBackchannelAuthenticationRepository)

    def test_factory_sql(self, tmp_path: Path) -> None:
        db = tmp_path / "factory-ciba.db"
        repo = build_backchannel_authentication_repository(
            Settings(storage_type="sql", storage_dsn=f"sqlite+aiosqlite:///{db}")
        )
        assert isinstance(repo, SQLBackchannelAuthenticationRepository)


class _PingCaptureHandler(BaseHTTPRequestHandler):
    """Capteure le POST ping reçu et répond 204 (ou 302 si ``redirect``)."""

    received: ClassVar[list[tuple[str, str | None, bytes]]] = []
    redirect: ClassVar[bool] = False

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).received.append((self.path, self.headers.get("Authorization"), body))
        if type(self).redirect:
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.end_headers()
            return
        self.send_response(204)
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        """Silence les logs du serveur de test."""


class TestCibaPingNotifier:
    """Tests de HTTPCibaPingNotifier contre un serveur local (CIBA §10.2)."""

    def test_posts_json_with_bearer_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from puridentityserver.infrastructure.backchannel import HTTPCibaPingNotifier

        monkeypatch.setattr(_PingCaptureHandler, "received", [])
        monkeypatch.setattr(_PingCaptureHandler, "redirect", False)
        server = ThreadingHTTPServer(("127.0.0.1", 0), _PingCaptureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            notifier = HTTPCibaPingNotifier()
            run(
                notifier.notify_ping(
                    url=f"http://127.0.0.1:{port}/notify",
                    client_notification_token="ntok-1",
                    auth_req_id="req-abc",
                )
            )
        finally:
            server.shutdown()
        assert len(_PingCaptureHandler.received) == 1
        path, authorization, body = _PingCaptureHandler.received[0]
        assert path == "/notify"
        assert authorization == "Bearer ntok-1"
        assert body == b'{"auth_req_id":"req-abc"}'

    def test_single_attempt_on_redirect(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from puridentityserver.infrastructure.backchannel import HTTPCibaPingNotifier

        monkeypatch.setattr(_PingCaptureHandler, "received", [])
        monkeypatch.setattr(_PingCaptureHandler, "redirect", True)
        server = ThreadingHTTPServer(("127.0.0.1", 0), _PingCaptureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            notifier = HTTPCibaPingNotifier()
            run(
                notifier.notify_ping(
                    url=f"http://127.0.0.1:{port}/notify",
                    client_notification_token="ntok-1",
                    auth_req_id="req-abc",
                )
            )
        finally:
            server.shutdown()
        assert len(_PingCaptureHandler.received) == 1

    def test_swallows_network_errors(self) -> None:
        from puridentityserver.infrastructure.backchannel import HTTPCibaPingNotifier

        notifier = HTTPCibaPingNotifier()
        run(
            notifier.notify_ping(
                url="http://127.0.0.1:1/notify",
                client_notification_token="ntok-1",
                auth_req_id="req-abc",
            )
        )


class TestCibaIntegrationHTTP:
    """Tests d'intégration HTTP du flow CIBA (TestClient FastAPI)."""

    def test_full_flow_approve_then_poll(self) -> None:
        with TestClient(_app()) as client:
            ack = client.post(
                "/bc-authorize",
                data={"scope": "openid profile", "login_hint": _DEMO_HINT_EMAIL},
                auth=(_CLIENT_ID, _CLIENT_SECRET),
            )
            assert ack.status_code == 200
            body = ack.json()
            auth_req_id = body["auth_req_id"]
            assert body["expires_in"] == 600
            assert body["interval"] == 5

            approval = client.post(f"/ciba/approve?token={auth_req_id}&type=allow")
            assert approval.status_code == 200
            assert approval.text == ""

            tokens = client.post(
                "/token",
                data={"grant_type": CIBA_GRANT_TYPE, "auth_req_id": auth_req_id},
                auth=(_CLIENT_ID, _CLIENT_SECRET),
            )
            assert tokens.status_code == 200
            issued = tokens.json()
            assert issued["access_token"]
            assert issued["id_token"]
            assert issued["scope"] == "openid profile"

    def test_poll_pending_before_decision(self) -> None:
        with TestClient(_app()) as client:
            ack = client.post(
                "/bc-authorize",
                data={"scope": "openid profile", "login_hint": _DEMO_HINT_EMAIL},
                auth=(_CLIENT_ID, _CLIENT_SECRET),
            )
            auth_req_id = ack.json()["auth_req_id"]
            pending = client.post(
                "/token",
                data={"grant_type": CIBA_GRANT_TYPE, "auth_req_id": auth_req_id},
                auth=(_CLIENT_ID, _CLIENT_SECRET),
            )
            assert pending.status_code == 400
            assert pending.json()["error"] == "authorization_pending"

    def test_full_flow_deny(self) -> None:
        with TestClient(_app()) as client:
            ack = client.post(
                "/bc-authorize",
                data={"scope": "openid profile", "login_hint": _DEMO_HINT_EMAIL},
                auth=(_CLIENT_ID, _CLIENT_SECRET),
            )
            auth_req_id = ack.json()["auth_req_id"]
            approval = client.post(f"/ciba/approve?token={auth_req_id}&type=deny")
            assert approval.status_code == 200
            poll = client.post(
                "/token",
                data={"grant_type": CIBA_GRANT_TYPE, "auth_req_id": auth_req_id},
                auth=(_CLIENT_ID, _CLIENT_SECRET),
            )
            assert poll.status_code == 400
            assert poll.json()["error"] == "access_denied"

    def test_slow_down_on_rapid_polls(self) -> None:
        with TestClient(_app()) as client:
            ack = client.post(
                "/bc-authorize",
                data={"scope": "openid profile", "login_hint": _DEMO_HINT_EMAIL},
                auth=(_CLIENT_ID, _CLIENT_SECRET),
            )
            auth_req_id = ack.json()["auth_req_id"]
            first = client.post(
                "/token",
                data={"grant_type": CIBA_GRANT_TYPE, "auth_req_id": auth_req_id},
                auth=(_CLIENT_ID, _CLIENT_SECRET),
            )
            assert first.json()["error"] == "authorization_pending"
            second = client.post(
                "/token",
                data={"grant_type": CIBA_GRANT_TYPE, "auth_req_id": auth_req_id},
                auth=(_CLIENT_ID, _CLIENT_SECRET),
            )
            assert second.json()["error"] == "slow_down"

    def test_client_secret_post_authentication(self) -> None:
        with TestClient(_app()) as client:
            ack = client.post(
                "/bc-authorize",
                data={
                    "scope": "openid profile",
                    "login_hint": _DEMO_HINT_EMAIL,
                    "client_id": _CLIENT_ID,
                    "client_secret": _CLIENT_SECRET,
                },
            )
            assert ack.status_code == 200
            denied = client.post(
                "/bc-authorize",
                data={
                    "scope": "openid profile",
                    "login_hint": _DEMO_HINT_EMAIL,
                    "client_id": _CLIENT_ID,
                    "client_secret": "wrong",
                },
            )
            assert denied.status_code == 401
            assert denied.json()["error"] == "invalid_client"

    def test_bc_authorize_disabled_without_flag(self) -> None:
        with TestClient(_app(ciba_enabled=False)) as client:
            resp = client.post(
                "/bc-authorize",
                data={"scope": "openid", "login_hint": _DEMO_HINT_EMAIL},
                auth=(_CLIENT_ID, _CLIENT_SECRET),
            )
            assert resp.status_code == 404

    def test_approval_disabled_without_flag(self) -> None:
        with TestClient(_app(ciba_approval_enabled=False)) as client:
            resp = client.post("/ciba/approve?token=x&type=allow")
            assert resp.status_code == 404

    def test_approval_rejects_unknown_id(self) -> None:
        with TestClient(_app()) as client:
            resp = client.post("/ciba/approve?token=nope&type=allow")
            assert resp.status_code == 404
            assert resp.json()["error"] == "invalid_request"

    def test_approval_rejects_invalid_type(self) -> None:
        with TestClient(_app()) as client:
            resp = client.post("/ciba/approve?token=nope&type=maybe")
            assert resp.status_code == 400
            assert resp.json()["error"] == "invalid_request"

    def test_discovery_advertises_ciba(self) -> None:
        with TestClient(_app()) as client:
            doc = client.get("/.well-known/openid-configuration").json()
            assert doc["backchannel_authentication_endpoint"] == f"{_ISSUER}/bc-authorize"
            assert doc["backchannel_token_delivery_modes_supported"] == ["poll", "ping"]
            assert doc["backchannel_user_code_parameter_supported"] is False
            assert CIBA_GRANT_TYPE in doc["grant_types_supported"]

    def test_discovery_hides_ciba_without_flag(self) -> None:
        with TestClient(_app(ciba_enabled=False)) as client:
            doc = client.get("/.well-known/openid-configuration").json()
            assert doc["backchannel_authentication_endpoint"] is None
            assert doc["backchannel_token_delivery_modes_supported"] == []
            assert CIBA_GRANT_TYPE not in doc["grant_types_supported"]


class TestCibaRegistrationMetadata:
    """Tests DCR des métadonnées CIBA (OIDC CIBA 1.0 §16.1.1)."""

    _HEADERS: ClassVar[dict[str, str]] = {"Authorization": "Bearer registrar"}

    def _app(self) -> FastAPI:
        return _app(
            registration_enabled=True,
            registration_requires_initial_access_token=False,
        )

    def test_registers_ping_client_with_ciba_metadata(self) -> None:
        with TestClient(self._app()) as client:
            resp = client.post(
                "/register",
                json={
                    "grant_types": ["authorization_code", CIBA_GRANT_TYPE],
                    "redirect_uris": ["https://rp.example/cb"],
                    "scope": "openid profile",
                    "backchannel_token_delivery_mode": "ping",
                    "backchannel_client_notification_endpoint": "https://rp.example/notify",
                },
                headers=self._HEADERS,
            )
            assert resp.status_code == 201, resp.text
            body = resp.json()
            assert body["backchannel_token_delivery_mode"] == "ping"
            assert body["backchannel_client_notification_endpoint"] == ("https://rp.example/notify")

    def test_rejects_push_delivery_mode(self) -> None:
        with TestClient(self._app()) as client:
            resp = client.post(
                "/register",
                json={
                    "redirect_uris": ["https://rp.example/cb"],
                    "backchannel_token_delivery_mode": "push",
                },
                headers=self._HEADERS,
            )
            assert resp.status_code == 400
            assert resp.json()["error"] == "invalid_client_metadata"

    def test_rejects_user_code_parameter(self) -> None:
        with TestClient(self._app()) as client:
            resp = client.post(
                "/register",
                json={
                    "redirect_uris": ["https://rp.example/cb"],
                    "backchannel_token_delivery_mode": "poll",
                    "backchannel_user_code_parameter": True,
                },
                headers=self._HEADERS,
            )
            assert resp.status_code == 400
            assert resp.json()["error"] == "invalid_client_metadata"

    def test_rejects_invalid_notification_endpoint(self) -> None:
        with TestClient(self._app()) as client:
            resp = client.post(
                "/register",
                json={
                    "redirect_uris": ["https://rp.example/cb"],
                    "backchannel_token_delivery_mode": "ping",
                    "backchannel_client_notification_endpoint": "not-a-uri",
                },
                headers=self._HEADERS,
            )
            assert resp.status_code == 400
            assert resp.json()["error"] == "invalid_client_metadata"
