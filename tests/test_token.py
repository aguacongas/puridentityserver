"""Tests unitaires du use case TokenUseCase et du PyJWTTokenManager."""

import asyncio
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from typing import TypeVar

import jwt
import pytest

from puridentityserver.application.token import TokenConfig, TokenRequest, TokenUseCase
from puridentityserver.domain.authorization import AuthorizationCode, Client, ClientType, Scope
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.persistence.memory.codes import (
    InMemoryAuthorizationCodeRepository,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.tokens import PyJWTTokenManager

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_CLIENT_SECRET = "super-secret"

_CONFIDENTIAL_CLIENT = Client(
    client_id="web-app",
    redirect_uris=frozenset({"https://app.example/callback"}),
    scopes=frozenset({Scope.OPENID}),
    client_type=ClientType.CONFIDENTIAL,
    client_secret_hash="a" * 64,
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


def _future_expiry() -> datetime:
    """Date d'expiration dans le futur (évite l'expiration immédiate du défaut)."""
    return datetime.now(timezone.utc) + timedelta(minutes=10)


def _make_usecase(
    client: Client | None = None, key_manager: DefaultKeyManager | None = None
) -> tuple[TokenUseCase, InMemoryAuthorizationCodeRepository]:
    """Construit un TokenUseCase avec des repos en mémoire."""
    clients = InMemoryClientRepository()
    codes = InMemoryAuthorizationCodeRepository()
    km = key_manager or DefaultKeyManager(InMemoryKeyPairRepository())
    token_manager = PyJWTTokenManager(km)
    resolved_client = client or _CONFIDENTIAL_CLIENT
    run(clients.save(resolved_client))
    config = TokenConfig(issuer=_ISSUER, signing_algorithm=JWTAlgorithm.RS256)
    return TokenUseCase(config, clients, codes, token_manager), codes


class TestTokenUseCaseErrors:
    """Couvre les branches d'erreur de TokenUseCase.execute."""

    def test_rejects_expired_code(self) -> None:
        uc, codes = _make_usecase()
        expired = AuthorizationCode(
            code="expired-code",
            client_id="web-app",
            redirect_uri="https://app.example/callback",
            scopes=frozenset({Scope.OPENID}),
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        )
        run(codes.save(expired))

        req = TokenRequest(
            grant_type="authorization_code",
            code="expired-code",
            redirect_uri="https://app.example/callback",
            client_id="web-app",
            client_secret=_CLIENT_SECRET,
        )
        result = run(uc.execute(req))

        assert result.error == "invalid_grant"
        assert "expiré" in result.error_description

    def test_rejects_unknown_client(self) -> None:
        uc, codes = _make_usecase()
        code = AuthorizationCode(
            code="valid-code",
            client_id="web-app",
            redirect_uri="https://app.example/callback",
            scopes=frozenset({Scope.OPENID}),
            expires_at=_future_expiry(),
        )
        run(codes.save(code))

        req = TokenRequest(
            grant_type="authorization_code",
            code="valid-code",
            redirect_uri="https://app.example/callback",
            client_id="unknown-client",
        )
        result = run(uc.execute(req))

        assert result.error == "invalid_client"

    def test_pkce_s256_missing_verifier(self) -> None:
        uc, codes = _make_usecase(_PUBLIC_CLIENT)
        code = AuthorizationCode(
            code="pkce-code",
            client_id="spa",
            redirect_uri="https://spa.example/cb",
            scopes=frozenset({Scope.OPENID}),
            code_challenge="challenge-value",
            code_challenge_method="S256",
            expires_at=_future_expiry(),
        )
        run(codes.save(code))

        req = TokenRequest(
            grant_type="authorization_code",
            code="pkce-code",
            redirect_uri="https://spa.example/cb",
            client_id="spa",
        )
        result = run(uc.execute(req))

        assert result.error == "invalid_grant"
        assert "PKCE" in result.error_description

    def test_pkce_plain_success(self) -> None:
        uc, codes = _make_usecase(_PUBLIC_CLIENT)
        code = AuthorizationCode(
            code="plain-code",
            client_id="spa",
            redirect_uri="https://spa.example/cb",
            scopes=frozenset({Scope.OPENID}),
            code_challenge="exact-match",
            code_challenge_method="plain",
            expires_at=_future_expiry(),
        )
        run(codes.save(code))

        req = TokenRequest(
            grant_type="authorization_code",
            code="plain-code",
            redirect_uri="https://spa.example/cb",
            client_id="spa",
            code_verifier="exact-match",
        )
        result = run(uc.execute(req))

        assert hasattr(result, "access_token")
        assert hasattr(result, "id_token")

    def test_ttl_uses_client_lifetime(self) -> None:
        client = Client(
            client_id="spa",
            redirect_uris=frozenset({"https://spa.example/cb"}),
            scopes=frozenset({Scope.OPENID}),
            client_type=ClientType.PUBLIC,
            access_token_lifetime_seconds=120,
        )
        uc, codes = _make_usecase(client)
        code = AuthorizationCode(
            code="ttl-code",
            client_id="spa",
            redirect_uri="https://spa.example/cb",
            scopes=frozenset({Scope.OPENID}),
            code_challenge="exact-match",
            code_challenge_method="plain",
            expires_at=_future_expiry(),
        )
        run(codes.save(code))

        req = TokenRequest(
            grant_type="authorization_code",
            code="ttl-code",
            redirect_uri="https://spa.example/cb",
            client_id="spa",
            code_verifier="exact-match",
        )
        result = run(uc.execute(req))

        assert result.expires_in == 120
        id_claims = jwt.decode(result.id_token, options={"verify_signature": False})
        assert id_claims["exp"] - id_claims["iat"] == 120
        access_claims = jwt.decode(result.access_token, options={"verify_signature": False})
        assert access_claims["exp"] - access_claims["iat"] == 120


class TestScope:
    """Couvre la branche vide de Scope.from_space_separated."""

    def test_from_space_separated_empty_string(self) -> None:
        assert Scope.from_space_separated("") == frozenset()
        assert Scope.from_space_separated("   ") == frozenset()

    def test_from_space_separated_none(self) -> None:
        assert Scope.from_space_separated(None) == frozenset()


class TestPyJWTTokenManager:
    """Couvre les branches de PyJWTTokenManager._first_active_key."""

    def test_generates_key_when_none_exists(self) -> None:
        keys = InMemoryKeyPairRepository()
        km = DefaultKeyManager(keys)
        tm = PyJWTTokenManager(km)

        token = run(
            tm.create_access_token(
                algorithm=JWTAlgorithm.RS256,
                issuer=_ISSUER,
                subject="sub",
                audience="aud",
                expires_at=9999999999,
                issued_at=1000000000,
                scopes=frozenset({Scope.OPENID}),
            )
        )

        assert token
        assert len(run(km.get_active_keys())) == 1

    def test_first_active_key_skips_foreign_algorithm_keys(self) -> None:
        keys = InMemoryKeyPairRepository()
        km = DefaultKeyManager(keys)
        run(km.generate_key_pair(2048, JWTAlgorithm.ES256))
        tm = PyJWTTokenManager(km)

        token = run(
            tm.create_access_token(
                algorithm=JWTAlgorithm.RS256,
                issuer=_ISSUER,
                subject="sub",
                audience="aud",
                expires_at=9999999999,
                issued_at=1000000000,
                scopes=frozenset({Scope.OPENID}),
            )
        )

        assert token
        assert len(run(km.get_active_keys())) == 2

    def test_raises_when_key_manager_cannot_create_key(self) -> None:

        class _BrokenKeyManager:
            async def get_active_keys(self) -> list:  # type: ignore[override]
                return []

            async def ensure_active_key(self, key_size: int, algorithm: object) -> None:
                pass

            async def generate_key_pair(self, key_size: int, algorithm: object) -> None:
                raise RuntimeError("cannot generate")

            async def mark_expired_keys(self, rotation_days: int, grace_period_days: int) -> int:
                return 0

        tm = PyJWTTokenManager(_BrokenKeyManager())  # type: ignore[arg-type]
        create = tm.create_access_token(
            algorithm=JWTAlgorithm.RS256,
            issuer=_ISSUER,
            subject="sub",
            audience="aud",
            expires_at=9999999999,
            issued_at=1000000000,
            scopes=frozenset({Scope.OPENID}),
        )

        with pytest.raises(RuntimeError, match="Aucune clé active"):
            run(create)
