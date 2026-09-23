"""Tests unitaires du use case TokenUseCase et du PyJWTTokenManager."""

import asyncio
import hashlib
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar

import jwt
import pytest

from puridentityserver.application.token import TokenConfig, TokenRequest, TokenUseCase
from puridentityserver.domain.authorization import (
    AuthorizationCode,
    Client,
    ClientType,
    RefreshToken,
    Scope,
)
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.domain.revocation import token_hash
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.factory import (
    build_refresh_token_repository,
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
from puridentityserver.infrastructure.persistence.sql.refresh_tokens import (
    SQLRefreshTokenRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_CLIENT_SECRET = "super-secret"

_CONFIDENTIAL_CLIENT = Client(
    client_id="web-app",
    redirect_uris=frozenset({"https://app.example/callback"}),
    scopes=frozenset({Scope.OPENID}),
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


def _future_expiry() -> datetime:
    """Date d'expiration dans le futur (évite l'expiration immédiate du défaut)."""
    return datetime.now(timezone.utc) + timedelta(minutes=10)


def _make_usecase(
    client: Client | None = None, key_manager: DefaultKeyManager | None = None
) -> tuple[TokenUseCase, InMemoryAuthorizationCodeRepository, InMemoryRefreshTokenRepository]:
    """Construit un TokenUseCase avec des repos en mémoire."""
    clients = InMemoryClientRepository()
    codes = InMemoryAuthorizationCodeRepository()
    refresh_tokens = InMemoryRefreshTokenRepository()
    device_codes = InMemoryDeviceAuthorizationRepository()
    km = key_manager or DefaultKeyManager(InMemoryKeyPairRepository())
    token_manager = PyJWTTokenManager(km)
    resolved_client = client or _CONFIDENTIAL_CLIENT
    run(clients.save(resolved_client))
    config = TokenConfig(issuer=_ISSUER, signing_algorithm=JWTAlgorithm.RS256)
    return (
        TokenUseCase(config, clients, codes, token_manager, refresh_tokens, device_codes),
        codes,
        refresh_tokens,
    )


class TestTokenUseCaseErrors:
    """Couvre les branches d'erreur de TokenUseCase.execute."""

    def test_rejects_expired_code(self) -> None:
        uc, codes, _ = _make_usecase()
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
        uc, codes, _ = _make_usecase()
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
        uc, codes, _ = _make_usecase(_PUBLIC_CLIENT)
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
        assert not hasattr(result, "id_token")

    def test_sid_from_code_is_carried_into_id_token(self) -> None:
        uc, codes, _ = _make_usecase()
        code = AuthorizationCode(
            code="sid-code",
            client_id="web-app",
            redirect_uri="https://app.example/callback",
            subject="alice-uuid",
            session_id="sid-alice-1",
            scopes=frozenset({Scope.OPENID}),
            expires_at=_future_expiry(),
        )
        run(codes.save(code))

        req = TokenRequest(
            grant_type="authorization_code",
            code="sid-code",
            redirect_uri="https://app.example/callback",
            client_id="web-app",
            client_secret=_CLIENT_SECRET,
        )
        result = run(uc.execute(req))

        id_claims = jwt.decode(result.id_token, options={"verify_signature": False})
        assert id_claims["sid"] == "sid-alice-1"
        assert id_claims["sub"] == "alice-uuid"

    def test_no_sid_when_code_without_session(self) -> None:
        uc, codes, _ = _make_usecase()
        code = AuthorizationCode(
            code="no-sid-code",
            client_id="web-app",
            redirect_uri="https://app.example/callback",
            scopes=frozenset({Scope.OPENID}),
            expires_at=_future_expiry(),
        )
        run(codes.save(code))

        req = TokenRequest(
            grant_type="authorization_code",
            code="no-sid-code",
            redirect_uri="https://app.example/callback",
            client_id="web-app",
            client_secret=_CLIENT_SECRET,
        )
        result = run(uc.execute(req))

        id_claims = jwt.decode(result.id_token, options={"verify_signature": False})
        assert "sid" not in id_claims

    def test_pkce_plain_success(self) -> None:
        uc, codes, _ = _make_usecase(_PUBLIC_CLIENT)
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
        uc, codes, _ = _make_usecase(client)
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


class TestRefreshGrant:
    """Couvre le grant type ``refresh_token`` (RFC 6749 §6) avec rotation."""

    _STORED_SCOPES = frozenset({Scope.OPENID, Scope.PROFILE, Scope.EMAIL})

    def _stored_refresh(
        self,
        *,
        client_id: str = "web-app",
        scopes: frozenset[Scope] = _STORED_SCOPES,
        ttl_minutes: int = 30,
        consumed: bool = False,
    ) -> RefreshToken:
        value = f"refresh-{client_id}"
        expires = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
        return RefreshToken(
            token_hash=token_hash(value),
            client_id=client_id,
            subject="alice",
            scopes=scopes,
            expires_at=expires,
            is_consumed=consumed,
        )

    def test_code_exchange_emits_refresh_token_with_offline_access(self) -> None:
        uc, codes, refresh_tokens = _make_usecase()
        code = AuthorizationCode(
            code="offline-code",
            client_id="web-app",
            redirect_uri="https://app.example/callback",
            subject="alice",
            scopes=frozenset({Scope.OPENID, Scope.OFFLINE_ACCESS}),
            expires_at=_future_expiry(),
        )
        run(codes.save(code))

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="offline-code",
                    redirect_uri="https://app.example/callback",
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert result.refresh_token
        stored = run(refresh_tokens.find_by_token_hash(token_hash(result.refresh_token)))
        assert stored is not None
        assert stored.client_id == "web-app"
        assert Scope.OFFLINE_ACCESS in stored.scopes

    def test_code_exchange_omits_refresh_token_without_offline_access(self) -> None:
        uc, codes, _ = _make_usecase()
        code = AuthorizationCode(
            code="plain-code",
            client_id="web-app",
            redirect_uri="https://app.example/callback",
            subject="alice",
            scopes=frozenset({Scope.OPENID}),
            expires_at=_future_expiry(),
        )
        run(codes.save(code))

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="plain-code",
                    redirect_uri="https://app.example/callback",
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert result.refresh_token == ""

    def test_refresh_rotates_and_returns_new_tokens(self) -> None:
        uc, _, refresh_tokens = _make_usecase()
        old = self._stored_refresh()
        run(refresh_tokens.save(old))

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token="refresh-web-app",
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert result.access_token
        assert result.id_token
        assert result.refresh_token
        assert result.refresh_token != "refresh-web-app"
        assert result.scope == "email openid profile"
        assert run(refresh_tokens.find_by_token_hash(old.token_hash)).is_consumed is True
        assert run(refresh_tokens.find_by_token_hash(token_hash(result.refresh_token))) is not None

    def test_refresh_rejects_reused_token(self) -> None:
        uc, _, refresh_tokens = _make_usecase()
        run(refresh_tokens.save(self._stored_refresh(consumed=True)))

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token="refresh-web-app",
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert result.error == "invalid_grant"
        assert "rotation" in result.error_description

    def test_refresh_rejects_expired_token(self) -> None:
        uc, _, refresh_tokens = _make_usecase()
        run(refresh_tokens.save(self._stored_refresh(ttl_minutes=-10)))

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token="refresh-web-app",
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert result.error == "invalid_grant"
        assert "expiré" in result.error_description

    def test_refresh_rejects_unknown_token(self) -> None:
        uc, _, _ = _make_usecase()

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token="inconnu",
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert result.error == "invalid_grant"

    def test_refresh_rejects_wrong_secret(self) -> None:
        uc, _, refresh_tokens = _make_usecase()
        run(refresh_tokens.save(self._stored_refresh()))

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token="refresh-web-app",
                    client_id="web-app",
                    client_secret="mauvais",
                )
            )
        )

        assert result.error == "invalid_client"

    def test_refresh_rejects_unknown_client(self) -> None:
        uc, _, _ = _make_usecase()

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token="refresh-web-app",
                    client_id="ghost",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert result.error == "invalid_client"

    def test_refresh_public_client_without_secret(self) -> None:
        uc, _, refresh_tokens = _make_usecase(_PUBLIC_CLIENT)
        run(refresh_tokens.save(self._stored_refresh(client_id="spa")))

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token="refresh-spa",
                    client_id="spa",
                )
            )
        )

        assert result.access_token
        assert result.refresh_token

    def test_refresh_narrows_scope(self) -> None:
        uc, _, refresh_tokens = _make_usecase()
        run(refresh_tokens.save(self._stored_refresh()))

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token="refresh-web-app",
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                    scope="openid email",
                )
            )
        )

        assert result.scope == "email openid"
        claims = jwt.decode(result.access_token, options={"verify_signature": False})
        assert claims["scope"] == "email openid"
        stored = run(refresh_tokens.find_by_token_hash(token_hash(result.refresh_token)))
        assert stored.scopes == frozenset({Scope.OPENID, Scope.EMAIL})

    def test_refresh_rejects_scope_not_granted(self) -> None:
        uc, _, refresh_tokens = _make_usecase()
        run(refresh_tokens.save(self._stored_refresh()))

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token="refresh-web-app",
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                    scope="openid offline_access",
                )
            )
        )

        assert result.error == "invalid_scope"

    def test_refresh_rejects_missing_parameter(self) -> None:
        uc, _, _ = _make_usecase()

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token="",
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert result.error == "invalid_grant"
        assert "manquant" in result.error_description


class TestRefreshTokenRepositories:
    """Couvre les implémentations mémoire et SQL du store de refresh tokens."""

    def test_memory_round_trip_consume_and_delete(self) -> None:
        repo = InMemoryRefreshTokenRepository()
        token = RefreshToken(
            token_hash="abc", client_id="web-app", scopes=frozenset({Scope.OPENID})
        )

        run(repo.save(token))

        assert run(repo.find_by_token_hash("abc")) is not None
        assert run(repo.find_by_token_hash("absent")) is None
        run(repo.consume("abc"))
        assert run(repo.find_by_token_hash("abc")).is_consumed is True
        run(repo.delete("abc"))
        assert run(repo.find_by_token_hash("abc")) is None

    def test_sql_round_trip_consume_and_delete(self, tmp_path: Path) -> None:
        repo = SQLRefreshTokenRepository(f"sqlite+aiosqlite:///{tmp_path / 'refresh.db'}")
        run(repo.initialise())
        token = RefreshToken(
            token_hash="abc", client_id="web-app", scopes=frozenset({Scope.OPENID})
        )

        run(repo.save(token))

        assert run(repo.find_by_token_hash("abc")) is not None
        assert run(repo.find_by_token_hash("absent")) is None
        run(repo.consume("abc"))
        assert run(repo.find_by_token_hash("abc")).is_consumed is True
        run(repo.delete("abc"))
        assert run(repo.find_by_token_hash("abc")) is None
        run(repo.close())

    def test_factory_builds_memory(self) -> None:
        repo = build_refresh_token_repository(Settings(storage_type="memory"))

        assert isinstance(repo, InMemoryRefreshTokenRepository)

    def test_factory_builds_sql(self) -> None:
        repo = build_refresh_token_repository(
            Settings(storage_type="sql", storage_dsn="sqlite:///memory")
        )

        assert isinstance(repo, SQLRefreshTokenRepository)

    def test_factory_rejects_unknown_store_type(self) -> None:
        settings = Settings.model_construct(storage_type="cassandra")

        with pytest.raises(ValueError, match="non supporté"):
            build_refresh_token_repository(settings)


class TestClientCredentialsGrant:
    """Couvre le grant type ``client_credentials`` (RFC 6749 §4.4)."""

    def test_issues_access_token_with_client_default_scopes(self) -> None:
        uc, _, _ = _make_usecase()

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="client_credentials",
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert result.access_token
        assert result.id_token == ""
        assert result.refresh_token == ""
        assert result.scope == "openid"
        claims = jwt.decode(result.access_token, options={"verify_signature": False})
        assert claims["sub"] == "web-app"
        assert claims["aud"] == "web-app"

    def test_requested_scope_subset_is_honoured(self) -> None:
        uc, _, _ = _make_usecase()

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="client_credentials",
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                    scope="openid",
                )
            )
        )

        assert result.scope == "openid"
        claims = jwt.decode(result.access_token, options={"verify_signature": False})
        assert claims["scope"] == "openid"

    def test_requested_scope_not_registered_is_rejected(self) -> None:
        uc, _, _ = _make_usecase()

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="client_credentials",
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                    scope="profile",
                )
            )
        )

        assert result.error == "invalid_scope"

    def test_rejects_wrong_secret(self) -> None:
        uc, _, _ = _make_usecase()

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="client_credentials",
                    client_id="web-app",
                    client_secret="mauvais-secret",
                )
            )
        )

        assert result.error == "invalid_client"

    def test_rejects_public_client(self) -> None:
        uc, _, _ = _make_usecase(_PUBLIC_CLIENT)

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="client_credentials",
                    client_id="spa",
                )
            )
        )

        assert result.error == "invalid_client"

    def test_rejects_unknown_client(self) -> None:
        uc, _, _ = _make_usecase()

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="client_credentials",
                    client_id="ghost",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert result.error == "invalid_client"

    def test_ttl_uses_client_lifetime(self) -> None:
        client = Client(
            client_id="machine",
            redirect_uris=frozenset(),
            scopes=frozenset({Scope.OPENID}),
            client_type=ClientType.CONFIDENTIAL,
            client_secret_hash=hashlib.sha256(_CLIENT_SECRET.encode("utf-8")).hexdigest(),
            access_token_lifetime_seconds=120,
        )
        uc, _, _ = _make_usecase(client)

        result = run(
            uc.execute(
                TokenRequest(
                    grant_type="client_credentials",
                    client_id="machine",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert result.expires_in == 120
        claims = jwt.decode(result.access_token, options={"verify_signature": False})
        assert claims["exp"] - claims["iat"] == 120


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
