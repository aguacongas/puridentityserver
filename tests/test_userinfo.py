"""Tests de la feature ID Token + UserInfo (validation JWT, endpoint /userinfo)."""

import asyncio
import base64
import hashlib
from collections.abc import Awaitable
from typing import TypeVar, cast
from urllib.parse import parse_qs, urlparse

import jwt as pyjwt
from fastapi import FastAPI
from fastapi.testclient import TestClient

from thepuroidc.application.userinfo import (
    UserInfoConfig,
    UserInfoError,
    UserInfoRequest,
    UserInfoResponse,
    UserInfoUseCase,
)
from thepuroidc.domain.authorization import Scope
from thepuroidc.domain.jwks import JWTAlgorithm
from thepuroidc.domain.userinfo import UserClaims
from thepuroidc.infrastructure.claims import InMemoryClaimsProvider
from thepuroidc.infrastructure.jwks import DefaultKeyManager
from thepuroidc.infrastructure.persistence.memory import InMemoryKeyPairRepository
from thepuroidc.infrastructure.persistence.users_memory import InMemoryUserRepository
from thepuroidc.infrastructure.settings import Settings
from thepuroidc.infrastructure.tokens import PyJWTTokenManager
from thepuroidc.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_CLIENT_JSON = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile email",
    "client_type": "confidential",
}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


def _make_token_manager() -> PyJWTTokenManager:
    """Construit un gestionnaire de jetons isolé avec ses propres clés."""
    return PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))


def _access_token(
    token_manager: PyJWTTokenManager,
    *,
    subject: str = "alice",
    issuer: str = _ISSUER,
    scopes: frozenset[Scope] = frozenset({Scope.OPENID}),
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
            scopes=scopes,
        )
    )


class TestValidateAccessToken:
    """Couvre les branches de PyJWTTokenManager.validate_access_token."""

    def test_returns_claims_for_valid_token(self) -> None:
        tm = _make_token_manager()
        token = _access_token(tm)

        claims = run(tm.validate_access_token(token=token, issuer=_ISSUER))

        assert claims is not None
        assert claims["sub"] == "alice"
        assert claims["aud"] == "web-app"
        assert claims["scope"] == "openid"

    def test_rejects_expired_token(self) -> None:
        from datetime import datetime, timedelta, timezone

        tm = _make_token_manager()
        token = run(
            tm.create_access_token(
                algorithm=JWTAlgorithm.RS256,
                issuer=_ISSUER,
                subject="alice",
                audience="web-app",
                expires_at=int((datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp()),
                issued_at=1000000000,
                scopes=frozenset({Scope.OPENID}),
            )
        )

        assert run(tm.validate_access_token(token=token, issuer=_ISSUER)) is None

    def test_rejects_wrong_issuer(self) -> None:
        tm = _make_token_manager()
        token = _access_token(tm, issuer="https://other.example")

        assert run(tm.validate_access_token(token=token, issuer=_ISSUER)) is None

    def test_rejects_tampered_token(self) -> None:
        tm = _make_token_manager()
        token = _access_token(tm)

        assert run(tm.validate_access_token(token=token + "x", issuer=_ISSUER)) is None

    def test_rejects_malformed_token(self) -> None:
        tm = _make_token_manager()
        value = "not-a-jwt"
        assert run(tm.validate_access_token(token=value, issuer=_ISSUER)) is None

    def test_rejects_unsupported_algorithm(self) -> None:
        tm = _make_token_manager()
        token = cast(str, pyjwt.encode({"sub": "alice"}, "s" * 32, algorithm="HS256"))

        assert run(tm.validate_access_token(token=token, issuer=_ISSUER)) is None

    def test_rejects_token_with_unknown_kid(self) -> None:
        signer = _make_token_manager()
        verifier = _make_token_manager()
        token = _access_token(signer)

        assert run(verifier.validate_access_token(token=token, issuer=_ISSUER)) is None

    def test_rejects_token_when_only_other_algorithm_available(self) -> None:
        km = DefaultKeyManager(InMemoryKeyPairRepository())
        run(km.generate_key_pair(256, JWTAlgorithm.ES256))
        verifier = PyJWTTokenManager(km)
        token = _access_token(_make_token_manager())

        assert run(verifier.validate_access_token(token=token, issuer=_ISSUER)) is None

    def test_rejects_token_when_kid_mismatches_all_keys(self) -> None:
        km = DefaultKeyManager(InMemoryKeyPairRepository())
        run(km.generate_key_pair(2048, JWTAlgorithm.RS256))
        run(km.generate_key_pair(2048, JWTAlgorithm.RS256))
        verifier = PyJWTTokenManager(km)
        token = _access_token(_make_token_manager())

        assert run(verifier.validate_access_token(token=token, issuer=_ISSUER)) is None


class TestUserInfoUseCase:
    """Couvre les branches du use case UserInfoUseCase."""

    def _claims_provider(
        self, profiles: dict[str, dict[str, object]] | None = None
    ) -> InMemoryClaimsProvider:
        """Construit un ClaimsProvider adossé à un user store mémoire seedé."""
        repository = InMemoryUserRepository()
        if profiles:
            run(
                repository.save_all(
                    [
                        UserClaims(subject=subject, claims=claims)
                        for subject, claims in profiles.items()
                    ]
                )
            )
        return InMemoryClaimsProvider(repository)

    def _result(
        self,
        tm: PyJWTTokenManager,
        token: str,
        profiles: dict[str, dict[str, object]] | None = None,
    ) -> UserInfoResponse | UserInfoError:
        usecase = UserInfoUseCase(
            UserInfoConfig(issuer=_ISSUER),
            tm,
            self._claims_provider(profiles),
        )
        return run(usecase.execute(UserInfoRequest(access_token=token)))

    def test_returns_sub_only_for_openid_scope(self) -> None:
        tm = _make_token_manager()
        token = _access_token(tm)

        result = self._result(tm, token, {"alice": {"name": "Alice", "email": "a@b.com"}})

        assert result.claims == {"sub": "alice"}

    def test_returns_sub_only_when_subject_unknown(self) -> None:
        tm = _make_token_manager()
        token = _access_token(tm, subject="ghost")

        result = self._result(tm, token, {"alice": {"name": "Alice"}})

        assert result.claims == {"sub": "ghost"}

    def test_returns_profile_and_email_claims_when_allowed(self) -> None:
        tm = _make_token_manager()
        token = _access_token(tm, scopes=frozenset({Scope.OPENID, Scope.PROFILE, Scope.EMAIL}))

        result = self._result(
            tm,
            token,
            {
                "alice": {
                    "name": "Alice Martin",
                    "given_name": "Alice",
                    "email": "alice@example.com",
                    "email_verified": True,
                    "address": {"formatted": "12 rue de la Paix"},
                }
            },
        )

        assert result.claims["sub"] == "alice"
        assert result.claims["name"] == "Alice Martin"
        assert result.claims["email"] == "alice@example.com"
        assert "address" not in result.claims

    def test_returns_address_claims_when_scope_granted(self) -> None:
        tm = _make_token_manager()
        token = _access_token(tm, scopes=frozenset({Scope.OPENID, Scope.PROFILE, Scope.ADDRESS}))

        result = self._result(
            tm,
            token,
            {
                "alice": {
                    "name": "Alice Martin",
                    "email": "alice@example.com",
                    "address": {"formatted": "12 rue de la Paix"},
                }
            },
        )

        assert result.claims["address"] == {"formatted": "12 rue de la Paix"}
        assert "email" not in result.claims

    def test_returns_invalid_token_for_unreadable_token(self) -> None:
        tm = _make_token_manager()

        result = self._result(tm, "garbage")

        assert result.error == "invalid_token"

    def test_returns_invalid_token_when_sub_missing(self) -> None:
        class _NoSubTokenManager:
            async def validate_access_token(
                self, *, token: str, issuer: str
            ) -> dict[str, object] | None:
                return {"scope": "openid"}

        usecase = UserInfoUseCase(
            UserInfoConfig(issuer=_ISSUER),
            _NoSubTokenManager(),  # type: ignore[arg-type]
            self._claims_provider(),
        )
        value = "useless-token"
        result = run(usecase.execute(UserInfoRequest(access_token=value)))

        assert result.error == "invalid_token"


class TestUserInfoEndpoint:
    """Couvre l'endpoint HTTP ``GET /userinfo`` (RFC 6750)."""

    def _app(self) -> FastAPI:
        return create_app(
            Settings(
                issuer=_ISSUER,
                base_url=_ISSUER,
                jwks_algorithms=("RS256",),
                clients_seed=(_CLIENT_JSON,),
            )
        )

    @staticmethod
    def _s256_challenge(verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def _access_token(self, client: TestClient) -> str:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "web-app",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile email",
                "code_challenge": self._s256_challenge("verifier-verifier"),
                "code_challenge_method": "S256",
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
                "client_secret": "super-secret",
                "code_verifier": "verifier-verifier",
            },
        )
        payload = response.json()
        return str(payload["access_token"])

    def test_returns_claims_for_valid_bearer_token(self) -> None:
        with TestClient(self._app()) as client:
            token = self._access_token(client)
            response = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        claims = response.json()
        assert claims["sub"] == "web-app"
        assert "name" in claims
        assert claims["email_verified"] is True

    def test_rejects_missing_authorization_header(self) -> None:
        with TestClient(self._app()) as client:
            response = client.get("/userinfo")

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_request"
        assert response.headers["www-authenticate"].startswith("Bearer error=")

    def test_rejects_non_bearer_scheme(self) -> None:
        with TestClient(self._app()) as client:
            response = client.get("/userinfo", headers={"Authorization": "Basic dXNlcjpwYXNz"})

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_request"

    def test_rejects_invalid_token(self) -> None:
        with TestClient(self._app()) as client:
            response = client.get("/userinfo", headers={"Authorization": "Bearer invalid-token"})

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_token"

    def test_discovery_advertises_supported_claims_and_scopes(self) -> None:
        with TestClient(self._app()) as client:
            response = client.get("/.well-known/openid-configuration")

        metadata = response.json()
        assert "name" in metadata["claims_supported"]
        assert "email_verified" in metadata["claims_supported"]
        assert metadata["scopes_supported"] == [
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
        ]
