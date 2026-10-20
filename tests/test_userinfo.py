"""Tests de la feature ID Token + UserInfo (validation JWT, endpoint /userinfo)."""

import asyncio
import base64
import hashlib
import json
from collections.abc import Awaitable
from typing import TypeVar, cast
from urllib.parse import parse_qs, urlparse

import jwt as pyjwt
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from puridentityserver.application.userinfo import (
    UserInfoConfig,
    UserInfoError,
    UserInfoRequest,
    UserInfoResponse,
    UserInfoUseCase,
)
from puridentityserver.domain.authorization import Client, Scope
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.domain.revocation import RevokedToken, token_hash
from puridentityserver.domain.userinfo import UserClaims
from puridentityserver.infrastructure.claims import UserStoreClaimsProvider
from puridentityserver.infrastructure.jwks import DefaultKeyManager, first_active_key
from puridentityserver.infrastructure.persistence.memory.clients import (
    InMemoryClientRepository,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.memory.revoked_tokens import (
    InMemoryRevokedTokenRepository,
)
from puridentityserver.infrastructure.persistence.memory.users import InMemoryUserRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_CLIENT_JSON = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile email",
    "client_type": "confidential",
}

_SIGNED_CLIENT_JSON = {
    "client_id": "signed-app",
    "client_secret": "signed-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile email",
    "client_type": "confidential",
    "userinfo_signed_response_alg": "RS256",
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
    ) -> UserStoreClaimsProvider:
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
        return UserStoreClaimsProvider(repository)

    def _result(
        self,
        tm: PyJWTTokenManager,
        token: str,
        profiles: dict[str, dict[str, object]] | None = None,
        blacklist: InMemoryRevokedTokenRepository | None = None,
    ) -> UserInfoResponse | UserInfoError:
        usecase = UserInfoUseCase(
            UserInfoConfig(issuer=_ISSUER),
            tm,
            self._claims_provider(profiles),
            blacklist or InMemoryRevokedTokenRepository(),
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

    def test_returns_roles_claim_when_profile_scope_granted(self) -> None:
        tm = _make_token_manager()
        token = _access_token(tm, scopes=frozenset({Scope.OPENID, Scope.PROFILE}))

        result = self._result(
            tm,
            token,
            {"alice": {"name": "Alice Martin", "roles": ["admin", "member"]}},
        )

        assert result.claims["sub"] == "alice"
        assert result.claims["roles"] == ["admin", "member"]

    def test_hides_roles_claim_without_profile_scope(self) -> None:
        tm = _make_token_manager()
        token = _access_token(tm, scopes=frozenset({Scope.OPENID, Scope.EMAIL}))

        result = self._result(
            tm,
            token,
            {"alice": {"name": "Alice Martin", "roles": ["admin"]}},
        )

        assert result.claims == {"sub": "alice"}

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
            InMemoryRevokedTokenRepository(),
        )
        value = "useless-token"
        result = run(usecase.execute(UserInfoRequest(access_token=value)))

        assert result.error == "invalid_token"

    def test_returns_invalid_token_for_revoked_token(self) -> None:
        from datetime import datetime, timedelta, timezone

        tm = _make_token_manager()
        token = _access_token(tm)
        blacklist = InMemoryRevokedTokenRepository()
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)
        run(blacklist.save(RevokedToken(token_hash=token_hash(token), expires_at=expires)))

        result = self._result(tm, token, blacklist=blacklist)

        assert result.error == "invalid_token"


class TestSignedUserinfo:
    """Réponses UserInfo signées ``application/jwt`` (OIDC Core 1.0 §5.3.1, §5.3.2)."""

    def _usecase(
        self, client: Client
    ) -> tuple[UserInfoUseCase, PyJWTTokenManager, DefaultKeyManager]:
        """Construit le use case avec ``client`` dans le registre et ses propres clés."""
        key_manager = DefaultKeyManager(InMemoryKeyPairRepository())
        token_manager = PyJWTTokenManager(key_manager)
        clients = InMemoryClientRepository()
        run(clients.save(client))
        usecase = UserInfoUseCase(
            UserInfoConfig(issuer=_ISSUER),
            token_manager,
            UserStoreClaimsProvider(InMemoryUserRepository()),
            InMemoryRevokedTokenRepository(),
            clients=clients,
        )
        return usecase, token_manager, key_manager

    @staticmethod
    def _token(token_manager: PyJWTTokenManager, *, client_id: str) -> str:
        """Émet un access token portant le claim privé ``client_id`` posé à l'émission."""
        return run(
            token_manager.create_access_token(
                algorithm=JWTAlgorithm.RS256,
                issuer=_ISSUER,
                subject="alice",
                audience=client_id,
                expires_at=9999999999,
                issued_at=1000000000,
                scopes=frozenset({Scope.OPENID}),
                additional_claims={"client_id": client_id},
            )
        )

    def test_signs_response_for_rs256_client(self) -> None:
        """§5.3.2 : ``iss``/``aud``/``iat`` en plus des claims, signature RS256 au ``kid``."""
        client = Client(client_id="signed-app", userinfo_signed_response_alg="RS256")
        usecase, token_manager, key_manager = self._usecase(client)
        token = self._token(token_manager, client_id="signed-app")

        result = run(usecase.execute(UserInfoRequest(access_token=token)))

        assert not isinstance(result, UserInfoError)
        assert result.claims == {"sub": "alice"}
        header = pyjwt.get_unverified_header(result.signed_jwt)
        assert header["alg"] == "RS256"
        assert header["kid"]
        key = run(first_active_key(key_manager, JWTAlgorithm.RS256))
        payload = pyjwt.decode(
            result.signed_jwt,
            key.public_key_pem,
            algorithms=["RS256"],
            audience="signed-app",
            issuer=_ISSUER,
        )
        assert payload["iss"] == _ISSUER
        assert payload["aud"] == "signed-app"
        assert payload["sub"] == "alice"
        assert payload["iat"] > 0

    def test_returns_json_for_client_without_registered_alg(self) -> None:
        """Sans ``userinfo_signed_response_alg``, la réponse reste en JSON (§5.3.2)."""
        client = Client(client_id="plain-app")
        usecase, token_manager, _ = self._usecase(client)
        token = self._token(token_manager, client_id="plain-app")

        result = run(usecase.execute(UserInfoRequest(access_token=token)))

        assert not isinstance(result, UserInfoError)
        assert result.signed_jwt == ""

    def test_returns_json_for_alg_not_published_by_op(self) -> None:
        """§5.3.1 : un algorithme non publié (``HS256``) n'impose pas de signature."""
        client = Client(client_id="hmac-app", userinfo_signed_response_alg="HS256")
        usecase, token_manager, _ = self._usecase(client)
        token = self._token(token_manager, client_id="hmac-app")

        result = run(usecase.execute(UserInfoRequest(access_token=token)))

        assert not isinstance(result, UserInfoError)
        assert result.signed_jwt == ""

    def test_returns_json_when_access_token_has_no_client_claim(self) -> None:
        """Sans claim privé ``client_id``, le client émetteur n'est pas résolvable."""
        client = Client(client_id="signed-app", userinfo_signed_response_alg="RS256")
        usecase, token_manager, _ = self._usecase(client)
        token = run(
            token_manager.create_access_token(
                algorithm=JWTAlgorithm.RS256,
                issuer=_ISSUER,
                subject="alice",
                audience="signed-app",
                expires_at=9999999999,
                issued_at=1000000000,
                scopes=frozenset({Scope.OPENID}),
            )
        )

        result = run(usecase.execute(UserInfoRequest(access_token=token)))

        assert not isinstance(result, UserInfoError)
        assert result.signed_jwt == ""

    def test_userinfo_jwt_primes_iss_and_aud_over_claims(self) -> None:
        """§5.3.2 : ``iss``/``aud``/``iat`` ne peuvent pas être écrasés par les claims."""
        token_manager = _make_token_manager()

        token = run(
            token_manager.create_userinfo_jwt(
                issuer=_ISSUER,
                audience="signed-app",
                algorithm=JWTAlgorithm.RS256,
                claims={"sub": "alice", "iss": "https://evil.example", "aud": "evil"},
            )
        )

        payload = pyjwt.decode(token, options={"verify_signature": False})
        assert payload["iss"] == _ISSUER
        assert payload["aud"] == "signed-app"
        assert payload["sub"] == "alice"
        assert pyjwt.get_unverified_header(token)["alg"] == "RS256"


class TestUserInfoEndpoint:
    """Couvre les endpoints HTTP ``GET``/``POST /userinfo`` (RFC 6750)."""

    def _app(self, *, clients_seed: tuple[dict[str, object], ...] = (_CLIENT_JSON,)) -> FastAPI:
        return create_app(
            Settings(
                issuer=_ISSUER,
                base_url=_ISSUER,
                jwks_algorithms=("RS256",),
                clients_seed=clients_seed,
                api_resources_seed=(),
                identity_seed_users={
                    "alice": {"email": "alice@example.com", "password": "password"}
                },
            )
        )

    @staticmethod
    def _s256_challenge(verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def _access_token(
        self,
        client: TestClient,
        *,
        client_id: str = "web-app",
        client_secret: str = "super-secret",  # ruff: ignore[hardcoded-password-default] (secret du client seed de test)
        redirect_uri: str = "https://app.example/callback",
    ) -> str:
        auth = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
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
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
                "code_verifier": "verifier-verifier",
            },
        )
        payload = response.json()
        return str(payload["access_token"])

    def test_serves_signed_jwt_for_client_with_userinfo_alg(self) -> None:
        """§5.3.2 : client RS256 → ``/userinfo`` en ``application/jwt`` vérifiable au JWKS."""
        with TestClient(self._app(clients_seed=(_CLIENT_JSON, _SIGNED_CLIENT_JSON))) as client:
            metadata = client.get("/.well-known/openid-configuration").json()
            assert metadata["userinfo_signing_alg_values_supported"] == ["RS256"]
            login = client.post(
                "/login",
                data={"username": "alice@example.com", "password": "password", "next": "/"},
                follow_redirects=False,
            )
            assert login.status_code == 302
            token = self._access_token(
                client, client_id="signed-app", client_secret="signed-secret"
            )
            response = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})
            jwks = client.get("/.well-known/jwks.json").json()

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/jwt")
        header = pyjwt.get_unverified_header(response.text)
        assert header["alg"] == "RS256"
        jwk = next(key for key in jwks["keys"] if key["kid"] == header["kid"])
        payload = pyjwt.decode(
            response.text,
            RSAAlgorithm.from_jwk(json.dumps(jwk)),
            algorithms=["RS256"],
            audience="signed-app",
            issuer=_ISSUER,
        )
        assert payload["iss"] == _ISSUER
        assert payload["aud"] == "signed-app"
        assert payload["sub"]  # sujet réel émis après login

    def test_returns_claims_for_valid_bearer_token(self) -> None:
        with TestClient(self._app()) as client:
            token = self._access_token(client)
            response = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        claims = response.json()
        assert claims["sub"] == ""
        assert len(claims) == 1

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

    def test_post_accepts_access_token_in_body(self) -> None:
        """RFC 6750 §2.1.2 : POST form avec ``access_token`` en corps, sans en-tête."""
        with TestClient(self._app()) as client:
            token = self._access_token(client)
            response = client.post("/userinfo", data={"access_token": token})

        assert response.status_code == 200
        assert response.json()["sub"] == ""

    def test_post_header_takes_precedence_over_body(self) -> None:
        """L'en-tête ``Authorization`` prime sur le corps form (RFC 6750 §2.1)."""
        with TestClient(self._app()) as client:
            token = self._access_token(client)
            response = client.post(
                "/userinfo",
                data={"access_token": "token-du-corps"},
                headers={"Authorization": f"Bearer {token}"},
            )

        assert response.status_code == 200
        assert response.json()["sub"] == ""

    def test_post_rejects_missing_token_in_header_and_body(self) -> None:
        with TestClient(self._app()) as client:
            response = client.post("/userinfo")

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_request"
        assert response.headers["www-authenticate"].startswith("Bearer error=")

    def test_discovery_advertises_supported_claims_and_scopes(self) -> None:
        with TestClient(self._app()) as client:
            response = client.get("/.well-known/openid-configuration")

        metadata = response.json()
        assert "name" in metadata["claims_supported"]
        assert "email_verified" in metadata["claims_supported"]
        assert "roles" in metadata["claims_supported"]
        assert metadata["scopes_supported"] == [
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
        ]
