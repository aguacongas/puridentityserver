"""Tests des Resource Indicators (RFC 8707) et du resource server intégré (FAPI-R-6.2.1)."""

import asyncio
import base64
import hashlib
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar
from urllib.parse import parse_qs, urlencode, urlparse
from uuid import UUID

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.authorize import AuthorizeRequest
from puridentityserver.application.backchannel_authorize import (
    AuthenticationAck,
    BackchannelAuthenticationConfig,
    BackchannelAuthenticationError,
    BackchannelAuthenticationParams,
    BackchannelAuthenticationUseCase,
)
from puridentityserver.application.par import (
    PushedAuthorizationConfig,
    PushedAuthorizationUseCase,
    PushError,
    PushResult,
)
from puridentityserver.application.protected_resource import (
    ProtectedResourceConfig,
    ProtectedResourceError,
    ProtectedResourceRequest,
    ProtectedResourceResponse,
    ProtectedResourceUseCase,
)
from puridentityserver.application.resource_indicators import (
    encode_resource_parameter,
    is_resource_uri,
    parse_resource_parameter,
    resource_audience,
)
from puridentityserver.application.scope_registry import ScopeRegistry
from puridentityserver.application.token import (
    TokenConfig,
    TokenError,
    TokenRequest,
    TokenResponse,
    TokenUseCase,
)
from puridentityserver.domain.api_resource import ApiResource
from puridentityserver.domain.authorization import (
    AuthorizationCode,
    BackchannelAuthenticationRequest,
    Client,
    ClientType,
    RefreshToken,
    Scope,
)
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.domain.revocation import RevokedToken, token_hash
from puridentityserver.domain.userinfo import UserClaims
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.api_resources import (
    InMemoryApiResourceRepository,
)
from puridentityserver.infrastructure.persistence.memory.backchannel_authentications import (
    InMemoryBackchannelAuthenticationRepository,
)
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.persistence.memory.codes import (
    InMemoryAuthorizationCodeRepository,
)
from puridentityserver.infrastructure.persistence.memory.device_authorizations import (
    InMemoryDeviceAuthorizationRepository,
)
from puridentityserver.infrastructure.persistence.memory.identity_resources import (
    InMemoryIdentityResourceRepository,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.memory.pushed_authorizations import (
    InMemoryPushedAuthorizationRepository,
)
from puridentityserver.infrastructure.persistence.memory.refresh_tokens import (
    InMemoryRefreshTokenRepository,
)
from puridentityserver.infrastructure.persistence.memory.revoked_tokens import (
    InMemoryRevokedTokenRepository,
)
from puridentityserver.infrastructure.persistence.memory.users import InMemoryUserRepository
from puridentityserver.infrastructure.persistence.sql.api_resources import SQLApiResourceRepository
from puridentityserver.infrastructure.persistence.sql.backchannel_authentications import (
    SQLBackchannelAuthenticationRepository,
)
from puridentityserver.infrastructure.persistence.sql.codes import (
    SQLAuthorizationCodeRepository,
)
from puridentityserver.infrastructure.persistence.sql.refresh_tokens import (
    SQLRefreshTokenRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_CLIENT_SECRET = "super-secret"
_REDIRECT_URI = "https://app.example/callback"
_RESOURCE_A = "https://api.example/protected"
_RESOURCE_B = "https://api.example/other"
_UNKNOWN_RESOURCE = "https://unknown.example/api"

_CLIENT_SEED: tuple[dict[str, object], ...] = (
    {
        "client_id": "web-app",
        "client_secret": _CLIENT_SECRET,
        "redirect_uris": [_REDIRECT_URI],
        "scopes": "openid profile",
        "client_type": "confidential",
    },
)

_API_SEED: tuple[dict[str, object], ...] = (
    {"name": "sample-api", "scopes": ["api.read"], "indicator": _RESOURCE_A},
    {"name": "other-api", "scopes": ["api.write"], "indicator": _RESOURCE_B},
)

_CONFIDENTIAL_CLIENT = Client(
    client_id="web-app",
    redirect_uris=frozenset({_REDIRECT_URI}),
    scopes=frozenset({Scope.OPENID, Scope.PROFILE, Scope.OFFLINE_ACCESS}),
    client_type=ClientType.CONFIDENTIAL,
    client_secret_hash=hashlib.sha256(_CLIENT_SECRET.encode("utf-8")).hexdigest(),
)

_CIBA_CLIENT = Client(
    client_id="ciba-app",
    scopes=frozenset({Scope.OPENID, Scope.PROFILE, Scope.OFFLINE_ACCESS}),
    client_type=ClientType.CONFIDENTIAL,
    client_secret_hash=hashlib.sha256(_CLIENT_SECRET.encode("utf-8")).hexdigest(),
    backchannel_token_delivery_mode="poll",
)

_PAR_CLIENT = Client(
    client_id="par-app",
    redirect_uris=frozenset({_REDIRECT_URI}),
    scopes=frozenset({Scope.OPENID}),
    client_type=ClientType.PUBLIC,
)

_PAR_PARAMS: dict[str, str] = {
    "response_type": "code",
    "client_id": "par-app",
    "redirect_uri": _REDIRECT_URI,
    "scope": "openid",
    "state": "st-1",
}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def _future_expiry() -> datetime:
    """Date d'expiration dans le futur (évite l'expiration immédiate du défaut)."""
    return datetime.now(timezone.utc) + timedelta(minutes=10)


def _s256_challenge(verifier: str) -> str:
    """Calcule le challenge PKCE S256 de `verifier`."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _redirect_query(redirect_url: str) -> dict[str, list[str]]:
    """Décode les paramètres de la query de redirection."""
    return parse_qs(urlparse(redirect_url).query)


def _aud(token: str) -> object:
    """Retourne le claim `aud` décodé d'un jeton (signature ignorée)."""
    payload = jwt.decode(token, options={"verify_signature": False})
    return payload["aud"]


def _registry(*resources: ApiResource) -> ScopeRegistry:
    """Construit un registre de scopes contenant les ApiResources de test."""
    identity = InMemoryIdentityResourceRepository()
    api = InMemoryApiResourceRepository()
    for resource in resources:
        run(api.save(resource))
    return ScopeRegistry(identity, api)


def _app(**settings: object) -> FastAPI:
    """Assemble une application mémoire avec les seeds de resources et de client."""
    values: dict[str, object] = {
        "issuer": _ISSUER,
        "base_url": _ISSUER,
        "jwks_algorithms": ("RS256",),
        "api_resources_seed": _API_SEED,
        "clients_seed": _CLIENT_SEED,
    }
    values.update(settings)
    return create_app(Settings(**values))  # type: ignore[arg-type]


def _authorize_query(**extra: str) -> dict[str, str]:
    """Construit une requête d'autorisation valide (PKCE inclus)."""
    params = {
        "response_type": "code",
        "client_id": "web-app",
        "redirect_uri": _REDIRECT_URI,
        "scope": "openid profile",
        "state": "st-1",
        "code_challenge": _s256_challenge("verifier-verifier"),
        "code_challenge_method": "S256",
    }
    params.update(extra)
    return params


def _exchange_authorization_code(client: TestClient, code: str) -> dict[str, object]:
    """Échange un code d'autorisation contre les jetons du client test."""
    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": _REDIRECT_URI,
            "client_id": "web-app",
            "client_secret": _CLIENT_SECRET,
            "code_verifier": "verifier-verifier",
        },
    )
    assert response.status_code == 200
    return response.json()


def _client_credentials_token(client: TestClient) -> str:
    """Émet un access token par le grant `client_credentials`."""
    response = client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "web-app",
            "client_secret": _CLIENT_SECRET,
            "scope": "openid profile",
        },
    )
    assert response.status_code == 200
    return str(response.json()["access_token"])


def _make_token_usecase(
    scope_registry: ScopeRegistry | None = None,
) -> tuple[TokenUseCase, InMemoryAuthorizationCodeRepository, InMemoryRefreshTokenRepository]:
    """Construit un TokenUseCase mémoire avec le client confidentiel test."""
    clients = InMemoryClientRepository()
    codes = InMemoryAuthorizationCodeRepository()
    refresh_tokens = InMemoryRefreshTokenRepository()
    token_manager = PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))
    run(clients.save(_CONFIDENTIAL_CLIENT))
    usecase = TokenUseCase(
        TokenConfig(issuer=_ISSUER, signing_algorithm=JWTAlgorithm.RS256),
        clients,
        codes,
        token_manager,
        refresh_tokens,
        InMemoryDeviceAuthorizationRepository(),
        scope_registry=scope_registry,
    )
    return usecase, codes, refresh_tokens


def _seed_code(
    codes: InMemoryAuthorizationCodeRepository,
    *,
    resource_uris: tuple[str, ...] = (),
    scopes: frozenset[Scope] = frozenset({Scope.OPENID, Scope.OFFLINE_ACCESS}),
) -> None:
    """Enregistre un code d'autorisation échangeable par le client test."""
    run(
        codes.save(
            AuthorizationCode(
                code="code-ri",
                client_id=_CONFIDENTIAL_CLIENT.client_id,
                redirect_uri=_REDIRECT_URI,
                subject="alice",
                scopes=scopes,
                expires_at=_future_expiry(),
                resource_uris=resource_uris,
            )
        )
    )


def _make_backchannel(
    scope_registry: ScopeRegistry | None = None,
) -> tuple[BackchannelAuthenticationUseCase, InMemoryBackchannelAuthenticationRepository]:
    """Construit le use case `/bc-authorize` avec un utilisateur hinté."""
    clients = InMemoryClientRepository()
    requests = InMemoryBackchannelAuthenticationRepository()
    users = InMemoryUserRepository()
    run(users.save(UserClaims(subject="alice", claims={"email": "alice@example.com"})))
    usecase = BackchannelAuthenticationUseCase(
        BackchannelAuthenticationConfig(
            issuer=_ISSUER,
            base_url=_ISSUER,
            ttl_seconds=600,
            interval_seconds=5,
        ),
        clients,
        users,
        requests,
        scope_registry=scope_registry,
    )
    run(clients.save(_CIBA_CLIENT))
    return usecase, requests


def _ciba_params(**extra: str) -> BackchannelAuthenticationParams:
    """Construit des paramètres CIBA valides (login_hint email)."""
    base: dict[str, str] = {
        "client_id": "ciba-app",
        "client_secret": _CLIENT_SECRET,
        "scope": "openid profile",
        "login_hint": "alice@example.com",
    }
    base.update(extra)
    return BackchannelAuthenticationParams(**base)


def _make_par(
    scope_registry: ScopeRegistry | None = None,
) -> tuple[PushedAuthorizationUseCase, InMemoryPushedAuthorizationRepository]:
    """Construit le use case PAR mémoire avec le client public test."""
    clients = InMemoryClientRepository()
    pushed = InMemoryPushedAuthorizationRepository()
    run(clients.save(_PAR_CLIENT))
    usecase = PushedAuthorizationUseCase(
        PushedAuthorizationConfig(ttl_seconds=90),
        clients,
        pushed,
        scope_registry=scope_registry,
    )
    return usecase, pushed


class TestResourceIndicatorHelpers:
    """Couvre les helpers RFC 8707 (lecture, encodage, audience)."""

    def test_parse_empty_returns_empty_tuple(self) -> None:
        assert parse_resource_parameter("") == ()
        assert parse_resource_parameter("   ") == ()

    def test_parse_single_uri_is_stripped(self) -> None:
        assert parse_resource_parameter(f"  {_RESOURCE_A} ") == (_RESOURCE_A,)

    def test_parse_json_array_dedupes_preserving_order(self) -> None:
        raw = f'["{_RESOURCE_B}", "{_RESOURCE_A}", "{_RESOURCE_B}"]'

        assert parse_resource_parameter(raw) == (_RESOURCE_B, _RESOURCE_A)

    def test_parse_invalid_json_falls_back_to_raw_value(self) -> None:
        assert parse_resource_parameter("[not-json") == ("[not-json",)

    def test_parse_stringifies_non_string_scalars(self) -> None:
        assert parse_resource_parameter(f'["{_RESOURCE_A}", 42]') == (_RESOURCE_A, "42")

    def test_parse_empty_json_array_returns_empty_tuple(self) -> None:
        assert parse_resource_parameter("[]") == ()

    def test_encode_empty_returns_empty_string(self) -> None:
        assert encode_resource_parameter([]) == ""
        assert encode_resource_parameter(["  "]) == ""

    def test_encode_single_value_passthrough(self) -> None:
        assert encode_resource_parameter([_RESOURCE_A]) == _RESOURCE_A

    def test_encode_ignores_blanks_and_dedupes(self) -> None:
        encoded = encode_resource_parameter([_RESOURCE_A, " ", _RESOURCE_A, _RESOURCE_B])

        assert parse_resource_parameter(encoded) == (_RESOURCE_A, _RESOURCE_B)

    def test_encode_parse_roundtrip_multiple(self) -> None:
        values = (_RESOURCE_A, _RESOURCE_B)

        assert parse_resource_parameter(encode_resource_parameter(list(values))) == values

    def test_resource_audience_single_is_string(self) -> None:
        assert resource_audience([_RESOURCE_A]) == _RESOURCE_A

    def test_resource_audience_multiple_is_list(self) -> None:
        assert resource_audience([_RESOURCE_B, _RESOURCE_A]) == [_RESOURCE_B, _RESOURCE_A]

    def test_is_resource_uri_accepts_absolute_uris(self) -> None:
        assert is_resource_uri(_RESOURCE_A) is True
        assert is_resource_uri("http://127.0.0.1:8000/protected-resource") is True

    def test_is_resource_uri_rejects_relative_empty_and_fragment(self) -> None:
        assert is_resource_uri("") is False
        assert is_resource_uri("/relative/path") is False
        assert is_resource_uri(f"{_RESOURCE_A}#fragment") is False


class TestSettingsApiResourceIndicator:
    """Couvre la lecture du champ `indicator` dans le seed de configuration."""

    def test_seed_parses_valid_indicator(self) -> None:
        settings = Settings(
            issuer=_ISSUER,
            api_resources_seed=(
                {"name": "sample-api", "scopes": ["api.read"], "indicator": _RESOURCE_A},
            ),
        )

        assert settings.seed_api_resources[0].indicator == _RESOURCE_A

    def test_seed_rejects_invalid_indicator(self) -> None:
        settings = Settings(
            issuer=_ISSUER,
            api_resources_seed=(
                {"name": "sample-api", "scopes": ["api.read"], "indicator": "/relative"},
            ),
        )

        with pytest.raises(ValueError, match="Indicator RFC 8707"):
            _ = settings.seed_api_resources


class TestAuthorizeResourceIndicators:
    """Couvre le contrôle de `resource` sur /authorize puis l'audience au /token."""

    def test_registered_resource_issues_code_and_sets_aud(self) -> None:
        with TestClient(_app()) as client:
            auth = client.get(
                "/authorize",
                params=_authorize_query(resource=_RESOURCE_A),
                follow_redirects=False,
            )
            query = _redirect_query(auth.headers["location"])
            token = _exchange_authorization_code(client, query["code"][0])

        assert auth.status_code == 302
        assert "error" not in query
        assert _aud(str(token["access_token"])) == _RESOURCE_A

    def test_unknown_resource_redirects_with_invalid_target(self) -> None:
        with TestClient(_app()) as client:
            auth = client.get(
                "/authorize",
                params=_authorize_query(resource=_UNKNOWN_RESOURCE),
                follow_redirects=False,
            )

        query = _redirect_query(auth.headers["location"])
        assert auth.status_code == 302
        assert query["error"] == ["invalid_target"]
        assert query["state"] == ["st-1"]

    def test_malformed_resource_redirects_with_invalid_target(self) -> None:
        with TestClient(_app()) as client:
            auth = client.get(
                "/authorize",
                params=_authorize_query(resource="not-a-uri"),
                follow_redirects=False,
            )

        query = _redirect_query(auth.headers["location"])
        assert query["error"] == ["invalid_target"]

    def test_fragmented_resource_redirects_with_invalid_target(self) -> None:
        with TestClient(_app()) as client:
            auth = client.get(
                "/authorize",
                params=_authorize_query(resource=f"{_RESOURCE_A}#frag"),
                follow_redirects=False,
            )

        query = _redirect_query(auth.headers["location"])
        assert query["error"] == ["invalid_target"]

    def test_get_repeated_resources_issue_code_and_aud_list(self) -> None:
        with TestClient(_app()) as client:
            auth = client.get(
                "/authorize",
                params={**_authorize_query(), "resource": [_RESOURCE_A, _RESOURCE_B]},
                follow_redirects=False,
            )
            query = _redirect_query(auth.headers["location"])
            token = _exchange_authorization_code(client, query["code"][0])

        assert "error" not in query
        assert _aud(str(token["access_token"])) == [_RESOURCE_A, _RESOURCE_B]

    def test_post_repeated_resources_issue_code(self) -> None:
        fields = list(_authorize_query().items())
        fields += [("resource", _RESOURCE_A), ("resource", _RESOURCE_B)]
        with TestClient(_app()) as client:
            auth = client.post(
                "/authorize",
                content=urlencode(fields),
                headers={"content-type": "application/x-www-form-urlencoded"},
                follow_redirects=False,
            )

        query = _redirect_query(auth.headers["location"])
        assert auth.status_code == 302
        assert "error" not in query
        assert query["code"]


class TestTokenResourceBoundaries:
    """Couvre le périmètre `resource` lié au code et au refresh token (RFC 8707 §4)."""

    def test_resource_outside_bound_rejected_and_code_kept(self) -> None:
        usecase, codes, _ = _make_token_usecase()
        _seed_code(codes, resource_uris=(_RESOURCE_A,))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="code-ri",
                    redirect_uri=_REDIRECT_URI,
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                    resource=_RESOURCE_B,
                )
            )
        )

        assert isinstance(result, TokenError)
        assert result.error == "invalid_target"
        stored = run(codes.find_by_code("code-ri"))
        assert stored is not None
        assert stored.is_consumed is False

    def test_resource_equal_to_bound_accepted(self) -> None:
        usecase, codes, _ = _make_token_usecase()
        _seed_code(codes, resource_uris=(_RESOURCE_A,))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="code-ri",
                    redirect_uri=_REDIRECT_URI,
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                    resource=_RESOURCE_A,
                )
            )
        )

        assert isinstance(result, TokenResponse)
        assert _aud(result.access_token) == _RESOURCE_A

    def test_request_may_restrict_bound_to_subset(self) -> None:
        usecase, codes, _ = _make_token_usecase()
        _seed_code(codes, resource_uris=(_RESOURCE_A, _RESOURCE_B))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="code-ri",
                    redirect_uri=_REDIRECT_URI,
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                    resource=_RESOURCE_A,
                )
            )
        )

        assert isinstance(result, TokenResponse)
        assert _aud(result.access_token) == _RESOURCE_A

    def test_silent_request_reuses_bound_resources(self) -> None:
        usecase, codes, _ = _make_token_usecase()
        _seed_code(codes, resource_uris=(_RESOURCE_A,))

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="code-ri",
                    redirect_uri=_REDIRECT_URI,
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert isinstance(result, TokenResponse)
        assert _aud(result.access_token) == _RESOURCE_A

    def test_registered_resource_accepted_when_bound_empty(self) -> None:
        registry = _registry(
            ApiResource(name="sample-api", scopes=frozenset({"api.read"}), indicator=_RESOURCE_A)
        )
        usecase, codes, _ = _make_token_usecase(registry)
        _seed_code(codes)

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="code-ri",
                    redirect_uri=_REDIRECT_URI,
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                    resource=_RESOURCE_A,
                )
            )
        )

        assert isinstance(result, TokenResponse)
        assert _aud(result.access_token) == _RESOURCE_A

    def test_unregistered_resource_rejected_when_bound_empty(self) -> None:
        registry = _registry(
            ApiResource(name="sample-api", scopes=frozenset({"api.read"}), indicator=_RESOURCE_A)
        )
        usecase, codes, _ = _make_token_usecase(registry)
        _seed_code(codes)

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="code-ri",
                    redirect_uri=_REDIRECT_URI,
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                    resource=_UNKNOWN_RESOURCE,
                )
            )
        )

        assert isinstance(result, TokenError)
        assert result.error == "invalid_target"

    def test_malformed_resource_rejected_without_registry(self) -> None:
        usecase, codes, _ = _make_token_usecase()
        _seed_code(codes)

        result = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="code-ri",
                    redirect_uri=_REDIRECT_URI,
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                    resource="not-a-uri",
                )
            )
        )

        assert isinstance(result, TokenError)
        assert result.error == "invalid_target"

    def test_refresh_reuses_bound_resources(self) -> None:
        usecase, codes, _ = _make_token_usecase()
        _seed_code(codes, resource_uris=(_RESOURCE_A,))
        first = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="code-ri",
                    redirect_uri=_REDIRECT_URI,
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )
        assert isinstance(first, TokenResponse)
        assert first.refresh_token

        renewed = run(
            usecase.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token=first.refresh_token,
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )

        assert isinstance(renewed, TokenResponse)
        assert _aud(renewed.access_token) == _RESOURCE_A

    def test_refresh_resource_outside_bound_rejected_and_token_kept(self) -> None:
        usecase, codes, _ = _make_token_usecase()
        _seed_code(codes, resource_uris=(_RESOURCE_A,))
        first = run(
            usecase.execute(
                TokenRequest(
                    grant_type="authorization_code",
                    code="code-ri",
                    redirect_uri=_REDIRECT_URI,
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )
        assert isinstance(first, TokenResponse)
        assert first.refresh_token

        rejected = run(
            usecase.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token=first.refresh_token,
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                    resource=_RESOURCE_B,
                )
            )
        )

        assert isinstance(rejected, TokenError)
        assert rejected.error == "invalid_target"
        retried = run(
            usecase.execute(
                TokenRequest(
                    grant_type="refresh_token",
                    refresh_token=first.refresh_token,
                    client_id="web-app",
                    client_secret=_CLIENT_SECRET,
                )
            )
        )
        assert isinstance(retried, TokenResponse)


class TestBackchannelResourceIndicators:
    """Couvre le contrôle de `resource` sur /bc-authorize (CIBA)."""

    def test_rejects_malformed_resource(self) -> None:
        usecase, _ = _make_backchannel()

        result = run(usecase.execute(_ciba_params(resource="not-a-uri")))

        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_target"

    def test_rejects_unknown_resource(self) -> None:
        registry = _registry(
            ApiResource(name="sample-api", scopes=frozenset({"api.read"}), indicator=_RESOURCE_A)
        )
        usecase, _ = _make_backchannel(registry)

        result = run(usecase.execute(_ciba_params(resource=_UNKNOWN_RESOURCE)))

        assert isinstance(result, BackchannelAuthenticationError)
        assert result.error == "invalid_target"

    def test_persists_resource_uris_on_ticket(self) -> None:
        registry = _registry(
            ApiResource(name="sample-api", scopes=frozenset({"api.read"}), indicator=_RESOURCE_A)
        )
        usecase, requests = _make_backchannel(registry)

        result = run(usecase.execute(_ciba_params(resource=_RESOURCE_A)))

        assert isinstance(result, AuthenticationAck)
        stored = run(requests.find_by_auth_req_id_hash(token_hash(result.auth_req_id)))
        assert stored is not None
        assert stored.resource_uris == (_RESOURCE_A,)


class TestParResourceIndicators:
    """Couvre le transport de `resource` par la Pushed Authorization Request."""

    def test_resolve_restores_resource(self) -> None:
        usecase, _ = _make_par()

        pushed = run(usecase.push({**_PAR_PARAMS, "resource": _RESOURCE_A}))
        assert isinstance(pushed, PushResult)
        resolved = run(usecase.resolve(pushed.request_uri, "par-app"))

        assert isinstance(resolved, AuthorizeRequest)
        assert resolved.resource == _RESOURCE_A

    def test_push_rejects_malformed_resource(self) -> None:
        usecase, _ = _make_par()

        result = run(usecase.push({**_PAR_PARAMS, "resource": "not-a-uri"}))

        assert isinstance(result, PushError)
        assert result.error == "invalid_target"

    def test_push_rejects_unknown_resource(self) -> None:
        registry = _registry(
            ApiResource(name="sample-api", scopes=frozenset({"api.read"}), indicator=_RESOURCE_A)
        )
        usecase, _ = _make_par(registry)

        result = run(usecase.push({**_PAR_PARAMS, "resource": _UNKNOWN_RESOURCE}))

        assert isinstance(result, PushError)
        assert result.error == "invalid_target"

    def test_http_push_registered_resource_returns_request_uri(self) -> None:
        with TestClient(_app()) as client:
            response = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": "web-app",
                    "client_secret": _CLIENT_SECRET,
                    "redirect_uri": _REDIRECT_URI,
                    "scope": "openid profile",
                    "state": "st-1",
                    "resource": _RESOURCE_A,
                },
            )

        assert response.status_code == 201
        assert response.json()["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")

    def test_http_push_unknown_resource_rejected(self) -> None:
        with TestClient(_app()) as client:
            response = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": "web-app",
                    "client_secret": _CLIENT_SECRET,
                    "redirect_uri": _REDIRECT_URI,
                    "scope": "openid profile",
                    "state": "st-1",
                    "resource": _UNKNOWN_RESOURCE,
                },
            )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_target"


class TestProtectedResourceEndpoint:
    """Couvre le resource server intégré GET /protected-resource (FAPI-R-6.2.1)."""

    def test_valid_token_returns_json_and_echoes_interaction_id(self) -> None:
        with TestClient(_app(protected_resource_enabled=True)) as client:
            token = _client_credentials_token(client)
            response = client.get(
                "/protected-resource",
                headers={
                    "Authorization": f"Bearer {token}",
                    "x-fapi-interaction-id": "fid-123",
                },
            )

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["x-fapi-interaction-id"] == "fid-123"
        assert response.headers["cache-control"] == "no-store"
        body = response.json()
        assert body["sub"] == "web-app"
        assert "openid" in body["scope"]

    def test_generates_interaction_id_when_client_omits_it(self) -> None:
        with TestClient(_app(protected_resource_enabled=True)) as client:
            token = _client_credentials_token(client)
            response = client.get(
                "/protected-resource",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert response.status_code == 200
        UUID(response.headers["x-fapi-interaction-id"])

    def test_missing_token_returns_401_with_challenge(self) -> None:
        with TestClient(_app(protected_resource_enabled=True)) as client:
            response = client.get("/protected-resource")

        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Bearer")
        assert response.json()["error"] == "invalid_request"

    def test_invalid_token_returns_401_invalid_token(self) -> None:
        with TestClient(_app(protected_resource_enabled=True)) as client:
            response = client.get(
                "/protected-resource",
                headers={"Authorization": "Bearer jeton-absolu"},
            )

        assert response.status_code == 401
        assert 'error="invalid_token"' in response.headers["www-authenticate"]
        assert response.json()["error"] == "invalid_token"

    def test_query_string_token_is_refused(self) -> None:
        with TestClient(_app(protected_resource_enabled=True)) as client:
            token = _client_credentials_token(client)
            response = client.get("/protected-resource", params={"access_token": token})

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_request"

    def test_disabled_flag_returns_404(self) -> None:
        with TestClient(_app(protected_resource_enabled=False)) as client:
            response = client.get("/protected-resource")

        assert response.status_code == 404

    def test_usecase_refuses_revoked_token(self) -> None:
        token_manager = PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))
        revoked = InMemoryRevokedTokenRepository()
        usecase = ProtectedResourceUseCase(
            ProtectedResourceConfig(issuer=_ISSUER), token_manager, revoked
        )
        now = datetime.now(timezone.utc)
        token = run(
            token_manager.create_access_token(
                algorithm=JWTAlgorithm.RS256,
                issuer=_ISSUER,
                subject="alice",
                audience="web-app",
                expires_at=int((now + timedelta(minutes=5)).timestamp()),
                issued_at=int(now.timestamp()),
                scopes=frozenset({Scope.OPENID}),
            )
        )

        accepted = run(usecase.execute(ProtectedResourceRequest(access_token=token)))
        assert isinstance(accepted, ProtectedResourceResponse)
        assert accepted.subject == "alice"

        run(
            revoked.save(
                RevokedToken(
                    token_hash=token_hash(token),
                    expires_at=now + timedelta(minutes=5),
                )
            )
        )
        refused = run(usecase.execute(ProtectedResourceRequest(access_token=token)))
        assert isinstance(refused, ProtectedResourceError)
        assert refused.error == "invalid_token"


class TestResourceIndicatorPersistence:
    """Couvre la persistance SQL des colonnes RFC 8707 (resource_uris, indicator)."""

    def test_sql_code_repo_round_trips_resource_uris(self, tmp_path: Path) -> None:
        repo = SQLAuthorizationCodeRepository(f"sqlite+aiosqlite:///{tmp_path / 'codes.db'}")
        run(repo.initialise())
        run(
            repo.save(
                AuthorizationCode(
                    code="sql-ri",
                    client_id="web-app",
                    redirect_uri=_REDIRECT_URI,
                    subject="alice",
                    scopes=frozenset({Scope.OPENID}),
                    expires_at=_future_expiry(),
                    resource_uris=(_RESOURCE_A, _RESOURCE_B),
                )
            )
        )

        found = run(repo.find_by_code("sql-ri"))
        run(repo.close())

        assert found is not None
        assert found.resource_uris == (_RESOURCE_A, _RESOURCE_B)

    def test_sql_refresh_repo_round_trips_resource_uris(self, tmp_path: Path) -> None:
        repo = SQLRefreshTokenRepository(f"sqlite+aiosqlite:///{tmp_path / 'refresh.db'}")
        run(repo.initialise())
        run(
            repo.save(
                RefreshToken(
                    token_hash="sql-ri-hash",
                    client_id="web-app",
                    scopes=frozenset({Scope.OPENID}),
                    resource_uris=(_RESOURCE_A,),
                )
            )
        )

        found = run(repo.find_by_token_hash("sql-ri-hash"))
        run(repo.close())

        assert found is not None
        assert found.resource_uris == (_RESOURCE_A,)

    def test_sql_backchannel_repo_round_trips_resource_uris(self, tmp_path: Path) -> None:
        repo = SQLBackchannelAuthenticationRepository(f"sqlite+aiosqlite:///{tmp_path / 'ciba.db'}")
        run(repo.initialise())
        run(
            repo.save(
                BackchannelAuthenticationRequest(
                    auth_req_id_hash="sql-ri-h",
                    client_id="ciba-app",
                    scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
                    subject="alice",
                    delivery_mode="poll",
                    binding_message="1234",
                    expires_at=_future_expiry(),
                    resource_uris=(_RESOURCE_A,),
                )
            )
        )

        found = run(repo.find_by_auth_req_id_hash("sql-ri-h"))
        run(repo.close())

        assert found is not None
        assert found.resource_uris == (_RESOURCE_A,)

    def test_sql_api_resource_repo_round_trips_indicator(self, tmp_path: Path) -> None:
        repo = SQLApiResourceRepository(f"sqlite+aiosqlite:///{tmp_path / 'api.db'}")
        run(repo.initialise())
        run(
            repo.save(
                ApiResource(
                    name="sample-api",
                    scopes=frozenset({"api.read"}),
                    indicator=_RESOURCE_A,
                )
            )
        )

        found = run(repo.find_by_name("sample-api"))
        run(repo.close())

        assert found is not None
        assert found.indicator == _RESOURCE_A
