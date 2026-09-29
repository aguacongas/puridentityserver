"""Tests du paramètre ``claims`` (OIDC Core 1.0 §5.5) et de la sélection des claims.

Couvre le module ``claims_request`` (parse, payload access_token, sélection par
scope, résolution user store) puis les cas d'utilisation de bout en bout :
``acr`` et ``claims`` sur ``/authorize`` (code et ``response_type=id_token``),
rejeu des deux members lors de l'échange du code, filtrage ``/userinfo``
élargi par l'access_token, et ``claims_parameter_supported`` au discovery.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from typing import TypeVar
from urllib.parse import parse_qs, urlparse

import jwt as pyjwt
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.authorize import (
    AuthorizeConfig,
    AuthorizeError,
    AuthorizeRedirect,
    AuthorizeRequest,
    AuthorizeUseCase,
)
from puridentityserver.application.claims_request import (
    ClaimsRequest,
    allowed_scope_claims,
    parse_claims_parameter,
    requested_userinfo_claims,
    requested_userinfo_payload,
    resolve_requested_claims,
    scope_claims_for_subject,
)
from puridentityserver.application.token import (
    TokenConfig,
    TokenRequest,
    TokenResponse,
    TokenUseCase,
)
from puridentityserver.application.userinfo import (
    UserInfoConfig,
    UserInfoError,
    UserInfoRequest,
    UserInfoResponse,
    UserInfoUseCase,
)
from puridentityserver.domain.authorization import AuthorizationCode, Client, ClientType, Scope
from puridentityserver.domain.identity_resource import IdentityResource
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.domain.userinfo import UserClaims
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.persistence.memory.codes import (
    InMemoryAuthorizationCodeRepository,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.memory.refresh_tokens import (
    InMemoryRefreshTokenRepository,
)
from puridentityserver.infrastructure.persistence.memory.revoked_tokens import (
    InMemoryRevokedTokenRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.interfaces.domain.userinfo import ClaimsProvider
from puridentityserver.interfaces.repositories.readers import IdentityResourceReader
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_REDIRECT_URI = "https://app.example/callback"
_CLIENT_JSON = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": [_REDIRECT_URI],
    "scopes": "openid profile",
    "client_type": "confidential",
}
_CLIENT = Client(
    client_id="web-app",
    redirect_uris=frozenset({_REDIRECT_URI}),
    scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
    client_type=ClientType.CONFIDENTIAL,
    client_secret_hash=hashlib.sha256(b"super-secret").hexdigest(),
)
_PROFILE_CLAIMS = {"name": "Alice Martin", "email": "alice@example.com"}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


class _FakeClaimsProvider:
    """ClaimsProvider de test : profil figé pour ``alice``, vide sinon."""

    def __init__(self, claims: dict[str, object] | None = None) -> None:
        self._claims = dict(claims if claims is not None else _PROFILE_CLAIMS)

    async def get_claims(self, subject: str) -> UserClaims:
        """Retourne le profil figé pour ``alice``, des claims vides sinon."""
        return UserClaims(subject=subject, claims=self._claims if subject == "alice" else {})


class _FakeIdentityResourceReader:
    """IdentityResourceReader de test : liste figée retournée par ``find_all``."""

    def __init__(self, resources: tuple[IdentityResource, ...] = ()) -> None:
        self._resources = resources

    async def find_by_name(self, name: str) -> IdentityResource | None:
        """Retourne la resource portant ``name``."""
        return next((item for item in self._resources if item.name == name), None)

    async def find_all(self) -> list[IdentityResource]:
        """Retourne les resources configurées."""
        return list(self._resources)


def _claims_provider() -> ClaimsProvider:
    """Fournit ``_FakeClaimsProvider`` au type du port ``ClaimsProvider``."""
    return _FakeClaimsProvider()  # type: ignore[return-value]


def _identity_reader(*resources: IdentityResource) -> IdentityResourceReader:
    """Fournit ``_FakeIdentityResourceReader`` au type du port."""
    return _FakeIdentityResourceReader(resources)  # type: ignore[return-value]


def _token_manager() -> PyJWTTokenManager:
    """Gestionnaire de jetons isolé avec ses propres clés."""
    return PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _decode(token: str) -> dict[str, object]:
    """Décode un JWT sans vérifier la signature (claims à contrôler)."""
    return pyjwt.decode(token, options={"verify_signature": False})


def _app(**settings: object) -> FastAPI:
    """Application de test sur le client ``web-app`` (seed mémoire)."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(_CLIENT_JSON,),
            **settings,
        )
    )


# ---------------------------------------------------------------------------
# parse_claims_parameter (OIDC Core 1.0 §5.5.1)
# ---------------------------------------------------------------------------


class TestParseClaimsParameter:
    """Validation du paramètre ``claims`` transmis à ``/authorize``."""

    def test_parses_userinfo_and_id_token_members(self) -> None:
        value = json.dumps(
            {
                "userinfo": {"name": {"essential": True}, "email": {"essential": True}},
                "id_token": {"acr": {}},
            }
        )

        parsed = parse_claims_parameter(value)

        assert parsed == ClaimsRequest(userinfo=("name", "email"), id_token=("acr",))

    def test_keeps_only_claim_names(self) -> None:
        value = json.dumps(
            {"userinfo": {"name": {"value": "Alice"}, "email": {"values": ["a@example.com"]}}}
        )

        parsed = parse_claims_parameter(value)

        assert parsed is not None
        assert set(parsed.userinfo) == {"name", "email"}

    def test_ignores_unknown_members(self) -> None:
        assert parse_claims_parameter(json.dumps({"resource": {"name": {}}})) == ClaimsRequest()

    def test_rejects_malformed_json(self) -> None:
        assert parse_claims_parameter("{not json") is None
        assert parse_claims_parameter("") is None

    def test_rejects_non_object_json(self) -> None:
        assert parse_claims_parameter("[1, 2]") is None
        assert parse_claims_parameter('"name"') is None
        assert parse_claims_parameter("null") is None

    def test_rejects_member_of_wrong_shape(self) -> None:
        assert parse_claims_parameter(json.dumps({"userinfo": ["name"]})) is None
        assert parse_claims_parameter(json.dumps({"id_token": "name"})) is None

    def test_rejects_constraint_of_wrong_shape(self) -> None:
        assert parse_claims_parameter(json.dumps({"userinfo": {"name": "essential"}})) is None


# ---------------------------------------------------------------------------
# payload access_token / lecture côté userinfo
# ---------------------------------------------------------------------------


class TestUserinfoClaimsPayload:
    """Voyage des noms ``userinfo`` dans l'access_token (§5.5)."""

    def test_payload_carries_userinfo_names(self) -> None:
        payload = requested_userinfo_payload(ClaimsRequest(userinfo=("name", "email")))

        assert payload == {"claims": {"userinfo": ["name", "email"]}}

    def test_payload_is_empty_without_userinfo_member(self) -> None:
        assert requested_userinfo_payload(ClaimsRequest(id_token=("name",))) == {}
        assert requested_userinfo_payload(ClaimsRequest()) == {}

    def test_reads_names_from_token_claim(self) -> None:
        assert requested_userinfo_claims({"userinfo": ["name", "email"]}) == {"name", "email"}

    def test_ignores_unexpected_shapes(self) -> None:
        assert requested_userinfo_claims(None) == set()
        assert requested_userinfo_claims("name") == set()
        assert requested_userinfo_claims({}) == set()
        assert requested_userinfo_claims({"userinfo": "name"}) == set()


# ---------------------------------------------------------------------------
# sélection par scope (OIDC Core 1.0 §5.4)
# ---------------------------------------------------------------------------


class TestAllowedScopeClaims:
    """Dérivation scope → claims autorisés depuis les IdentityResources."""

    def test_defaults_to_builtin_resources(self) -> None:
        allowed = run(allowed_scope_claims("openid profile"))

        assert {"sub", "name", "preferred_username"} <= allowed
        assert "email" not in allowed

    def test_unknown_scope_only_allows_sub(self) -> None:
        assert run(allowed_scope_claims("unknown-scope")) == {"sub"}

    def test_injected_reader_overrides_defaults(self) -> None:
        reader = _identity_reader(
            IdentityResource(name="profile", user_claims=frozenset({"custom_claim"}))
        )

        allowed = run(allowed_scope_claims("profile", reader))

        assert allowed == {"sub", "custom_claim"}

    def test_empty_reader_falls_back_to_defaults(self) -> None:
        allowed = run(allowed_scope_claims("email", _identity_reader()))

        assert allowed == {"sub", "email", "email_verified"}


# ---------------------------------------------------------------------------
# résolution des valeurs depuis le user store
# ---------------------------------------------------------------------------


class TestResolveRequestedClaims:
    """Résolution des claims demandés via le ``ClaimsProvider``."""

    def test_resolves_requested_names_only(self) -> None:
        resolved = run(resolve_requested_claims(("name",), "alice", _claims_provider()))

        assert resolved == {"name": "Alice Martin"}

    def test_omits_unknown_claims(self) -> None:
        resolved = run(resolve_requested_claims(("nickname",), "alice", _claims_provider()))

        assert resolved == {}

    def test_returns_empty_without_names_provider_or_subject(self) -> None:
        assert run(resolve_requested_claims((), "alice", _claims_provider())) == {}
        assert run(resolve_requested_claims(("name",), "alice", None)) == {}
        assert run(resolve_requested_claims(("name",), "", _claims_provider())) == {}

    def test_scope_claims_filtered_by_allowed_set(self) -> None:
        resolved = run(scope_claims_for_subject("openid email", "alice", _claims_provider()))

        assert resolved == {"email": "alice@example.com"}

    def test_scope_claims_empty_without_provider_or_subject(self) -> None:
        assert run(scope_claims_for_subject("openid", "alice", None)) == {}
        assert run(scope_claims_for_subject("openid", "", _claims_provider())) == {}


# ---------------------------------------------------------------------------
# AuthorizeUseCase : acr + claims sur /authorize
# ---------------------------------------------------------------------------


def _make_authorize_usecase() -> AuthorizeUseCase:
    """Use case d'autorisation avec repos mémoire, jetons réels et provider fake."""
    clients = InMemoryClientRepository()
    run(clients.save(_CLIENT))
    return AuthorizeUseCase(
        AuthorizeConfig(issuer=_ISSUER, signing_algorithm=JWTAlgorithm.RS256),
        clients,
        InMemoryAuthorizationCodeRepository(),
        _token_manager(),
        claims_provider=_claims_provider(),
        identity_resources=_identity_reader(),
    )


def _authorize_request(
    response_type: str,
    *,
    scope: str = "openid profile",
    acr_values: str = "",
    claims: str = "",
) -> AuthorizeRequest:
    """Demande d'autorisation valide pour le client ``web-app``."""
    return AuthorizeRequest(
        response_type=response_type,
        client_id="web-app",
        redirect_uri=_REDIRECT_URI,
        scope=scope,
        subject="alice",
        state="xyz",
        nonce="n-claims",
        code_challenge=_s256_challenge("verifier-verifier"),
        acr_values=acr_values,
        claims=claims,
    )


class TestAuthorizeAcrAndClaims:
    """Émission de ``acr`` et des claims complémentaires depuis ``/authorize``."""

    def test_id_token_carries_first_acr_value(self) -> None:
        usecase = _make_authorize_usecase()

        result = run(usecase.execute(_authorize_request("id_token", acr_values="1 2")))

        assert isinstance(result, AuthorizeRedirect)
        assert _decode(result.id_token)["acr"] == "1"

    def test_id_token_gets_scope_claims_only_for_pure_id_token(self) -> None:
        usecase = _make_authorize_usecase()

        pure = run(usecase.execute(_authorize_request("id_token")))
        hybrid = run(usecase.execute(_authorize_request("code id_token")))

        assert isinstance(pure, AuthorizeRedirect)
        assert isinstance(hybrid, AuthorizeRedirect)
        assert _decode(pure.id_token)["name"] == "Alice Martin"
        assert "name" not in _decode(hybrid.id_token)

    def test_id_token_member_is_resolved_into_id_token(self) -> None:
        usecase = _make_authorize_usecase()
        claims_param = json.dumps({"id_token": {"name": {"essential": True}}})

        result = run(
            usecase.execute(_authorize_request("id_token", scope="openid", claims=claims_param))
        )

        assert isinstance(result, AuthorizeRedirect)
        assert _decode(result.id_token)["name"] == "Alice Martin"

    def test_userinfo_member_rides_access_token(self) -> None:
        usecase = _make_authorize_usecase()
        claims_param = json.dumps({"userinfo": {"name": {"essential": True}}})

        result = run(
            usecase.execute(
                _authorize_request("id_token token", scope="openid", claims=claims_param)
            )
        )

        assert isinstance(result, AuthorizeRedirect)
        assert _decode(result.access_token)["claims"] == {"userinfo": ["name"]}
        assert "name" not in _decode(result.id_token)

    def test_malformed_claims_parameter_is_invalid_request(self) -> None:
        usecase = _make_authorize_usecase()

        result = run(usecase.execute(_authorize_request("code", claims="[1, 2]")))

        assert isinstance(result, AuthorizeError)
        assert result.error == "invalid_request"


# ---------------------------------------------------------------------------
# TokenUseCase : rejeu de acr/claims à l'échange du code
# ---------------------------------------------------------------------------


def _make_token_usecase() -> tuple[TokenUseCase, InMemoryAuthorizationCodeRepository]:
    """Use case token + repository de codes pour l'échange."""
    clients = InMemoryClientRepository()
    run(clients.save(_CLIENT))
    codes = InMemoryAuthorizationCodeRepository()
    usecase = TokenUseCase(
        TokenConfig(issuer=_ISSUER, signing_algorithm=JWTAlgorithm.RS256),
        clients,
        codes,
        _token_manager(),
        InMemoryRefreshTokenRepository(),
        claims_provider=_claims_provider(),
    )
    return usecase, codes


def _saved_code(codes: InMemoryAuthorizationCodeRepository, **fields: object) -> str:
    """Enregistre un code valide et retourne sa valeur."""
    code = AuthorizationCode(
        client_id="web-app",
        redirect_uri=_REDIRECT_URI,
        subject="alice",
        scopes=frozenset({Scope.OPENID}),
        nonce="n-claims",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        **fields,  # type: ignore[arg-type]
    )
    run(codes.save(code))
    return code.code


def _token_request(code: str) -> TokenRequest:
    """Requête d'échange standard (client_secret_post)."""
    return TokenRequest(
        grant_type="authorization_code",
        code=code,
        redirect_uri=_REDIRECT_URI,
        client_id="web-app",
        client_secret="super-secret",
    )


class TestTokenEndpointAcrAndClaims:
    """Reproduction de ``acr`` et des claims à l'échange du code (§3.1.3.3)."""

    def test_id_token_reproduces_acr_from_code(self) -> None:
        usecase, codes = _make_token_usecase()

        result = run(usecase.execute(_token_request(_saved_code(codes, acr="1"))))

        assert isinstance(result, TokenResponse)
        assert _decode(result.id_token)["acr"] == "1"

    def test_id_token_and_access_token_honor_claims_parameter(self) -> None:
        usecase, codes = _make_token_usecase()
        claims_param = json.dumps(
            {
                "userinfo": {"email": {"essential": True}},
                "id_token": {"name": {"essential": True}},
            }
        )

        result = run(usecase.execute(_token_request(_saved_code(codes, claims=claims_param))))

        assert isinstance(result, TokenResponse)
        id_token_claims = _decode(result.id_token)
        token_claims = _decode(result.access_token)
        assert id_token_claims["name"] == "Alice Martin"
        assert "email" not in id_token_claims
        assert token_claims["claims"] == {"userinfo": ["email"]}


# ---------------------------------------------------------------------------
# UserInfoUseCase : filtrage élargi par l'access_token
# ---------------------------------------------------------------------------


class TestUserInfoHonorsAccessTokenClaims:
    """``/userinfo`` ajoute les claims du member ``userinfo`` de l'access_token."""

    def _execute(self, claims_parameter: object | None = None) -> UserInfoResponse:
        """Émet un access_token ``openid`` puis appelle ``/userinfo``.

        Le même ``PyJWTTokenManager`` (donc les mêmes clés) signe et valide le
        jeton : sans cela le rejet ``invalid_token`` tiendrait à un JWKS
        distinct, pas au filtrage des claims.
        """
        tm = _token_manager()
        token = run(
            tm.create_access_token(
                algorithm=JWTAlgorithm.RS256,
                issuer=_ISSUER,
                subject="alice",
                audience="web-app",
                expires_at=9999999999,
                issued_at=1000000000,
                scopes=frozenset({Scope.OPENID}),
                additional_claims=(
                    {"claims": claims_parameter} if claims_parameter is not None else None
                ),
            )
        )
        usecase = UserInfoUseCase(
            UserInfoConfig(issuer=_ISSUER),
            tm,
            _claims_provider(),
            InMemoryRevokedTokenRepository(),
        )
        result = run(usecase.execute(UserInfoRequest(access_token=token)))
        assert not isinstance(result, UserInfoError), f"userinfo en erreur : {result.error}"
        return result

    def test_name_returned_when_requested_in_token(self) -> None:
        result = self._execute({"userinfo": ["name"]})

        assert result.claims.get("name") == "Alice Martin"

    def test_name_excluded_without_claims_parameter(self) -> None:
        result = self._execute()

        assert result.claims == {"sub": "alice"}


# ---------------------------------------------------------------------------
# API : discovery + rejet de claims malformé sur /authorize
# ---------------------------------------------------------------------------


class TestClaimsParameterApiSurface:
    """Surface HTTP du paramètre ``claims`` et du discovery."""

    def test_discovery_declares_claims_parameter_supported(self) -> None:
        with TestClient(_app()) as client:
            metadata = client.get("/.well-known/openid-configuration").json()

        assert metadata["claims_parameter_supported"] is True

    def test_authorize_rejects_malformed_claims(self) -> None:
        with TestClient(_app()) as client:
            response = client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": "web-app",
                    "redirect_uri": _REDIRECT_URI,
                    "scope": "openid",
                    "state": "xyz",
                    "claims": "[1, 2]",
                },
                follow_redirects=False,
            )

        assert response.status_code == 302
        query = parse_qs(urlparse(response.headers["location"]).query)
        assert query["error"] == ["invalid_request"]
        assert query["state"] == ["xyz"]

    def test_authorize_accepts_acr_values_and_claims_through_query(self) -> None:
        verifier = "verifier-verifier"
        with TestClient(_app()) as client:
            auth = client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": "web-app",
                    "redirect_uri": _REDIRECT_URI,
                    "scope": "openid profile",
                    "state": "xyz",
                    "acr_values": "1 2",
                    "claims": json.dumps({"userinfo": {"name": {"essential": True}}}),
                    "code_challenge": _s256_challenge(verifier),
                    "code_challenge_method": "S256",
                },
                follow_redirects=False,
            )
            code = parse_qs(urlparse(auth.headers["location"]).query)["code"][0]
            payload = client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": _REDIRECT_URI,
                    "client_id": "web-app",
                    "client_secret": "super-secret",
                    "code_verifier": verifier,
                },
            ).json()

        assert _decode(payload["id_token"])["acr"] == "1"
        assert _decode(payload["access_token"])["claims"] == {"userinfo": ["name"]}
