"""Tests de la séparation administration / protocole et de l'authentification JWT.

- Unitaires : ``ClaimRule`` / ``BearerClaimAuthorizer``, ``Settings``
  (rôle, claim, mode de registration), sélection et comportement des
  vérificateurs Bearer (local, JWKS distant, discovery).
- HTTP E2E : CRUD protégés par JWT (401/200) via un vrai access token
  ``client_credentials``, montage conditionnel des routeurs selon le rôle,
  et modes d'autorisation de ``POST /register``.
"""

import asyncio
import json
from collections.abc import Awaitable
from typing import TypeVar

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jwt import PyJWK  # type: ignore[attr-defined]  # non exposé par types-PyJWT
from jwt.algorithms import RSAAlgorithm

from puridentityserver.application.claim_authorizer import BearerClaimAuthorizer, ClaimRule
from puridentityserver.infrastructure import bearer as bearer_module
from puridentityserver.infrastructure.bearer import (
    JwksBearerVerifier,
    LocalBearerVerifier,
    build_bearer_verifier,
)
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_ADMIN_API = {"name": "management", "scopes": ["admin"]}
_SAMPLE_API = {"name": "sample-api", "scopes": ["api.read"]}

_ADMIN_CLIENT = {
    "client_id": "admin-app",
    "client_secret": "admin-secret",
    "scopes": "openid admin",
    "client_type": "confidential",
}

_PLAIN_CLIENT = {
    "client_id": "plain-app",
    "client_secret": "plain-secret",
    "scopes": "openid api.read",
    "client_type": "confidential",
}

_REGISTRATION = {
    "redirect_uris": ["https://app.example/callback"],
    "scope": "openid profile email",
}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


def _app(
    *,
    api_resources: tuple[dict[str, object], ...] = (_ADMIN_API, _SAMPLE_API),
    clients_seed: tuple[dict[str, object], ...] = (_ADMIN_CLIENT, _PLAIN_CLIENT),
    **settings: object,
) -> FastAPI:
    """Assemble une application de test (protection admin par défaut)."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            api_resources_seed=api_resources,
            clients_seed=clients_seed,
            **settings,
        )
    )


def _access_token(
    client: TestClient,
    *,
    client_id: str = "admin-app",
    client_secret: str = "admin-secret",  # ruff: ignore[hardcoded-password-default] (secret de test)
    scope: str = "openid admin",
) -> str:
    """Émet un access token ``client_credentials`` pour un client de test."""
    response = client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


class _FakeVerifier:
    """Vérificateur Bearer factice retournant des claims fixes."""

    def __init__(self, claims: dict[str, object] | None) -> None:
        self._claims = claims

    async def verify(self, token: str) -> dict[str, object] | None:
        """Retourne les claims configurés, quel que soit le jeton."""
        return self._claims


class _FakeResponse:
    """Réponse HTTP factice (context manager) pour ``urlopen``."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._payload


class TestClaimRule:
    """Couvre l'évaluation d'un claim (appartenance ``scope``, égalité)."""

    def test_scope_membership(self) -> None:
        rule = ClaimRule("scope", frozenset({"admin"}))

        assert rule.matches({"scope": "openid admin"}) is True
        assert rule.matches({"scope": "openid profile"}) is False

    def test_missing_claim(self) -> None:
        assert ClaimRule("scope", frozenset({"admin"})).matches({}) is False

    def test_non_scope_string_equality(self) -> None:
        rule = ClaimRule("role", frozenset({"operator"}))

        assert rule.matches({"role": "operator"}) is True
        assert rule.matches({"role": "viewer"}) is False

    def test_list_claim_membership(self) -> None:
        rule = ClaimRule("roles", frozenset({"operator"}))

        assert rule.matches({"roles": ["viewer", "operator"]}) is True
        assert rule.matches({"roles": ["viewer"]}) is False

    def test_unsupported_claim_type(self) -> None:
        assert ClaimRule("roles", frozenset({"operator"})).matches({"roles": 42}) is False


class TestBearerClaimAuthorizer:
    """Couvre l'autorisation (jeton valide + claim attendu)."""

    def _authorizer(self, claims: dict[str, object] | None) -> BearerClaimAuthorizer:
        return BearerClaimAuthorizer(
            _FakeVerifier(claims), ClaimRule("scope", frozenset({"admin"}))
        )

    def test_accepts_valid_token_with_claim(self) -> None:
        assert run(self._authorizer({"scope": "openid admin"}).authorise("t")) is True

    def test_rejects_invalid_token(self) -> None:
        assert run(self._authorizer(None).authorise("t")) is False

    def test_rejects_missing_claim(self) -> None:
        assert run(self._authorizer({"scope": "openid"}).authorise("t")) is False


class TestAdminSettings:
    """Couvre les réglages de rôle, de claim et de mode de registration."""

    def test_defaults_are_secure(self) -> None:
        settings = Settings(_env_file=None)

        assert settings.role == "full"
        assert settings.admin_required_claim == "scope"
        assert settings.admin_required_claim_values == ("admin",)
        assert settings.admin_protected is True
        assert settings.registration_initial_access_token_mode == "static"

    def test_management_issuer_defaults_to_server_issuer(self) -> None:
        settings = Settings(issuer=_ISSUER)

        assert settings.management_issuer == _ISSUER

    def test_management_issuer_override(self) -> None:
        settings = Settings(issuer=_ISSUER, management_jwt_issuer="https://admin.example")

        assert settings.management_issuer == "https://admin.example"

    def test_empty_claim_values_disable_protection(self) -> None:
        assert Settings(admin_required_claim_values=()).admin_protected is False

    def test_rejects_unknown_role(self) -> None:
        with pytest.raises(ValueError, match="Rôle non supporté"):
            Settings(role="gateway")

    def test_rejects_unknown_registration_mode(self) -> None:
        with pytest.raises(ValueError, match="Mode d'initial access token non supporté"):
            Settings(registration_initial_access_token_mode="magic")

    def test_env_splits_claim_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PURIDENTITYSERVER_ADMIN_REQUIRED_CLAIM_VALUES", "admin, operator")
        monkeypatch.setenv("PURIDENTITYSERVER_REGISTRATION_REQUIRED_CLAIM_VALUES", "register")

        settings = Settings(_env_file=None)

        assert settings.admin_required_claim_values == ("admin", "operator")
        assert settings.registration_required_claim_values == ("register",)


class TestBearerVerifierSelection:
    """Couvre le choix du vérificateur local ou distant (JWKS)."""

    def _manager(self) -> PyJWTTokenManager:
        return PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))

    def test_local_when_issuer_matches(self) -> None:
        settings = Settings(issuer=_ISSUER)

        assert isinstance(build_bearer_verifier(settings, self._manager()), LocalBearerVerifier)

    def test_remote_when_issuer_differs(self) -> None:
        settings = Settings(issuer=_ISSUER, management_jwt_issuer="https://admin.example")

        assert isinstance(build_bearer_verifier(settings, self._manager()), JwksBearerVerifier)

    def test_remote_when_jwks_url_configured(self) -> None:
        settings = Settings(issuer=_ISSUER, management_jwt_jwks_url="https://admin.example/jwks")

        assert isinstance(build_bearer_verifier(settings, self._manager()), JwksBearerVerifier)


class TestJwksBearerVerifier:
    """Couvre la validation distante (discovery, signature, échecs)."""

    def test_fetch_json_parses_payload(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            bearer_module, "urlopen", lambda url, timeout: _FakeResponse(b'{"a": 1}')
        )

        assert bearer_module._fetch_json("https://x/metadata") == {"a": 1}

    def test_fetch_json_ignores_non_object(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bearer_module, "urlopen", lambda url, timeout: _FakeResponse(b"[1, 2]"))

        assert bearer_module._fetch_json("https://x/metadata") == {}

    def test_accepts_token_signed_by_discovered_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = pyjwt.encode({"iss": _ISSUER, "sub": "s", "scope": "admin"}, key, "RS256")
        public_jwk = PyJWK(json.loads(RSAAlgorithm.to_jwk(key.public_key())))

        class _FakeClient:
            def __init__(self, url: str, timeout: int) -> None:
                self.url = url

            def get_signing_key_from_jwt(self, raw: str) -> object:
                return public_jwk

        monkeypatch.setattr(bearer_module, "PyJWKClient", _FakeClient)
        verifier = JwksBearerVerifier(issuer=_ISSUER, jwks_url="https://admin.example/jwks")

        claims = run(verifier.verify(token))

        assert claims is not None
        assert claims["scope"] == "admin"

    def test_discovers_jwks_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, str] = {}

        class _FakeClient:
            def __init__(self, url: str, timeout: int) -> None:
                captured["url"] = url

            def get_signing_key_from_jwt(self, raw: str) -> object:
                raise pyjwt.PyJWTError("boom")

        monkeypatch.setattr(bearer_module, "PyJWKClient", _FakeClient)
        monkeypatch.setattr(
            bearer_module,
            "_fetch_json",
            lambda url: {"jwks_uri": "https://admin.example/keys"},
        )
        verifier = JwksBearerVerifier(issuer=_ISSUER)

        assert run(verifier.verify("token")) is None
        assert captured["url"] == "https://admin.example/keys"

    def test_returns_none_when_discovery_lacks_jwks_uri(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(bearer_module, "_fetch_json", lambda url: {})
        verifier = JwksBearerVerifier(issuer=_ISSUER)

        assert run(verifier.verify("token")) is None


class TestAdminApiAuthentication:
    """Couvre la protection JWT des CRUD d'administration."""

    def test_crud_requires_token_by_default(self) -> None:
        with TestClient(_app()) as client:
            assert client.get("/api-resources").status_code == 401
            assert client.get("/identity-resources").status_code == 401

    def test_unauthorized_response_advertises_bearer(self) -> None:
        with TestClient(_app()) as client:
            response = client.get("/api-resources")

        assert response.headers["www-authenticate"] == "Bearer"

    def test_rejects_token_without_admin_scope(self) -> None:
        with TestClient(_app()) as client:
            token = _access_token(
                client, client_id="plain-app", client_secret="plain-secret", scope="openid api.read"
            )
            response = client.get("/api-resources", headers={"authorization": f"Bearer {token}"})

        assert response.status_code == 401

    def test_accepts_token_with_admin_scope(self) -> None:
        with TestClient(_app()) as client:
            token = _access_token(client)
            api = client.get("/api-resources", headers={"authorization": f"Bearer {token}"})
            identity = client.get(
                "/identity-resources", headers={"authorization": f"Bearer {token}"}
            )

        assert api.status_code == 200
        assert identity.status_code == 200

    def test_custom_claim_is_enforced(self) -> None:
        with TestClient(
            _app(admin_required_claim="role", admin_required_claim_values=("operator",))
        ) as client:
            token = _access_token(client)
            response = client.get("/api-resources", headers={"authorization": f"Bearer {token}"})

        assert response.status_code == 401


class TestRoleMounting:
    """Couvre le montage conditionnel des routeurs selon le rôle."""

    def test_protocol_role_omits_admin_endpoints(self) -> None:
        with TestClient(_app(role="protocol", admin_required_claim_values=())) as client:
            assert client.get("/api-resources").status_code == 404
            assert client.get("/identity-resources").status_code == 404
            assert client.get("/.well-known/openid-configuration").status_code == 200

    def test_admin_role_omits_protocol_endpoints(self) -> None:
        with TestClient(_app(role="admin", admin_required_claim_values=())) as client:
            assert client.get("/api-resources").status_code == 200
            assert client.get("/identity-resources").status_code == 200
            assert client.get("/.well-known/openid-configuration").status_code == 404
            assert client.get("/authorize").status_code == 404
            assert client.get("/.well-known/jwks.json").status_code == 404


class TestRegistrationAuthorizationModes:
    """Couvre les modes ``static`` / ``jwt`` / ``disabled`` de ``POST /register``."""

    def test_static_mode_uses_hashed_initial_token(self) -> None:
        with TestClient(
            _app(registration_enabled=True, registration_initial_access_tokens=("registrar",))
        ) as client:
            assert client.post("/register", json=_REGISTRATION).status_code == 401
            response = client.post(
                "/register",
                json=_REGISTRATION,
                headers={"authorization": "Bearer registrar"},
            )

        assert response.status_code == 201

    def test_jwt_mode_requires_authorized_token(self) -> None:
        with TestClient(
            _app(
                registration_enabled=True,
                registration_initial_access_token_mode="jwt",
                registration_required_claim_values=("admin",),
            )
        ) as client:
            assert client.post("/register", json=_REGISTRATION).status_code == 401
            token = _access_token(client)
            response = client.post(
                "/register",
                json=_REGISTRATION,
                headers={"authorization": f"Bearer {token}"},
            )

        assert response.status_code == 201

    def test_disabled_mode_allows_registration(self) -> None:
        with TestClient(
            _app(
                registration_enabled=True,
                registration_initial_access_token_mode="disabled",
            )
        ) as client:
            response = client.post("/register", json=_REGISTRATION)

        assert response.status_code == 201
