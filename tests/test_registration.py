"""Tests de la feature Dynamic Client Registration (RFC 7591) + gestion (RFC 7592).

- Unitaires : ``RegistrationUseCase`` (création, lecture, mise à jour,
  suppression, rotation de secret, authentifications initial et de gestion).
- HTTP E2E : ``POST /register`` + ``GET/PUT/DELETE /register/{client_id}``
  via ``TestClient``, plus l'annonce du ``registration_endpoint`` au
  discovery (activé / désactivé).
"""

import asyncio
from collections.abc import Awaitable
from typing import TypeVar

from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.registration import (
    ClientRegistration,
    DeleteClientRequest,
    ReadClientRequest,
    RegisterRequest,
    RegistrationConfig,
    RegistrationError,
    RegistrationUseCase,
    UpdateClientRequest,
    hash_secret,
)
from puridentityserver.domain.authorization import ClientType
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "http://id.example"

_INITIAL_TOKEN = "registrar-token"

_CONFIG = RegistrationConfig(
    issuer=_ISSUER,
    base_url=_ISSUER,
    requires_initial_access_token=True,
    initial_access_token_hashes=frozenset({hash_secret(_INITIAL_TOKEN)}),
)

_REGISTRATION = {
    "redirect_uris": ["https://app.example/callback"],
    "post_logout_redirect_uris": ["https://app.example/post-logout"],
    "scope": "openid profile email",
}

_ENDPOINT_SETTINGS = Settings(
    issuer=_ISSUER,
    base_url=_ISSUER,
    jwks_algorithms=("RS256",),
    registration_enabled=True,
    registration_initial_access_tokens=(_INITIAL_TOKEN,),
)


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone."""
    return asyncio.run(awaitable)


def _usecase(
    *,
    requires_initial_access_token: bool = True,
) -> RegistrationUseCase:
    """Construit un RegistrationUseCase avec un registre clients en mémoire."""
    config = RegistrationConfig(
        issuer=_ISSUER,
        base_url=_ISSUER,
        requires_initial_access_token=requires_initial_access_token,
        initial_access_token_hashes=frozenset({hash_secret(_INITIAL_TOKEN)}),
    )
    return RegistrationUseCase(config, InMemoryClientRepository())


def _registered(usecase: RegistrationUseCase) -> ClientRegistration:
    """Enregistre un client confidentiel et retourne sa réponse complète."""
    result = run(
        usecase.register(RegisterRequest(_REGISTRATION, initial_access_token=_INITIAL_TOKEN))
    )
    assert isinstance(result, ClientRegistration)
    assert result.client_secret
    assert result.registration_access_token
    return result


class TestRegister:
    """Couvre la création d'un client (RFC 7591 §4)."""

    def test_creates_confidential_client(self) -> None:
        usecase = _usecase()

        result = _registered(usecase)

        assert result.client_id
        assert result.client_type is ClientType.CONFIDENTIAL
        assert result.token_endpoint_auth_method == "client_secret_basic"
        assert result.grant_types == ["authorization_code"]
        assert result.response_types == ["code"]
        assert result.scope == "email openid profile"
        assert result.redirect_uris == ["https://app.example/callback"]
        assert result.post_logout_redirect_uris == ["https://app.example/post-logout"]
        assert result.registration_client_uri == f"{_ISSUER}/register/{result.client_id}"
        stored = run(usecase._clients.find_by_id(result.client_id))
        assert stored is not None
        assert stored.client_secret_hash == hash_secret(result.client_secret)
        assert stored.registration_access_token_hash == hash_secret(
            result.registration_access_token
        )

    def test_register_issues_secret_only_once(self) -> None:
        usecase = _usecase()
        result = _registered(usecase)

        stored = run(usecase._clients.find_by_id(result.client_id))
        assert stored is not None
        assert stored.client_secret_hash != result.client_secret

    def test_creates_public_client_without_secret(self) -> None:
        usecase = _usecase()
        metadata = {**_REGISTRATION, "token_endpoint_auth_method": "none"}

        result = run(
            usecase.register(RegisterRequest(metadata, initial_access_token=_INITIAL_TOKEN))
        )

        assert isinstance(result, ClientRegistration)
        assert result.client_type is ClientType.PUBLIC
        assert result.token_endpoint_auth_method == "none"
        assert result.client_secret == ""

    def test_accepts_client_secret_post(self) -> None:
        usecase = _usecase()
        metadata = {**_REGISTRATION, "token_endpoint_auth_method": "client_secret_post"}

        result = run(
            usecase.register(RegisterRequest(metadata, initial_access_token=_INITIAL_TOKEN))
        )

        assert isinstance(result, ClientRegistration)
        assert result.client_type is ClientType.CONFIDENTIAL

    def test_defaults_scopes_and_metadata(self) -> None:
        usecase = _usecase()
        payload = {"redirect_uris": ["https://app.example/callback"]}

        result = run(
            usecase.register(RegisterRequest(payload, initial_access_token=_INITIAL_TOKEN))
        )

        assert isinstance(result, ClientRegistration)
        assert result.scope == "openid"
        assert result.grant_types == ["authorization_code"]
        assert result.response_types == ["code"]

    def test_requires_initial_access_token(self) -> None:
        usecase = _usecase()

        missing = run(usecase.register(RegisterRequest(_REGISTRATION)))
        wrong = run(usecase.register(RegisterRequest(_REGISTRATION, initial_access_token="wrong")))

        for result in (missing, wrong):
            assert isinstance(result, RegistrationError)
            assert result.error == "invalid_client"
            assert result.status_code == 401

    def test_open_registration_without_token(self) -> None:
        usecase = _usecase(requires_initial_access_token=False)

        result = run(usecase.register(RegisterRequest(_REGISTRATION)))

        assert isinstance(result, ClientRegistration)
        assert result.client_id

    def test_rejects_missing_redirect_uris(self) -> None:
        usecase = _usecase()

        result = run(usecase.register(RegisterRequest({}, initial_access_token=_INITIAL_TOKEN)))

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "redirect_uris" in result.error_description

    def test_rejects_invalid_redirect_uris(self) -> None:
        usecase = _usecase()
        for bad_uri in (
            "relative/uri",
            "https://app.example/cb#fragment",
            "ftp://app.example/cb",
        ):
            result = run(
                usecase.register(
                    RegisterRequest(
                        {"redirect_uris": [bad_uri]},
                        initial_access_token=_INITIAL_TOKEN,
                    )
                )
            )
            assert isinstance(result, RegistrationError)
            assert result.error == "invalid_redirect_uri"

    def test_rejects_unknown_scope(self) -> None:
        usecase = _usecase()

        result = run(
            usecase.register(
                RegisterRequest(
                    {**_REGISTRATION, "scope": "openid admin"},
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "scope" in result.error_description

    def test_rejects_unsupported_grant_types(self) -> None:
        usecase = _usecase()

        result = run(
            usecase.register(
                RegisterRequest(
                    {**_REGISTRATION, "grant_types": ["implicit"]},
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"
        assert "grant_types" in result.error_description

    def test_rejects_unsupported_response_types(self) -> None:
        usecase = _usecase()

        result = run(
            usecase.register(
                RegisterRequest(
                    {**_REGISTRATION, "response_types": ["code id_token"]},
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"

    def test_rejects_unsupported_auth_method(self) -> None:
        usecase = _usecase()

        result = run(
            usecase.register(
                RegisterRequest(
                    {**_REGISTRATION, "token_endpoint_auth_method": "private_key_jwt"},
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"

    def test_rejects_malformed_redirect_uris_field(self) -> None:
        usecase = _usecase()

        result = run(
            usecase.register(
                RegisterRequest(
                    {"redirect_uris": "https://app.example/cb"},
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"


class TestRead:
    """Couvre la lecture de la configuration (RFC 7592 §2)."""

    def test_reads_registered_configuration(self) -> None:
        usecase = _usecase()
        registered = _registered(usecase)

        result = run(
            usecase.read(
                ReadClientRequest(registered.client_id, registered.registration_access_token)
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.client_id == registered.client_id
        assert result.redirect_uris == ["https://app.example/callback"]
        assert result.client_secret == ""
        assert result.registration_access_token == ""

    def test_rejects_wrong_registration_access_token(self) -> None:
        usecase = _usecase()
        registered = _registered(usecase)

        result = run(usecase.read(ReadClientRequest(registered.client_id, "wrong-token")))

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client"
        assert result.status_code == 401

    def test_rejects_unknown_client(self) -> None:
        usecase = _usecase()

        result = run(usecase.read(ReadClientRequest("ghost-client", _INITIAL_TOKEN)))

        assert isinstance(result, RegistrationError)
        assert result.status_code == 404


class TestUpdate:
    """Couvre le remplacement de la configuration (RFC 7592 §3)."""

    def test_replaces_metadata(self) -> None:
        usecase = _usecase()
        registered = _registered(usecase)
        new_metadata = {"redirect_uris": ["https://new.example/cb"], "scope": "openid"}

        result = run(
            usecase.update(
                UpdateClientRequest(
                    registered.client_id,
                    registered.registration_access_token,
                    new_metadata,
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.redirect_uris == ["https://new.example/cb"]
        assert result.scope == "openid"
        assert result.client_secret == ""
        read = run(
            usecase.read(
                ReadClientRequest(registered.client_id, registered.registration_access_token)
            )
        )
        assert isinstance(read, ClientRegistration)
        assert read.redirect_uris == ["https://new.example/cb"]

    def test_rotates_secret_when_requested(self) -> None:
        usecase = _usecase()
        registered = _registered(usecase)
        new_secret = "a-brand-new-secret-value"
        new_metadata = {**_REGISTRATION, "client_secret": new_secret}

        result = run(
            usecase.update(
                UpdateClientRequest(
                    registered.client_id,
                    registered.registration_access_token,
                    new_metadata,
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.client_secret == new_secret
        stored = run(usecase._clients.find_by_id(registered.client_id))
        assert stored is not None
        assert stored.client_secret_hash == hash_secret(new_secret)

    def test_keeps_secret_without_rotation(self) -> None:
        usecase = _usecase()
        registered = _registered(usecase)

        result = run(
            usecase.update(
                UpdateClientRequest(
                    registered.client_id,
                    registered.registration_access_token,
                    _REGISTRATION,
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.client_secret == ""
        stored = run(usecase._clients.find_by_id(registered.client_id))
        assert stored is not None
        assert stored.client_secret_hash == hash_secret(registered.client_secret)

    def test_switches_to_public_and_clears_secret(self) -> None:
        usecase = _usecase()
        registered = _registered(usecase)

        result = run(
            usecase.update(
                UpdateClientRequest(
                    registered.client_id,
                    registered.registration_access_token,
                    {**_REGISTRATION, "token_endpoint_auth_method": "none"},
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.client_type is ClientType.PUBLIC
        assert result.client_secret == ""
        stored = run(usecase._clients.find_by_id(registered.client_id))
        assert stored is not None
        assert stored.client_secret_hash == ""

    def test_switches_to_confidential_and_generates_secret(self) -> None:
        usecase = _usecase()
        registered = run(
            usecase.register(
                RegisterRequest(
                    {**_REGISTRATION, "token_endpoint_auth_method": "none"},
                    initial_access_token=_INITIAL_TOKEN,
                )
            )
        )
        assert isinstance(registered, ClientRegistration)

        result = run(
            usecase.update(
                UpdateClientRequest(
                    registered.client_id,
                    registered.registration_access_token,
                    _REGISTRATION,
                )
            )
        )

        assert isinstance(result, ClientRegistration)
        assert result.client_type is ClientType.CONFIDENTIAL
        assert result.client_secret

    def test_rejects_weak_requested_secret(self) -> None:
        usecase = _usecase()
        registered = _registered(usecase)

        result = run(
            usecase.update(
                UpdateClientRequest(
                    registered.client_id,
                    registered.registration_access_token,
                    {**_REGISTRATION, "client_secret": "short"},
                )
            )
        )

        assert isinstance(result, RegistrationError)
        assert result.error == "invalid_client_metadata"


class TestDelete:
    """Couvre la suppression d'un client (RFC 7592 §4)."""

    def test_deletes_client(self) -> None:
        usecase = _usecase()
        registered = _registered(usecase)

        result = run(
            usecase.delete(
                DeleteClientRequest(registered.client_id, registered.registration_access_token)
            )
        )

        assert result is None
        assert run(usecase._clients.find_by_id(registered.client_id)) is None
        read = run(
            usecase.read(
                ReadClientRequest(registered.client_id, registered.registration_access_token)
            )
        )
        assert isinstance(read, RegistrationError)
        assert read.status_code == 404

    def test_rejects_delete_without_token(self) -> None:
        usecase = _usecase()
        registered = _registered(usecase)

        result = run(usecase.delete(DeleteClientRequest(registered.client_id, "")))

        assert isinstance(result, RegistrationError)
        assert result.status_code == 401
        assert run(usecase._clients.find_by_id(registered.client_id)) is not None


class TestRegistrationEndpoint:
    """Couvre les endpoints HTTP POST /register + gestion (RFC 7591/7592)."""

    def _app(self, *, enabled: bool = True) -> FastAPI:
        return create_app(
            Settings(
                issuer=_ISSUER,
                base_url=_ISSUER,
                jwks_algorithms=("RS256",),
                registration_enabled=enabled,
                registration_initial_access_tokens=(_INITIAL_TOKEN,),
            )
        )

    def test_full_registration_lifecycle(self) -> None:
        with TestClient(self._app()) as client:
            response = client.post("/register", json=_REGISTRATION)
            assert response.status_code == 401
            assert response.json()["error"] == "invalid_client"

            response = client.post(
                "/register",
                json=_REGISTRATION,
                headers={"authorization": f"Bearer {_INITIAL_TOKEN}"},
            )
            assert response.status_code == 201, response.text
            registration = response.json()
            assert registration["client_id"]
            assert registration["client_secret"]
            assert registration["registration_access_token"]
            assert response.headers["location"] == registration["registration_client_uri"]

            auth = {"authorization": f"Bearer {registration['registration_access_token']}"}
            response = client.get(registration["registration_client_uri"], headers=auth)
            assert response.status_code == 200
            assert response.json()["client_id"] == registration["client_id"]
            assert "client_secret" not in response.json()

            response = client.put(
                registration["registration_client_uri"],
                json={
                    "redirect_uris": ["https://moved.example/cb"],
                    "scope": "openid",
                },
                headers=auth,
            )
            assert response.status_code == 200
            assert response.json()["redirect_uris"] == ["https://moved.example/cb"]

            response = client.delete(registration["registration_client_uri"], headers=auth)
            assert response.status_code == 204

            response = client.get(registration["registration_client_uri"], headers=auth)
            assert response.status_code == 404

    def test_rejects_malformed_metadata_over_http(self) -> None:
        with TestClient(self._app()) as client:
            response = client.post(
                "/register",
                content="not-json",
                headers={"content-type": "application/json"},
            )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_rejects_registration_when_disabled(self) -> None:
        with TestClient(self._app(enabled=False)) as client:
            response = client.post("/register", json=_REGISTRATION)

        assert response.status_code == 404

    def test_discovery_advertises_registration_endpoint_when_enabled(self) -> None:
        with TestClient(self._app()) as client:
            metadata = client.get("/.well-known/openid-configuration").json()

        assert metadata["registration_endpoint"] == f"{_ISSUER}/register"

    def test_discovery_omits_registration_endpoint_when_disabled(self) -> None:
        with TestClient(self._app(enabled=False)) as client:
            metadata = client.get("/.well-known/openid-configuration").json()

        assert metadata.get("registration_endpoint") is None
