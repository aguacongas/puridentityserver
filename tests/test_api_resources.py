"""Tests de la feature ApiResources (ressources protégées / scopes d'API).

Couvre le registre (CRUD + seed), le refus des scopes non enregistrés aux
endpoints d'émission (authorize / token / device / PAR), le calcul de
l'audience ``aud`` des access tokens (resource protégée, ou client par
défaut), l'introspection d'un jeton multi-audience et l'alignement du
discovery (``scopes_supported``).
"""

import asyncio
import base64
import hashlib
from collections.abc import Awaitable
from pathlib import Path
from typing import TypeVar
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jwt import decode as jwt_decode

from puridentityserver.application.api_resource import (
    ApiResourceData,
    ApiResourceError,
    ApiResourceRequest,
    ApiResourceUseCase,
)
from puridentityserver.application.introspect import (
    IntrospectConfig,
    IntrospectRequest,
    IntrospectResponse,
    IntrospectUseCase,
)
from puridentityserver.application.scope_registry import ScopeRegistry
from puridentityserver.domain.api_resource import ApiResource
from puridentityserver.domain.authorization import Client, ClientType, Scope
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.factory import build_api_resource_repository
from puridentityserver.infrastructure.persistence.memory.api_resources import (
    InMemoryApiResourceRepository,
)
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.persistence.memory.identity_resources import (
    InMemoryIdentityResourceRepository,
)
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.memory.revoked_tokens import (
    InMemoryRevokedTokenRepository,
)
from puridentityserver.infrastructure.persistence.sql.api_resources import SQLApiResourceRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_API_NAME = "sample-api"
_API_SCOPES = ("api.read", "api.write")

_API_RESOURCE = {
    "name": _API_NAME,
    "display_name": "API de démonstration",
    "scopes": list(_API_SCOPES),
    "allowed_access_token_signing_algos": ["ES256"],
}

_API_CLIENT = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile api.read",
    "client_type": "confidential",
}

_REJECT_CLIENT = {
    "client_id": "loose-app",
    "client_secret": "super-secret",
    "scopes": "openid profile nope",
    "client_type": "confidential",
}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def _resource() -> ApiResource:
    """ApiResource de test (scopes identiques au seed par défaut)."""
    return ApiResource(
        name=_API_NAME,
        display_name="API de démonstration",
        scopes=frozenset(_API_SCOPES),
        allowed_access_token_signing_algos=("ES256",),
    )


async def _make_sql_repo(tmp_path: Path) -> SQLApiResourceRepository:
    repo = SQLApiResourceRepository(f"sqlite+aiosqlite:///{tmp_path / 'api_resources.db'}")
    await repo.initialise()
    return repo


def _close(repo: SQLApiResourceRepository) -> None:
    run(repo.close())


def _app(
    *api_resources: dict[str, object],
    clients_seed: tuple[dict[str, object], ...] = (_API_CLIENT,),
    **settings: object,
) -> FastAPI:
    """Assemble une application avec les ApiResources et clients seedés."""
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


def _s256_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _redirect_query(redirect_url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(redirect_url).query)


def _access_token(client: TestClient, scope: str = "openid profile api.read") -> str:
    """Joue le flow Authorization Code + PKCE complet et retourne l'access_token."""
    auth = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "web-app",
            "redirect_uri": "https://app.example/callback",
            "scope": scope,
            "state": "st-1",
            "code_challenge": _s256_challenge("verifier-verifier"),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    code = _redirect_query(auth.headers["location"])["code"][0]
    access = client.post(
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
    return str(access.json()["access_token"])


class TestInMemoryApiResourceRepository:
    """Couvre le comportement du store mémoire (tests unitaires)."""

    def test_save_and_find_by_name(self) -> None:
        repo = InMemoryApiResourceRepository()
        run(repo.save(_resource()))

        assert run(repo.find_by_name(_API_NAME)) == _resource()

    def test_save_overwrites_same_name(self) -> None:
        repo = InMemoryApiResourceRepository()
        run(repo.save(_resource()))
        run(repo.save(ApiResource(name=_API_NAME, scopes=frozenset({"api.other"}))))

        stored = run(repo.find_by_name(_API_NAME))
        assert stored is not None
        assert stored.scopes == frozenset({"api.other"})
        assert len(run(repo.find_all())) == 1

    def test_unknown_name_returns_none(self) -> None:
        repo = InMemoryApiResourceRepository()

        assert run(repo.find_by_name("ghost")) is None

    def test_delete_removes_resource(self) -> None:
        repo = InMemoryApiResourceRepository()
        run(repo.save(_resource()))

        run(repo.delete(_API_NAME))

        assert run(repo.find_by_name(_API_NAME)) is None


class TestSQLApiResourceRepository:
    """Couvre le comportement du store SQL (SQLite asynchrone)."""

    def test_save_find_and_survives_restart(self, tmp_path: Path) -> None:
        repo = run(_make_sql_repo(tmp_path))
        run(repo.save(_resource()))
        _close(repo)

        repo2 = SQLApiResourceRepository(f"sqlite+aiosqlite:///{tmp_path / 'api_resources.db'}")
        try:
            stored = run(repo2.find_by_name(_API_NAME))
        finally:
            _close(repo2)

        assert stored == _resource()

    def test_find_all_returns_seeded_resources(self, tmp_path: Path) -> None:
        repo = run(_make_sql_repo(tmp_path))
        run(repo.save(_resource()))
        run(repo.save(ApiResource(name="second-api", scopes=frozenset({"api.other"}))))

        assert {r.name for r in run(repo.find_all())} == {_API_NAME, "second-api"}
        _close(repo)

    def test_unknown_name_returns_none(self, tmp_path: Path) -> None:
        repo = run(_make_sql_repo(tmp_path))

        assert run(repo.find_by_name("ghost")) is None
        _close(repo)


class TestFactory:
    """Couvre le choix du registre de resources selon ``storage_type``."""

    def test_builds_memory_repository(self) -> None:
        repository = build_api_resource_repository(Settings(storage_type="memory"))

        assert isinstance(repository, InMemoryApiResourceRepository)

    def test_builds_sql_repository(self) -> None:
        repository = build_api_resource_repository(
            Settings(storage_type="sql", storage_dsn="sqlite:///memory")
        )

        assert isinstance(repository, SQLApiResourceRepository)

    def test_rejects_unknown_store_type(self) -> None:
        settings = Settings.model_construct(storage_type="cassandra")

        with pytest.raises(ValueError, match="non supporté"):
            build_api_resource_repository(settings)


class TestSettingsApiResources:
    """Couvre le chargement du seed ``api_resources_seed``."""

    def test_config_seeds_resources(self) -> None:
        settings = Settings(api_resources_seed=(_API_RESOURCE,))

        resources = settings.seed_api_resources
        assert len(resources) == 1
        assert resources[0].name == _API_NAME
        assert resources[0].display_name == "API de démonstration"
        assert resources[0].scopes == frozenset(_API_SCOPES)
        assert resources[0].allowed_access_token_signing_algos == ("ES256",)

    def test_env_json_list_seeds_resources(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "PURIDENTITYSERVER_API_RESOURCES_SEED",
            f'[{{"name": "{_API_NAME}", "scopes": ["api.read"]}}]',
        )

        settings = Settings(_env_file=None)

        resources = settings.seed_api_resources
        assert len(resources) == 1
        assert resources[0].scopes == frozenset({"api.read"})

    def test_rejects_non_list_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PURIDENTITYSERVER_API_RESOURCES_SEED", '{"name": "' + _API_NAME + '"}')

        with pytest.raises(ValueError, match="liste JSON"):
            Settings(_env_file=None)

    def test_rejects_unknown_signing_algorithm(self) -> None:
        settings = Settings(
            api_resources_seed=(
                {
                    "name": _API_NAME,
                    "scopes": ["api.read"],
                    "allowed_access_token_signing_algos": ["XX512"],
                },
            )
        )

        with pytest.raises(ValueError, match="non supportés"):
            _ = settings.seed_api_resources


class TestApiResourceUseCase:
    """Couvre les branches CRUD du usecase de gestion des ApiResources."""

    def _repo(self, *resources: ApiResource) -> InMemoryApiResourceRepository:
        repository = InMemoryApiResourceRepository()
        for resource in resources:
            run(repository.save(resource))
        return repository

    def test_create_then_read_then_list(self) -> None:
        usecase = ApiResourceUseCase(self._repo())

        created = run(
            usecase.create(
                ApiResourceRequest(
                    name=_API_NAME,
                    display_name="API",
                    scopes=frozenset(_API_SCOPES),
                )
            )
        )

        assert isinstance(created, ApiResourceData)
        assert created.name == _API_NAME
        assert created.scopes == sorted(_API_SCOPES)
        assert run(usecase.read(_API_NAME)) == created
        assert run(usecase.list()) == [created]

    def test_duplicate_create_returns_409(self) -> None:
        usecase = ApiResourceUseCase(self._repo(_resource()))

        result = run(
            usecase.create(ApiResourceRequest(name=_API_NAME, scopes=frozenset({"api.other"})))
        )

        assert isinstance(result, ApiResourceError)
        assert result.status_code == 409
        assert result.error == "invalid_api_resource"

    def test_update_replaces_fields_but_keeps_name(self) -> None:
        usecase = ApiResourceUseCase(self._repo(_resource()))

        updated = run(
            usecase.update(
                _API_NAME,
                ApiResourceRequest(
                    name="autre-nom",
                    display_name="Nouveau",
                    scopes=frozenset({"api.write", "api.admin"}),
                ),
            )
        )

        assert isinstance(updated, ApiResourceData)
        assert updated.name == _API_NAME
        assert updated.display_name == "Nouveau"
        assert updated.scopes == ["api.admin", "api.write"]
        assert run(usecase.read(_API_NAME)) is not None

    def test_update_unknown_returns_404(self) -> None:
        usecase = ApiResourceUseCase(self._repo())

        result = run(usecase.update("ghost", ApiResourceRequest(name="ghost")))

        assert isinstance(result, ApiResourceError)
        assert result.status_code == 404

    def test_delete_removes_resource(self) -> None:
        usecase = ApiResourceUseCase(self._repo(_resource()))

        assert run(usecase.delete(_API_NAME)) is None
        assert isinstance(run(usecase.read(_API_NAME)), ApiResourceError)

    def test_delete_unknown_returns_404(self) -> None:
        usecase = ApiResourceUseCase(self._repo())

        result = run(usecase.delete("ghost"))

        assert isinstance(result, ApiResourceError)
        assert result.status_code == 404

    def test_create_rejects_empty_name(self) -> None:
        usecase = ApiResourceUseCase(self._repo())

        result = run(usecase.create(ApiResourceRequest(name="  ")))

        assert isinstance(result, ApiResourceError)
        assert result.status_code == 400

    def test_create_rejects_invalid_name_characters(self) -> None:
        usecase = ApiResourceUseCase(self._repo())

        result = run(usecase.create(ApiResourceRequest(name="mauvais nom")))

        assert isinstance(result, ApiResourceError)
        assert result.status_code == 400

    def test_create_rejects_invalid_scope(self) -> None:
        usecase = ApiResourceUseCase(self._repo())

        result = run(
            usecase.create(ApiResourceRequest(name=_API_NAME, scopes=frozenset({"mauvais scope"})))
        )

        assert isinstance(result, ApiResourceError)
        assert result.status_code == 400
        assert "Scope(s) d'API invalide(s)" in result.error_description

    def test_create_rejects_unknown_signing_algorithm(self) -> None:
        usecase = ApiResourceUseCase(self._repo())

        result = run(
            usecase.create(
                ApiResourceRequest(
                    name=_API_NAME,
                    scopes=frozenset({"api.read"}),
                    allowed_access_token_signing_algos=frozenset({"XX512"}),
                )
            )
        )

        assert isinstance(result, ApiResourceError)
        assert result.status_code == 400
        assert "non supportés" in result.error_description


class TestApiResourceEndpoint:
    """Couvre l'API HTTP de gestion (CRUD) sur ``/api-resources``."""

    def test_default_app_exposes_empty_registry(self) -> None:
        with TestClient(_app()) as client:
            listing = client.get("/api-resources")

        assert listing.status_code == 200
        assert listing.json() == []

    def test_create_list_read_update_delete(self) -> None:
        with TestClient(_app()) as client:
            created = client.post("/api-resources", json=_API_RESOURCE)
            created_payload = created.json()
            listing = client.get("/api-resources")
            read = client.get(f"/api-resources/{_API_NAME}")
            updated = client.put(
                f"/api-resources/{_API_NAME}",
                json={"name": "autre", "display_name": "API", "scopes": ["api.write"]},
            )
            deleted = client.delete(f"/api-resources/{_API_NAME}")
            gone = client.get(f"/api-resources/{_API_NAME}")

        assert created.status_code == 201
        assert created_payload["name"] == _API_NAME
        assert created_payload["scopes"] == list(_API_SCOPES)
        assert created_payload["allowed_access_token_signing_algos"] == ["ES256"]
        assert listing.json() == [created_payload]
        assert read.json() == created_payload
        assert updated.status_code == 200
        assert updated.json()["scopes"] == ["api.write"]
        assert deleted.status_code == 204
        assert gone.status_code == 404

    def test_duplicate_create_returns_409(self) -> None:
        with TestClient(_app(_API_RESOURCE)) as client:
            response = client.post("/api-resources", json=_API_RESOURCE)

        assert response.status_code == 409
        assert response.json()["error"] == "invalid_api_resource"

    def test_invalid_body_returns_400(self) -> None:
        with TestClient(_app()) as client:
            response = client.post("/api-resources", json={"name": "mauvais nom"})

        assert response.status_code == 400

    def test_invalid_json_returns_400(self) -> None:
        with TestClient(_app()) as client:
            response = client.post("/api-resources", content="nope", headers={})

        assert response.status_code == 400

    def test_unknown_read_returns_404(self) -> None:
        with TestClient(_app()) as client:
            response = client.get("/api-resources/ghost")

        assert response.status_code == 404


class TestScopeRegistry:
    """Couvre la vérification d'enregistrement des scopes et le calcul d'audience."""

    def _registry(self, *resources: ApiResource) -> ScopeRegistry:
        identity = InMemoryIdentityResourceRepository()
        api = InMemoryApiResourceRepository()
        for resource in resources or (_resource(),):
            run(api.save(resource))
        return ScopeRegistry(identity, api)

    def test_unknown_scopes_filters_registered(self) -> None:
        registry = self._registry()

        unknown = run(registry.unknown_scopes(frozenset({"openid", "api.read", "ghost"})))

        assert unknown == ("ghost",)

    def test_known_scope_names_merges_identity_and_api(self) -> None:
        registry = self._registry()

        known = run(registry.known_scope_names())

        assert {"openid", "profile", "api.read", "api.write"} <= known

    def test_audience_is_single_resource_name(self) -> None:
        registry = self._registry()

        audience = run(registry.audiences_for("client-id", frozenset({"openid", "api.read"})))

        assert audience == _API_NAME

    def test_audience_is_sorted_list_for_multiple_resources(self) -> None:
        identity = InMemoryIdentityResourceRepository()
        api = InMemoryApiResourceRepository()
        for resource in (
            _resource(),
            ApiResource(name="a-api", scopes=frozenset({"a.read"})),
        ):
            run(api.save(resource))
        registry = ScopeRegistry(identity, api)

        audience = run(registry.audiences_for("client-id", frozenset({"api.read", "a.read"})))

        assert audience == ["a-api", _API_NAME]

    def test_audience_falls_back_to_client_id(self) -> None:
        registry = self._registry()

        audience = run(registry.audiences_for("client-id", frozenset({"openid", "profile"})))

        assert audience == "client-id"

    def test_audience_falls_back_without_api_repository(self) -> None:
        registry = ScopeRegistry()

        audience = run(registry.audiences_for("client-id", frozenset({"openid"})))

        assert audience == "client-id"


class TestApiResourceScopeValidation:
    """Critères d'acceptation #45 : refus des scopes non enregistrés aux émissions."""

    def test_discovery_lists_api_scopes(self) -> None:
        with TestClient(_app(_API_RESOURCE)) as client:
            metadata = client.get("/.well-known/openid-configuration").json()

        assert metadata["scopes_supported"] == [
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
            "api.read",
            "api.write",
        ]

    def test_discovery_without_api_resources_keeps_standard_scopes(self) -> None:
        with TestClient(_app()) as client:
            metadata = client.get("/.well-known/openid-configuration").json()

        assert "api.read" not in metadata["scopes_supported"]

    def test_authorize_rejects_unregistered_scope(self) -> None:
        with TestClient(_app()) as client:
            response = client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": "web-app",
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid totally.unregistered",
                },
                follow_redirects=False,
            )

        assert response.status_code == 302
        assert _redirect_query(response.headers["location"])["error"] == ["invalid_scope"]

    def test_authorize_accepts_registered_api_scope(self) -> None:
        with TestClient(_app(_API_RESOURCE)) as client:
            response = client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": "web-app",
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid profile api.read",
                    "code_challenge": _s256_challenge("verifier-verifier"),
                    "code_challenge_method": "S256",
                },
                follow_redirects=False,
            )

        assert response.status_code == 302
        assert "code" in _redirect_query(response.headers["location"])

    def test_par_rejects_unregistered_scope(self) -> None:
        with TestClient(_app(_API_RESOURCE)) as client:
            response = client.post(
                "/par",
                data={
                    "response_type": "code",
                    "client_id": "web-app",
                    "redirect_uri": "https://app.example/callback",
                    "scope": "openid totally.unregistered",
                },
            )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_scope"

    def test_client_credentials_rejects_unregistered_scope(self) -> None:
        with TestClient(_app(clients_seed=(_REJECT_CLIENT,))) as client:
            response = client.post(
                "/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "loose-app",
                    "client_secret": "super-secret",
                    "scope": "openid nope",
                },
            )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_scope"

    def test_device_authorization_rejects_unregistered_scope(self) -> None:
        with TestClient(_app(clients_seed=(_REJECT_CLIENT,))) as client:
            response = client.post(
                "/device_authorization",
                data={
                    "client_id": "loose-app",
                    "client_secret": "super-secret",
                    "scope": "openid nope",
                },
            )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_scope"

    def test_access_token_aud_is_api_resource(self) -> None:
        with TestClient(_app(_API_RESOURCE)) as client:
            token = _access_token(client)

        assert jwt_decode(token, options={"verify_signature": False})["aud"] == _API_NAME

    def test_access_token_aud_without_api_scope_is_client_id(self) -> None:
        with TestClient(_app(_API_RESOURCE)) as client:
            token = _access_token(client, scope="openid profile")

        assert jwt_decode(token, options={"verify_signature": False})["aud"] == "web-app"

    def test_client_credentials_aud_is_api_resource(self) -> None:
        api_client = {
            "client_id": "cc-app",
            "client_secret": "super-secret",
            "scopes": "openid profile api.read",
            "client_type": "confidential",
        }
        with TestClient(_app(_API_RESOURCE, clients_seed=(api_client,))) as client:
            response = client.post(
                "/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "cc-app",
                    "client_secret": "super-secret",
                    "scope": "openid api.read",
                },
            )

        assert response.status_code == 200
        access = jwt_decode(response.json()["access_token"], options={"verify_signature": False})
        assert access["aud"] == _API_NAME
        assert access["scope"] == "api.read openid"


class TestIntrospectApiAudience:
    """Introspection d'un jeton dont l'audience est une liste de resources."""

    def _make_usecase(self) -> tuple[IntrospectUseCase, PyJWTTokenManager]:
        clients = InMemoryClientRepository()
        run(
            clients.save(
                Client(
                    client_id="web-app",
                    redirect_uris=frozenset({"https://app.example/callback"}),
                    scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
                    client_type=ClientType.CONFIDENTIAL,
                    client_secret_hash=hashlib.sha256(b"super-secret").hexdigest(),
                )
            )
        )
        token_manager = PyJWTTokenManager(DefaultKeyManager(InMemoryKeyPairRepository()))
        usecase = IntrospectUseCase(
            IntrospectConfig(issuer=_ISSUER),
            clients,
            token_manager,
            InMemoryRevokedTokenRepository(),
        )
        return usecase, token_manager

    @staticmethod
    def _mint(token_manager: PyJWTTokenManager, audience: str | list[str]) -> str:
        return run(
            token_manager.create_access_token(
                algorithm=JWTAlgorithm.RS256,
                issuer=_ISSUER,
                subject="alice",
                audience=audience,
                expires_at=9999999999,
                issued_at=1000000000,
                scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
            )
        )

    def test_introspect_multiaudience_token_without_client_id(self) -> None:
        usecase, token_manager = self._make_usecase()
        token = self._mint(token_manager, ["a-api", "b-api"])

        result = run(
            usecase.execute(
                IntrospectRequest(token=token, client_id="web-app", client_secret="super-secret")
            )
        )

        assert isinstance(result, IntrospectResponse)
        assert result.active is True
        assert result.claims["aud"] == ["a-api", "b-api"]
        assert "client_id" not in result.claims

    def test_introspect_single_audience_maps_client_id(self) -> None:
        usecase, token_manager = self._make_usecase()
        token = self._mint(token_manager, "web-app")

        result = run(
            usecase.execute(
                IntrospectRequest(token=token, client_id="web-app", client_secret="super-secret")
            )
        )

        assert isinstance(result, IntrospectResponse)
        assert result.claims["aud"] == "web-app"
        assert result.claims["client_id"] == "web-app"
