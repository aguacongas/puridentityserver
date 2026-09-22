"""Tests de la feature IdentityResources (scopes identité, OIDC Core 1.0 §5.4)."""

import asyncio
from collections.abc import Awaitable
from pathlib import Path
from typing import TypeVar

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.discovery import DiscoveryConfig, DiscoveryUseCase
from puridentityserver.application.identity_resource import (
    IdentityResourceData,
    IdentityResourceError,
    IdentityResourceRequest,
    IdentityResourceUseCase,
)
from puridentityserver.application.userinfo import (
    UserInfoConfig,
    UserInfoRequest,
    UserInfoResponse,
    UserInfoUseCase,
)
from puridentityserver.domain.identity_resource import DEFAULT_IDENTITY_RESOURCES, IdentityResource
from puridentityserver.infrastructure.persistence.factory import build_identity_resource_repository
from puridentityserver.infrastructure.persistence.memory.identity_resources import (
    InMemoryIdentityResourceRepository,
)
from puridentityserver.infrastructure.persistence.memory.revoked_tokens import (
    InMemoryRevokedTokenRepository,
)
from puridentityserver.infrastructure.persistence.sql.identity_resources import (
    SQLIdentityResourceRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_PROFILE_JSON = {
    "name": "profile",
    "display_name": "Votre profil",
    "user_claims": [
        "name",
        "family_name",
        "given_name",
        "birthdate",
        "roles",
    ],
    "show_in_discovery_document": True,
}


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def _profile() -> IdentityResource:
    """IdentityResource de test (scope profile filré pour les besoins du test)."""
    return IdentityResource(
        name="profile",
        display_name="Votre profil",
        user_claims=frozenset({"name", "family_name", "given_name", "birthdate", "roles"}),
    )


async def _make_sql_repo(tmp_path: Path) -> SQLIdentityResourceRepository:
    repo = SQLIdentityResourceRepository(f"sqlite+aiosqlite:///{tmp_path / 'identity.db'}")
    await repo.initialise()
    return repo


def _close(repo: SQLIdentityResourceRepository) -> None:
    run(repo.close())


class TestInMemoryIdentityResourceRepository:
    """Couvre le comportement du store mémoire (tests unitaires)."""

    def test_save_and_find_by_name(self) -> None:
        repo = InMemoryIdentityResourceRepository()
        run(repo.save(_profile()))

        assert run(repo.find_by_name("profile")) == _profile()

    def test_save_overwrites_same_name(self) -> None:
        repo = InMemoryIdentityResourceRepository()
        run(repo.save(_profile()))
        run(repo.save(IdentityResource(name="profile", user_claims=frozenset({"name", "email"}))))

        stored = run(repo.find_by_name("profile"))
        assert stored is not None
        assert stored.user_claims == frozenset({"name", "email"})
        assert len(run(repo.find_all())) == 1

    def test_unknown_name_returns_none(self) -> None:
        repo = InMemoryIdentityResourceRepository()

        assert run(repo.find_by_name("ghost")) is None

    def test_delete_removes_resource(self) -> None:
        repo = InMemoryIdentityResourceRepository()
        run(repo.save(_profile()))

        run(repo.delete("profile"))

        assert run(repo.find_by_name("profile")) is None

    def test_initialise_is_noop(self) -> None:
        assert run(InMemoryIdentityResourceRepository().initialise()) is None


class TestSQLIdentityResourceRepository:
    """Couvre le comportement du store SQL (SQLite asynchrone)."""

    def test_save_find_and_survives_restart(self, tmp_path: Path) -> None:
        repo = run(_make_sql_repo(tmp_path))
        run(repo.save(_profile()))
        _close(repo)

        repo2 = SQLIdentityResourceRepository(f"sqlite+aiosqlite:///{tmp_path / 'identity.db'}")
        try:
            stored = run(repo2.find_by_name("profile"))
        finally:
            _close(repo2)

        assert stored == _profile()

    def test_find_all_returns_seeded_resources(self, tmp_path: Path) -> None:
        repo = run(_make_sql_repo(tmp_path))
        run(repo.save(_profile()))
        run(repo.save(IdentityResource(name="email", user_claims=frozenset({"email"}))))

        assert {r.name for r in run(repo.find_all())} == {"profile", "email"}
        _close(repo)

    def test_unknown_name_returns_none(self, tmp_path: Path) -> None:
        repo = run(_make_sql_repo(tmp_path))

        assert run(repo.find_by_name("ghost")) is None
        _close(repo)

    def test_delete_removes_resource(self, tmp_path: Path) -> None:
        repo = run(_make_sql_repo(tmp_path))
        run(repo.save(_profile()))

        run(repo.delete("profile"))

        assert run(repo.find_by_name("profile")) is None
        _close(repo)


class TestFactory:
    """Couvre le choix du registre de resources selon ``storage_type``."""

    def test_builds_memory_repository(self) -> None:
        repository = build_identity_resource_repository(Settings(storage_type="memory"))

        assert isinstance(repository, InMemoryIdentityResourceRepository)

    def test_builds_sql_repository(self) -> None:
        repository = build_identity_resource_repository(
            Settings(storage_type="sql", storage_dsn="sqlite:///memory")
        )

        assert isinstance(repository, SQLIdentityResourceRepository)

    def test_rejects_unknown_store_type(self) -> None:
        settings = Settings.model_construct(storage_type="cassandra")

        with pytest.raises(ValueError, match="non supporté"):
            build_identity_resource_repository(settings)


class TestSettingsIdentityResources:
    """Couvre le chargement du seed ``identity_resources_seed``."""

    def test_defaults_seeded_even_without_config_entry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = Path(__file__).resolve().parents[1] / "config.toml"
        monkeypatch.setenv("PURIDENTITYSERVER_SETTINGS_FILE", str(config))
        settings = Settings(_env_file=None)

        assert [r.name for r in settings.seed_identity_resources] == [
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
        ]
        profile = next(r for r in settings.seed_identity_resources if r.name == "profile")
        assert "roles" in profile.user_claims
        assert (
            "sub"
            in next(r for r in settings.seed_identity_resources if r.name == "openid").user_claims
        )

    def test_defaults_to_standard_resources(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = tmp_path / "config.toml"
        config.write_text("[settings]\nissuer = 'http://127.0.0.1:8000'\n", encoding="utf-8")
        monkeypatch.setenv("PURIDENTITYSERVER_SETTINGS_FILE", str(config))

        settings = Settings(_env_file=None)

        assert settings.seed_identity_resources == DEFAULT_IDENTITY_RESOURCES

    def test_config_adds_resources_after_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "PURIDENTITYSERVER_IDENTITY_RESOURCES_SEED",
            '[{"name": "custom", "user_claims": ["custom_claim"]}]',
        )
        settings = Settings(_env_file=None)

        names = [r.name for r in settings.seed_identity_resources]
        assert names == [
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
            "custom",
        ]
        custom = settings.seed_identity_resources[-1]
        assert custom.user_claims == frozenset({"custom_claim"})

    def test_config_overrides_default_by_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "PURIDENTITYSERVER_IDENTITY_RESOURCES_SEED",
            '[{"name": "profile", "user_claims": ["custom_profile_claim"]}]',
        )
        settings = Settings(_env_file=None)

        names = [r.name for r in settings.seed_identity_resources]
        assert names == ["openid", "profile", "email", "address", "phone", "offline_access"]
        profile = next(r for r in settings.seed_identity_resources if r.name == "profile")
        assert profile.user_claims == frozenset({"custom_profile_claim"})

    def test_rejects_non_list_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PURIDENTITYSERVER_IDENTITY_RESOURCES_SEED", '{"name": "custom"}')

        with pytest.raises(ValueError, match="liste JSON"):
            Settings(_env_file=None)


class TestIdentityResourceUseCase:
    """Couvre les branches CRUD du usecase de gestion des IdentityResources."""

    def _repo(self, *resources: IdentityResource) -> InMemoryIdentityResourceRepository:
        repository = InMemoryIdentityResourceRepository()
        for resource in resources:
            run(repository.save(resource))
        return repository

    def test_create_then_read_then_list(self) -> None:
        usecase = IdentityResourceUseCase(self._repo())

        created = run(
            usecase.create(
                IdentityResourceRequest(
                    name="profile",
                    display_name="Votre profil",
                    user_claims=frozenset({"name", "roles"}),
                )
            )
        )

        assert isinstance(created, IdentityResourceData)
        assert created.name == "profile"
        assert created.user_claims == ["name", "roles"]
        assert run(usecase.read("profile")) == created
        assert run(usecase.list()) == [created]

    def test_create_rejects_duplicate_name(self) -> None:
        usecase = IdentityResourceUseCase(self._repo(_profile()))

        result = run(usecase.create(IdentityResourceRequest(name="profile")))

        assert isinstance(result, IdentityResourceError)
        assert result.status_code == 409

    def test_create_rejects_empty_name(self) -> None:
        usecase = IdentityResourceUseCase(self._repo())

        result = run(usecase.create(IdentityResourceRequest(name="  ")))

        assert isinstance(result, IdentityResourceError)
        assert result.status_code == 400

    def test_create_rejects_oversized_name(self) -> None:
        usecase = IdentityResourceUseCase(self._repo())

        result = run(usecase.create(IdentityResourceRequest(name="x" * 129)))

        assert isinstance(result, IdentityResourceError)
        assert result.status_code == 400

    def test_create_rejects_invalid_characters(self) -> None:
        usecase = IdentityResourceUseCase(self._repo())

        result = run(usecase.create(IdentityResourceRequest(name="mauvais nom")))

        assert isinstance(result, IdentityResourceError)
        assert result.status_code == 400

    def test_update_replaces_fields_and_keeps_name(self) -> None:
        usecase = IdentityResourceUseCase(self._repo(_profile()))

        updated = run(
            usecase.update(
                "profile",
                IdentityResourceRequest(
                    name="autre-nom",
                    display_name="Nouveau libellé",
                    user_claims=frozenset({"email"}),
                    show_in_discovery_document=False,
                ),
            )
        )

        assert isinstance(updated, IdentityResourceData)
        assert updated.name == "profile"
        assert updated.display_name == "Nouveau libellé"
        assert updated.user_claims == ["email"]
        assert updated.show_in_discovery_document is False

    def test_update_unknown_name_returns_404(self) -> None:
        usecase = IdentityResourceUseCase(self._repo())

        result = run(usecase.update("ghost", IdentityResourceRequest(name="profile")))

        assert isinstance(result, IdentityResourceError)
        assert result.status_code == 404

    def test_delete_removes_resource(self) -> None:
        usecase = IdentityResourceUseCase(self._repo(_profile()))

        assert run(usecase.delete("profile")) is None
        error = run(usecase.read("profile"))
        assert isinstance(error, IdentityResourceError)
        assert error.status_code == 404

    def test_delete_unknown_name_returns_404(self) -> None:
        usecase = IdentityResourceUseCase(self._repo())

        result = run(usecase.delete("ghost"))

        assert isinstance(result, IdentityResourceError)
        assert result.status_code == 404


class TestUserInfoResourceDriven:
    """Couvre le filtrage des claims piloté par les IdentityResources injectées."""

    def test_claims_follow_custom_resource(self) -> None:
        class _FakeTokenManager:
            async def validate_access_token(
                self, *, token: str, issuer: str
            ) -> dict[str, object] | None:
                return {"sub": "alice", "scope": "openid custom"}

        repository = InMemoryIdentityResourceRepository()
        run(
            repository.save(
                IdentityResource(name="custom", user_claims=frozenset({"custom_claim"}))
            )
        )

        class _Provider:
            async def get_claims(self, subject: str) -> object:
                return type("C", (), {"claims": {"custom_claim": "valeur", "name": "Alice"}})()

        usecase = UserInfoUseCase(
            UserInfoConfig(issuer=_ISSUER),
            _FakeTokenManager(),  # type: ignore[arg-type]
            _Provider(),  # type: ignore[arg-type]
            InMemoryRevokedTokenRepository(),
            repository,
        )

        result = run(usecase.execute(UserInfoRequest(access_token="token")))

        assert isinstance(result, UserInfoResponse)
        assert result.claims == {"sub": "alice", "custom_claim": "valeur"}

    def test_scope_openid_only_exposes_sub(self) -> None:
        class _FakeTokenManager:
            async def validate_access_token(
                self, *, token: str, issuer: str
            ) -> dict[str, object] | None:
                return {"sub": "alice", "scope": "openid"}

        repository = InMemoryIdentityResourceRepository()
        run(repository.save(_profile()))

        class _Provider:
            async def get_claims(self, subject: str) -> object:
                return type("C", (), {"claims": {"name": "Alice", "email": "alice@example.com"}})()

        usecase = UserInfoUseCase(
            UserInfoConfig(issuer=_ISSUER),
            _FakeTokenManager(),  # type: ignore[arg-type]
            _Provider(),  # type: ignore[arg-type]
            InMemoryRevokedTokenRepository(),
            repository,
        )

        result = run(usecase.execute(UserInfoRequest(access_token="token")))

        assert isinstance(result, UserInfoResponse)
        assert result.claims == {"sub": "alice"}


class TestDiscoveryResourceDriven:
    """Couvre `scopes_supported` / `claims_supported` dérivés des resources."""

    def test_scopes_and_claims_follow_registered_resources(self) -> None:
        repository = InMemoryIdentityResourceRepository()
        run(repository.save(_profile()))
        run(repository.save(IdentityResource(name="email", user_claims=frozenset({"email"}))))

        usecase = DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER), identity_resources=repository)
        document = run(usecase.execute())

        assert document["scopes_supported"] == ["profile", "email"]
        assert document["claims_supported"] == [
            "birthdate",
            "family_name",
            "given_name",
            "name",
            "roles",
            "email",
        ]

    def test_falls_back_to_defaults_without_repository(self) -> None:
        usecase = DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER))
        document = run(usecase.execute())

        assert "openid" in document["scopes_supported"]
        assert "name" in document["claims_supported"]


_CUSTOM_JSON = {
    "name": "custom",
    "display_name": "Custom",
    "user_claims": ["custom_claim"],
    "show_in_discovery_document": True,
}

_DEFAULT_NAMES = ["openid", "profile", "email", "address", "phone", "offline_access"]


class TestIdentityResourceEndpoint:
    """Couvre l'API HTTP de gestion (CRUD) sur ``/identity-resources``."""

    def _app(self, *resources: dict[str, object]) -> FastAPI:
        return create_app(
            Settings(
                issuer=_ISSUER,
                base_url=_ISSUER,
                jwks_algorithms=("RS256",),
                identity_resources_seed=(*resources,),
                api_resources_seed=(),
                admin_required_claim_values=(),
            )
        )

    def test_defaults_seeded_without_config_entry(self) -> None:
        with TestClient(self._app()) as client:
            listing = client.get("/identity-resources")

        assert listing.status_code == 200
        assert [r["name"] for r in listing.json()] == _DEFAULT_NAMES

    def test_create_list_read_update_delete_flow(self) -> None:
        with TestClient(self._app(_CUSTOM_JSON)) as client:
            listing = client.get("/identity-resources")
            assert listing.status_code == 200
            assert [r["name"] for r in listing.json()] == [*_DEFAULT_NAMES, "custom"]

            created = client.post(
                "/identity-resources",
                json={
                    "name": "another",
                    "display_name": "Another",
                    "user_claims": ["another_claim"],
                    "show_in_discovery_document": True,
                },
            )
            assert created.status_code == 201
            assert created.headers["location"] == "/identity-resources/another"
            assert created.json()["name"] == "another"

            listing = client.get("/identity-resources")
            assert listing.status_code == 200
            assert [r["name"] for r in listing.json()] == [
                *_DEFAULT_NAMES,
                "custom",
                "another",
            ]

            read = client.get("/identity-resources/another")
            assert read.status_code == 200
            assert read.json()["user_claims"] == ["another_claim"]

            replaced = client.put(
                "/identity-resources/another",
                json={"name": "another-v2", "user_claims": ["autre_claim"]},
            )
            assert replaced.status_code == 200
            assert replaced.json()["name"] == "another"
            assert replaced.json()["user_claims"] == ["autre_claim"]

            deleted = client.delete("/identity-resources/another")
            assert deleted.status_code == 204
            assert client.get("/identity-resources/another").status_code == 404

    def test_duplicate_create_returns_409(self) -> None:
        with TestClient(self._app()) as client:
            response = client.post(
                "/identity-resources", json={"name": "profile", "user_claims": []}
            )

        assert response.status_code == 409
        assert response.json()["error"] == "invalid_identity_resource"

    def test_invalid_body_returns_400(self) -> None:
        with TestClient(self._app()) as client:
            response = client.post("/identity-resources", json={"name": "mauvais nom"})

        assert response.status_code == 400

    def test_invalid_json_returns_400(self) -> None:
        with TestClient(self._app()) as client:
            response = client.post("/identity-resources", content="nope", headers={})

        assert response.status_code == 400

    def test_unknown_read_returns_404(self) -> None:
        with TestClient(self._app()) as client:
            response = client.get("/identity-resources/ghost")

        assert response.status_code == 404

    def test_discovery_reflects_registered_resources(self) -> None:
        with TestClient(self._app(_CUSTOM_JSON)) as client:
            metadata = client.get("/.well-known/openid-configuration").json()

        assert metadata["scopes_supported"] == [*_DEFAULT_NAMES, "custom"]
        assert "custom_claim" in metadata["claims_supported"]
        assert "name" in metadata["claims_supported"]

    def test_config_overrides_default_claims(self) -> None:
        with TestClient(self._app(_PROFILE_JSON)) as client:
            listing = client.get("/identity-resources")
            metadata = client.get("/.well-known/openid-configuration").json()

        profile = next(r for r in listing.json() if r["name"] == "profile")
        assert sorted(profile["user_claims"]) == sorted(_PROFILE_JSON["user_claims"])
        assert metadata["scopes_supported"] == _DEFAULT_NAMES


class TestScopeEnumGuard:
    """Garde-fou : les scopes réservés restent couverts par les resources par défaut."""

    _STANDARD_SCOPES = (
        "openid",
        "profile",
        "email",
        "address",
        "phone",
        "offline_access",
    )

    def test_defaults_cover_standard_scopes(self) -> None:
        assert {resource.name for resource in DEFAULT_IDENTITY_RESOURCES} >= set(
            self._STANDARD_SCOPES
        )
