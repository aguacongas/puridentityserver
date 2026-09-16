"""Tests du user store — persistance des profils utilisateurs (memory + SQL)."""

import asyncio
from collections.abc import Awaitable
from pathlib import Path
from typing import TypeVar

import pytest

from thepuroidc.domain.userinfo import UserClaims
from thepuroidc.infrastructure.persistence.factory import build_user_repository
from thepuroidc.infrastructure.persistence.users_memory import InMemoryUserRepository
from thepuroidc.infrastructure.persistence.users_sql import SQLUserRepository
from thepuroidc.infrastructure.settings import Settings

_T = TypeVar("_T")


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def _alice() -> UserClaims:
    """Profil utilisateur de test (claims standards d'OIDC §5.4)."""
    return UserClaims(
        subject="alice",
        claims={
            "name": "Alice Martin",
            "email": "alice@example.com",
            "email_verified": True,
            "address": {"formatted": "12 rue de la Paix"},
        },
    )


def _bob() -> UserClaims:
    """Second profil utilisateur de test."""
    return UserClaims(subject="bob", claims={"name": "Bob Dupont"})


async def _make_repo(tmp_path: Path) -> SQLUserRepository:
    repo = SQLUserRepository(f"sqlite+aiosqlite:///{tmp_path / 'users.db'}")
    await repo.initialise()
    return repo


def _close(repo: SQLUserRepository) -> None:
    run(repo.close())


class TestInMemoryUserRepository:
    """Couvre le comportement du store mémoire (tests unitaires)."""

    def test_save_and_find_by_subject(self) -> None:
        repo = InMemoryUserRepository()
        run(repo.save(_alice()))

        assert run(repo.find_by_subject("alice")) == _alice()

    def test_save_overwrites_same_subject(self) -> None:
        repo = InMemoryUserRepository()
        run(repo.save(_alice()))
        run(repo.save(UserClaims(subject="alice", claims={"name": "Alice Renée"})))

        stored = run(repo.find_by_subject("alice"))
        assert stored is not None
        assert stored.claims["name"] == "Alice Renée"
        assert run(repo.find_all()) == [stored]

    def test_unknown_subject_returns_none(self) -> None:
        repo = InMemoryUserRepository()

        assert run(repo.find_by_subject("ghost")) is None

    def test_save_all_seeds_profiles(self) -> None:
        repo = InMemoryUserRepository()
        run(repo.save_all([_alice(), _bob()]))

        assert run(repo.find_by_subject("bob")) == _bob()
        assert len(run(repo.find_all())) == 2


class TestSQLUserRepository:
    """Couvre le comportement du store SQL (SQLite asynchrone)."""

    def test_save_find_and_survives_restart(self, tmp_path: Path) -> None:
        repo = run(_make_repo(tmp_path))
        run(repo.save(_alice()))
        _close(repo)

        repo2 = SQLUserRepository(f"sqlite+aiosqlite:///{tmp_path / 'users.db'}")
        try:
            stored = run(repo2.find_by_subject("alice"))
        finally:
            _close(repo2)

        assert stored == _alice()

    def test_find_all_returns_seeded_profiles(self, tmp_path: Path) -> None:
        repo = run(_make_repo(tmp_path))
        run(repo.save_all([_alice(), _bob()]))

        assert {user.subject for user in run(repo.find_all())} == {"alice", "bob"}
        _close(repo)

    def test_unknown_subject_returns_none(self, tmp_path: Path) -> None:
        repo = run(_make_repo(tmp_path))

        assert run(repo.find_by_subject("ghost")) is None
        _close(repo)

    def test_save_overwrites_same_subject(self, tmp_path: Path) -> None:
        repo = run(_make_repo(tmp_path))
        run(repo.save(_alice()))
        run(repo.save(UserClaims(subject="alice", claims={"name": "Alice Renée"})))
        run(repo.save_all([_bob()]))

        stored = run(repo.find_by_subject("alice"))
        assert stored is not None
        assert stored.claims["name"] == "Alice Renée"
        assert len(run(repo.find_all())) == 2
        _close(repo)

    def test_preserves_nested_claims(self, tmp_path: Path) -> None:
        repo = run(_make_repo(tmp_path))
        run(repo.save(_alice()))
        _close(repo)

        repo2 = SQLUserRepository(f"sqlite+aiosqlite:///{tmp_path / 'users.db'}")
        try:
            stored = run(repo2.find_by_subject("alice"))
        finally:
            _close(repo2)

        assert stored is not None
        assert stored.claims["address"] == {"formatted": "12 rue de la Paix"}


class TestFactory:
    """Couvre le choix du user store selon ``key_store_type``."""

    def test_builds_memory_repository(self) -> None:
        repository = build_user_repository(Settings(key_store_type="memory"))

        assert isinstance(repository, InMemoryUserRepository)

    def test_builds_sql_repository(self) -> None:
        repository = build_user_repository(
            Settings(key_store_type="sql", key_store_dsn="sqlite:///memory")
        )

        assert isinstance(repository, SQLUserRepository)

    def test_rejects_unknown_store_type(self) -> None:
        settings = Settings.model_construct(key_store_type="cassandra")

        with pytest.raises(ValueError, match="non supporté"):
            build_user_repository(settings)


class TestSettingsProfiles:
    """Couvre le chargement de ``THEPUROIDC_USERS_SEED`` (seed du user store)."""

    def test_reads_profiles_from_config_toml(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = Path(__file__).resolve().parents[1] / "config.toml"
        monkeypatch.setenv("THEPUROIDC_SETTINGS_FILE", str(config))
        settings = Settings(_env_file=None)

        assert settings.users_seed["alice"]["email"] == "alice.martin@example.com"
        assert settings.users_seed["bob"]["email"] == "bob.durand@example.com"
        assert settings.users_seed["alice"]["roles"] == ["admin", "member"]
        assert settings.users_seed["bob"]["roles"] == ["member"]
        assert "sample-pkce-client" not in settings.users_seed
        assert "web-app" not in settings.users_seed

    def test_reads_json_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "THEPUROIDC_USERS_SEED",
            '{"alice": {"name": "Alice", "roles": ["admin"]}}',
        )
        settings = Settings(_env_file=None)

        assert settings.users_seed == {"alice": {"name": "Alice", "roles": ["admin"]}}

    def test_defaults_to_empty_dict(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = tmp_path / "config.toml"
        config.write_text("[settings]\nissuer = 'http://127.0.0.1:8000'\n", encoding="utf-8")
        monkeypatch.setenv("THEPUROIDC_SETTINGS_FILE", str(config))

        settings = Settings(_env_file=None)

        assert settings.users_seed == {}

    def test_reads_identity_seed_from_config_toml(self, monkeypatch: pytest.MonkeyPatch) -> None:
        config = Path(__file__).resolve().parents[1] / "config.toml"
        monkeypatch.setenv("THEPUROIDC_SETTINGS_FILE", str(config))
        settings = Settings(_env_file=None)

        assert settings.identity_seed_users["alice"]["email"] == "alice@example.com"
        assert settings.identity_seed_users["bob"]["password"] == "password"
        assert settings.identity_jwt_lifetime_seconds == 3600
        # plus aucun secret statique de gestion de compte (jetons signés RS256 rotatifs)
        assert not hasattr(settings, "identity_reset_password_secret")
        assert not hasattr(settings, "identity_verification_secret")

    def test_reads_identity_seed_from_json_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            "THEPUROIDC_IDENTITY_SEED_USERS",
            '{"alice": {"email": "a@example.com", "password": "p"}}',
        )
        settings = Settings(_env_file=None)

        assert settings.identity_seed_users == {
            "alice": {"email": "a@example.com", "password": "p"}
        }

    def test_overrides_identity_settings_via_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THEPUROIDC_IDENTITY_JWT_LIFETIME_SECONDS", "7200")
        settings = Settings(_env_file=None)

        assert settings.identity_jwt_lifetime_seconds == 7200

    def test_defaults_identity_seed_to_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = tmp_path / "config.toml"
        config.write_text("[settings]\nissuer = 'http://127.0.0.1:8000'\n", encoding="utf-8")
        monkeypatch.setenv("THEPUROIDC_SETTINGS_FILE", str(config))

        settings = Settings(_env_file=None)

        assert settings.users_seed == {}

    def test_rejects_non_dict_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("THEPUROIDC_USERS_SEED", '[{"client_id": "x"}]')

        with pytest.raises(ValueError, match="objet JSON"):
            Settings(_env_file=None)
