"""Tests du backend identité mémoire — comptes de connexion sans driver SQL.

Couvre ``Settings.identity_storage_type`` (défaut ``memory``),
``InMemoryUserDatabase`` et le démarrage d'une application **sans** création
de moteur SQLAlchemy : en mode mémoire aucun dialecte n'est importé, ce qui
permet de démarrer avec un simple ``uv sync`` (sans l'extra ``sql``).
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.identity.memory_db import InMemoryUserDatabase
from puridentityserver.identity.user import User
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_ISSUER = "https://id.example"

_CLIENT_JSON = {
    "client_id": "web-app",
    "client_secret": "super-secret",
    "redirect_uris": ["https://app.example/callback"],
    "scopes": "openid profile",
    "client_type": "confidential",
}

_SEED = {
    "alice": {"email": "alice@example.com", "password": "password"},
    "bob": {"email": "bob@example.com", "password": "password"},
}


def _app(**settings: object) -> FastAPI:
    """Construit une application de test avec les réglages fournis."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256",),
            clients_seed=(_CLIENT_JSON,),
            identity_seed_users=_SEED,
            **settings,
        )
    )


async def _create(db: InMemoryUserDatabase, email: str) -> User:
    """Crée un compte minimal via l'adaptateur (dict ``create`` de fastapi-users)."""
    return await db.create(
        {
            "email": email,
            "hashed_password": "hash-de-test",
            "is_active": True,
            "is_superuser": False,
            "is_verified": False,
        }
    )


def _use_memory_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isole les globals du module identity en mode mémoire (restaurés après le test)."""
    from puridentityserver.identity import config as mod

    monkeypatch.setattr(mod, "_storage_type", "memory")
    monkeypatch.setattr(mod, "_memory_users", None)
    monkeypatch.setattr(mod, "_engine", None)


class TestSettingsIdentityStorageType:
    """Couvre le réglage ``identity_storage_type`` (défaut, env, config)."""

    def test_defaults_to_memory(self) -> None:
        """Le backend identité par défaut est mémoire (aucun driver SQL)."""
        assert Settings(_env_file=None).identity_storage_type == "memory"

    def test_reads_sql_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`PURIDENTITYSERVER_IDENTITY_STORAGE_TYPE` bascule sur le mode sql."""
        monkeypatch.setenv("PURIDENTITYSERVER_IDENTITY_STORAGE_TYPE", "sql")

        assert Settings(_env_file=None).identity_storage_type == "sql"

    def test_reads_memory_from_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Le mode mémoire peut être réaffirmé explicitement par l'environnement."""
        monkeypatch.setenv("PURIDENTITYSERVER_IDENTITY_STORAGE_TYPE", "memory")

        assert Settings(_env_file=None).identity_storage_type == "memory"


class TestInMemoryUserDatabase:
    """Couvre l'adaptateur ``fastapi-users`` en mémoire (sémantique SQL incluse)."""

    @pytest.mark.anyio
    async def test_create_get_update_delete_roundtrip(self) -> None:
        """Create pose un id UUID ; get/update/delete opèrent sur le dict."""
        db = InMemoryUserDatabase()

        created = await _create(db, "alice@example.com")
        assert isinstance(created.id, uuid.UUID)
        assert await db.get(created.id) is created
        assert await db.get(uuid.uuid4()) is None

        updated = await db.update(created, {"is_verified": True})
        assert updated is created
        assert created.is_verified

        await db.delete(created)
        assert await db.get(created.id) is None
        await db.delete(created)  # retrait idempotent

    @pytest.mark.anyio
    async def test_get_by_email_is_case_insensitive(self) -> None:
        """La recherche d'email ignore la casse, comme ``func.lower`` côté SQL."""
        db = InMemoryUserDatabase()
        await _create(db, "Alice@Example.com")

        assert await db.get_by_email("alice@example.com") is not None
        assert await db.get_by_email("ALICE@EXAMPLE.COM") is not None
        assert await db.get_by_email("bob@example.com") is None

    @pytest.mark.anyio
    async def test_get_by_oauth_account_not_implemented(self) -> None:
        """Sans table OAuth, la recherche lève NotImplementedError (comme le SQL)."""
        db = InMemoryUserDatabase()

        with pytest.raises(NotImplementedError):
            await db.get_by_oauth_account("github", "42")


class TestIdentityBackendInitialisation:
    """Couvre ``init_users_db`` / ``apply_schema`` dans les deux modes."""

    @pytest.mark.anyio
    async def test_apply_schema_memory_creates_adapter_without_engine(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Le mode mémoire crée l'adaptateur sans moteur ni table."""
        from puridentityserver.identity import config as mod
        from puridentityserver.identity.config import apply_schema

        _use_memory_backend(monkeypatch)
        await apply_schema("memory")

        assert mod._storage_type == "memory"
        assert mod._memory_users is not None
        assert mod._engine is None

    @pytest.mark.anyio
    async def test_init_users_db_rejects_unknown_storage_type(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Une valeur inconnue de ``identity_storage_type`` lève ValueError."""
        from puridentityserver.identity import config as mod

        _use_memory_backend(monkeypatch)
        with pytest.raises(ValueError, match="non supporté"):
            mod.init_users_db("redis")
        assert mod._storage_type == "memory"

    @pytest.mark.anyio
    async def test_seed_users_is_idempotent_in_memory(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """seed_users crée puis recharge les comptes dans le dict mémoire."""
        from puridentityserver.identity import config as mod
        from puridentityserver.identity.config import apply_schema, seed_users

        _use_memory_backend(monkeypatch)
        await apply_schema("memory")

        users = await seed_users(_SEED)
        again = await seed_users(_SEED)

        assert set(users) == {"alice", "bob"}
        assert {subject: user.id for subject, user in again.items()} == {
            subject: user.id for subject, user in users.items()
        }
        assert mod._engine is None
        memory_db = mod._memory_users
        assert memory_db is not None
        assert await memory_db.get_by_email("alice@example.com") is users["alice"]


class TestApplicationInMemoryMode:
    """Couvre le démarrage d'une application sans driver SQL (issue #95)."""

    def test_app_defaults_to_memory_backend_without_engine(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """L'application démarre sans moteur et authentifie via le dict mémoire."""
        from puridentityserver.identity import config as mod

        monkeypatch.setattr(mod, "_storage_type", "sql")
        monkeypatch.setattr(mod, "_engine", None)
        monkeypatch.setattr(mod, "_session_factory", None)
        monkeypatch.setattr(mod, "_memory_users", None)

        with TestClient(_app()) as client:
            assert mod._storage_type == "memory"
            assert mod._engine is None
            assert mod._memory_users is not None

            login = client.post(
                "/login",
                data={"username": "alice@example.com", "password": "password", "next": "/"},
                follow_redirects=False,
            )

        assert login.status_code == 302
        assert "fastapiusersauth" in login.headers.get("set-cookie", "")

    def test_app_identity_backend_follows_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`identity_storage_type = "sql"` restaure le moteur SQLite en mémoire."""
        from puridentityserver.identity import config as mod

        monkeypatch.setattr(mod, "_storage_type", "memory")
        monkeypatch.setattr(mod, "_engine", None)
        monkeypatch.setattr(mod, "_session_factory", None)

        with TestClient(_app(identity_storage_type="sql")) as client:
            assert mod._storage_type == "sql"
            assert mod._engine is not None

            login = client.post(
                "/login",
                data={"username": "alice@example.com", "password": "password", "next": "/"},
                follow_redirects=False,
            )

        assert login.status_code == 302

    def test_register_and_login_through_fastapi_users(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """POST /auth/register remplit le dict mémoire, la connexion utilise le même compte."""
        from puridentityserver.identity import config as mod

        monkeypatch.setattr(mod, "_storage_type", "sql")
        monkeypatch.setattr(mod, "_engine", None)
        monkeypatch.setattr(mod, "_session_factory", None)
        monkeypatch.setattr(mod, "_memory_users", None)

        with TestClient(_app()) as client:
            register = client.post(
                "/auth/register",
                json={"email": "nouveau@example.com", "password": "mot-de-passe-42"},
            )
            assert register.status_code == 201
            assert register.json()["email"] == "nouveau@example.com"

            duplicate = client.post(
                "/auth/register",
                json={"email": "NOUVEAU@example.com", "password": "mot-de-passe-42"},
            )
            assert duplicate.status_code == 400

            login = client.post(
                "/login",
                data={
                    "username": "nouveau@example.com",
                    "password": "mot-de-passe-42",
                    "next": "/",
                },
                follow_redirects=False,
            )

            assert mod._storage_type == "memory"
            assert mod._engine is None

        assert login.status_code == 302
        assert "fastapiusersauth" in login.headers.get("set-cookie", "")
