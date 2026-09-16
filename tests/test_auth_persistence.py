"""Tests de la persistance SQL des clients et des codes d'autorisation."""

import asyncio
import sqlite3
from collections.abc import Awaitable
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

import pytest

from thepuroidc.domain.authorization import AuthorizationCode, Client, ClientType, Scope
from thepuroidc.infrastructure.persistence.clients_memory import InMemoryClientRepository
from thepuroidc.infrastructure.persistence.clients_sql import ClientRow, SQLClientRepository
from thepuroidc.infrastructure.persistence.clients_sql import _from_row as _from_client_row
from thepuroidc.infrastructure.persistence.codes_memory import InMemoryAuthorizationCodeRepository
from thepuroidc.infrastructure.persistence.codes_sql import (
    AuthorizationCodeRow,
    SQLAuthorizationCodeRepository,
)
from thepuroidc.infrastructure.persistence.codes_sql import (
    _from_row as _from_code_row,
)
from thepuroidc.infrastructure.persistence.factory import (
    build_authorization_code_repository,
    build_client_repository,
)
from thepuroidc.infrastructure.settings import Settings

_CLIENT = Client(
    client_id="web-app",
    redirect_uris=frozenset({"https://app.example/callback"}),
    scopes=frozenset({Scope.OPENID, Scope.PROFILE}),
    client_type=ClientType.CONFIDENTIAL,
    client_secret_hash="a" * 64,
    session_lifetime_seconds=1800,
    access_token_lifetime_seconds=120,
    authorization_code_lifetime_seconds=30,
)

_T = TypeVar("_T")


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def _make_client_repo(tmp_path: Path) -> SQLClientRepository:
    repo = SQLClientRepository(f"sqlite+aiosqlite:///{tmp_path / 'clients.db'}")
    run(repo.initialise())
    return repo


def _make_code_repo(tmp_path: Path) -> SQLAuthorizationCodeRepository:
    repo = SQLAuthorizationCodeRepository(f"sqlite+aiosqlite:///{tmp_path / 'codes.db'}")
    run(repo.initialise())
    return repo


def test_sql_client_repo_round_trip(tmp_path: Path) -> None:
    repo = _make_client_repo(tmp_path)

    run(repo.save(_CLIENT))
    stored = run(repo.find_by_id("web-app"))

    assert stored == _CLIENT
    assert stored is not None
    assert stored.redirect_uris == frozenset({"https://app.example/callback"})
    assert stored.client_secret_hash == "a" * 64
    assert stored.session_lifetime_seconds == 1800
    assert stored.access_token_lifetime_seconds == 120
    assert stored.authorization_code_lifetime_seconds == 30
    run(repo.close())


def test_sql_client_repo_find_all_and_missing(tmp_path: Path) -> None:
    repo = _make_client_repo(tmp_path)
    run(repo.save(_CLIENT))

    assert run(repo.find_by_id("nope")) is None
    assert len(run(repo.find_all())) == 1
    run(repo.close())


def test_sql_client_repo_migrates_table_without_lifetime_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "clients.db"
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """
        CREATE TABLE clients (
            client_id VARCHAR(128) NOT NULL,
            redirect_uris JSON NOT NULL,
            scopes JSON NOT NULL,
            client_type VARCHAR(16) NOT NULL,
            client_secret_hash VARCHAR(64) NOT NULL,
            created_at DATETIME NOT NULL,
            is_active BOOLEAN NOT NULL,
            PRIMARY KEY (client_id)
        )
        """
    )
    connection.execute(
        """
        INSERT INTO clients
        (client_id, redirect_uris, scopes, client_type, client_secret_hash,
         created_at, is_active)
        VALUES ('legacy-app', '["https://app.example/callback"]', '["openid"]', 'public',
                '', '2026-01-01T00:00:00+00:00', 1)
        """
    )
    connection.commit()
    connection.close()

    repo = SQLClientRepository(f"sqlite+aiosqlite:///{db_path}")
    run(repo.initialise())

    stored = run(repo.find_by_id("legacy-app"))
    assert stored is not None
    assert stored.session_lifetime_seconds is None
    assert stored.access_token_lifetime_seconds is None
    assert stored.authorization_code_lifetime_seconds is None
    run(repo.close())


def test_sql_code_repo_round_trip_and_consume(tmp_path: Path) -> None:
    repo = _make_code_repo(tmp_path)
    code = AuthorizationCode(
        code="auth-code-1",
        client_id="web-app",
        redirect_uri="https://app.example/callback",
        scopes=frozenset({Scope.OPENID}),
        code_challenge="challenge-bytes",
        nonce="n-42",
    )

    run(repo.save(code))
    assert run(repo.find_by_code("auth-code-1")) == code
    assert run(repo.find_by_code("missing")) is None

    run(repo.consume("auth-code-1"))
    consumed = run(repo.find_by_code("auth-code-1"))
    assert consumed is not None
    assert consumed.is_consumed is True
    run(repo.close())


def test_sql_code_repo_delete(tmp_path: Path) -> None:
    repo = _make_code_repo(tmp_path)
    code = AuthorizationCode(code="to-delete", client_id="web-app")
    run(repo.save(code))

    run(repo.delete("to-delete"))
    run(repo.delete("missing"))
    assert run(repo.find_by_code("to-delete")) is None
    run(repo.close())


def test_sql_code_repo_migrates_table_created_before_subject(tmp_path: Path) -> None:
    db_path = tmp_path / "codes.db"
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """
        CREATE TABLE authorization_codes (
            code VARCHAR(128) NOT NULL,
            client_id VARCHAR(128) NOT NULL,
            redirect_uri VARCHAR(1024) NOT NULL,
            scopes JSON NOT NULL,
            code_challenge VARCHAR(512) NOT NULL,
            code_challenge_method VARCHAR(8) NOT NULL,
            nonce VARCHAR(256) NOT NULL,
            expires_at DATETIME NOT NULL,
            is_consumed BOOLEAN NOT NULL,
            PRIMARY KEY (code)
        )
        """
    )
    connection.execute(
        """
        INSERT INTO authorization_codes
        (code, client_id, redirect_uri, scopes, code_challenge,
         code_challenge_method, nonce, expires_at, is_consumed)
        VALUES ('legacy-code', 'web-app', 'https://app.example/callback', '["openid"]',
                'challenge-like', 'S256', 'n-legacy',
                '2026-01-01T00:00:00+00:00', 0)
        """
    )
    connection.commit()
    connection.close()

    repo = SQLAuthorizationCodeRepository(f"sqlite+aiosqlite:///{db_path}")
    run(repo.initialise())

    code = run(repo.find_by_code("legacy-code"))
    assert code is not None
    assert code.subject == ""
    assert run(repo.find_by_code("legacy-code")).is_consumed is False
    run(repo.save(AuthorizationCode(code="new-code", client_id="web-app", subject="alice-uuid")))
    assert run(repo.find_by_code("new-code")).subject == "alice-uuid"
    run(repo.close())


def test_client_factory_builds_memory() -> None:
    repo = build_client_repository(Settings(key_store_type="memory"))

    assert isinstance(repo, InMemoryClientRepository)


def test_client_factory_builds_sql() -> None:
    repo = build_client_repository(Settings(key_store_type="sql", key_store_dsn="sqlite:///memory"))

    assert isinstance(repo, SQLClientRepository)


def test_client_factory_rejects_unknown_store_type() -> None:
    settings = Settings.model_construct(key_store_type="cassandra")

    with pytest.raises(ValueError, match="non supporté"):
        build_client_repository(settings)


def test_code_factory_builds_memory() -> None:
    repo = build_authorization_code_repository(Settings(key_store_type="memory"))

    assert isinstance(repo, InMemoryAuthorizationCodeRepository)


def test_code_factory_builds_sql() -> None:
    repo = build_authorization_code_repository(
        Settings(key_store_type="sql", key_store_dsn="sqlite:///memory")
    )

    assert isinstance(repo, SQLAuthorizationCodeRepository)


def test_code_factory_rejects_unknown_store_type() -> None:
    settings = Settings.model_construct(key_store_type="cassandra")

    with pytest.raises(ValueError, match="non supporté"):
        build_authorization_code_repository(settings)


def test_memory_client_repo_find_all() -> None:
    repo = InMemoryClientRepository()
    run(repo.save(_CLIENT))

    assert run(repo.find_all()) == [_CLIENT]
    assert run(repo.find_all()) == [run(repo.find_by_id("web-app"))]


def test_memory_client_repo_save_is_idempotent() -> None:
    repo = InMemoryClientRepository()
    run(repo.save(_CLIENT))
    run(repo.save(_CLIENT))

    assert len(run(repo.find_all())) == 1


def test_memory_code_repo_consume_missing_code_is_noop() -> None:
    repo = InMemoryAuthorizationCodeRepository()

    run(repo.consume("absent-code"))

    assert run(repo.find_by_code("absent-code")) is None


def test_memory_code_repo_delete() -> None:
    repo = InMemoryAuthorizationCodeRepository()
    code = AuthorizationCode(code="to-delete", client_id="web-app")
    run(repo.save(code))

    run(repo.delete("to-delete"))
    run(repo.delete("missing"))

    assert run(repo.find_by_code("to-delete")) is None


def test_sql_client_row_preserves_aware_datetime() -> None:
    aware = datetime.now(timezone.utc)
    row = ClientRow(
        client_id="web-app",
        redirect_uris=["https://app.example/callback"],
        scopes=["openid"],
        client_type="confidential",
        client_secret_hash="a" * 64,
        created_at=aware,
        is_active=True,
    )

    client = _from_client_row(row)

    assert client.created_at.tzinfo is not None
    assert client.created_at.tzinfo == timezone.utc


def test_sql_code_row_preserves_aware_datetime() -> None:
    aware = datetime.now(timezone.utc)
    row = AuthorizationCodeRow(
        code="auth-code-1",
        client_id="web-app",
        redirect_uri="https://app.example/callback",
        scopes=["openid"],
        expires_at=aware,
        is_consumed=False,
    )

    code = _from_code_row(row)

    assert code.expires_at.tzinfo is not None
    assert code.expires_at.tzinfo == timezone.utc


def test_sql_code_repo_consume_missing_is_noop(tmp_path: Path) -> None:
    repo = _make_code_repo(tmp_path)

    run(repo.consume("absent-code"))

    assert run(repo.find_by_code("absent-code")) is None
    run(repo.close())
