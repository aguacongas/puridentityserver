"""Tests de la persistance des clés de signature (repository SQL)."""

import asyncio
from collections.abc import Awaitable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar

import pytest

from puridentityserver.application.jwks import JWKSetConfig, JWKSetUseCase
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.factory import build_key_pair_repository
from puridentityserver.infrastructure.persistence.memory.keys import InMemoryKeyPairRepository
from puridentityserver.infrastructure.persistence.sql.base import async_dsn
from puridentityserver.infrastructure.persistence.sql.keys import (
    KeyPairRow,
    SQLKeyPairRepository,
    _from_row,
)
from puridentityserver.infrastructure.settings import Settings

_KEY_SIZE = 2048

_T = TypeVar("_T")


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


async def _make_repo(tmp_path: Path) -> SQLKeyPairRepository:
    repo = SQLKeyPairRepository(f"sqlite+aiosqlite:///{tmp_path / 'keys.db'}")
    await repo.initialise()
    return repo


def test_sql_repo_delete_absent_key_is_noop(tmp_path: Path) -> None:
    repo = run(_make_repo(tmp_path))

    run(repo.delete("missing-kid"))

    assert run(repo.find_all()) == []


def test_async_dsn_rewrites_dialect() -> None:
    assert async_dsn("sqlite:///keys.db") == "sqlite+aiosqlite:///keys.db"
    assert async_dsn("postgresql://user@host/db") == "postgresql+asyncpg://user@host/db"
    assert async_dsn("sqlite+aiosqlite:///keys.db") == "sqlite+aiosqlite:///keys.db"


def test_factory_builds_memory_repository() -> None:
    repository = build_key_pair_repository(Settings(key_store_type="memory"))

    assert isinstance(repository, InMemoryKeyPairRepository)


def test_factory_builds_sql_repository() -> None:
    repository = build_key_pair_repository(
        Settings(key_store_type="sql", key_store_dsn="sqlite:///memory")
    )

    assert isinstance(repository, SQLKeyPairRepository)


def test_factory_rejects_unknown_store_type() -> None:
    settings = Settings.model_construct(key_store_type="cassandra")

    with pytest.raises(ValueError, match="non supporté"):
        build_key_pair_repository(settings)


def test_sql_repo_normalises_old_naive_datetime(tmp_path: Path) -> None:
    """Les dates stockées sans fuseau (anciennes versions) sont relues en UTC."""
    repo = run(_make_repo(tmp_path))
    manager = DefaultKeyManager(repo)
    key_pair = run(manager.generate_key_pair(_KEY_SIZE, JWTAlgorithm.RS256))
    naive = replace(key_pair, created_at=datetime(year=2026, month=1, day=1))
    run(repo.update(naive))

    stored = run(repo.find_all())[0]

    assert stored.created_at.tzinfo == timezone.utc


def _close(repo: SQLKeyPairRepository) -> None:
    run(repo.close())


def test_sql_repo_round_trip(tmp_path: Path) -> None:
    repo = run(_make_repo(tmp_path))
    manager = DefaultKeyManager(repo)
    key_pair = run(manager.generate_key_pair(_KEY_SIZE, JWTAlgorithm.ES256))

    stored = run(repo.find_all())

    assert len(stored) == 1
    assert stored[0].kid == key_pair.kid
    assert stored[0].algorithm is JWTAlgorithm.ES256
    assert stored[0].private_key_pem == key_pair.private_key_pem
    assert stored[0].public_key_pem == key_pair.public_key_pem
    assert stored[0].is_active is True


def test_sql_repo_first_active_key_per_algorithm(tmp_path: Path) -> None:
    repo = run(_make_repo(tmp_path))
    manager = DefaultKeyManager(repo)
    run(manager.ensure_active_key(_KEY_SIZE, JWTAlgorithm.RS256))
    run(manager.ensure_active_key(_KEY_SIZE, JWTAlgorithm.RS256))

    assert len(run(repo.find_all())) == 1


def test_sql_repo_survives_restart(tmp_path: Path) -> None:
    """Les clés relues par un nouvel accès (reprise après redémarrage)."""
    repo = run(_make_repo(tmp_path))
    manager = DefaultKeyManager(repo)
    key_pair = run(manager.generate_key_pair(_KEY_SIZE, JWTAlgorithm.RS256))
    _close(repo)

    repo2 = SQLKeyPairRepository(f"sqlite+aiosqlite:///{tmp_path / 'keys.db'}")
    manager2 = DefaultKeyManager(repo2)
    active = run(manager2.get_active_keys())

    assert len(active) == 1
    assert active[0].kid == key_pair.kid
    _close(repo2)


def test_sql_repo_rotation_persisted(tmp_path: Path) -> None:
    repo = run(_make_repo(tmp_path))
    manager = DefaultKeyManager(repo)

    async def _set_old_key() -> str:
        now = datetime.now(timezone.utc)
        key = await manager.generate_key_pair(_KEY_SIZE, JWTAlgorithm.RS256)
        old = replace(key, created_at=now - timedelta(days=100))
        await repo.update(old)
        return old.kid

    old_kid = run(_set_old_key())
    usecase = JWKSetUseCase(
        JWKSetConfig(key_size=_KEY_SIZE, algorithms=(JWTAlgorithm.RS256,)), manager
    )

    active = run(usecase.get_active_keys())

    assert len(active) == 1
    assert active[0].kid != old_kid
    assert len(run(repo.find_all())) == 1
    assert run(repo.find_all())[0].is_active is True
    _close(repo)


def test_sql_key_pair_row_preserves_aware_datetime() -> None:
    aware = datetime.now(timezone.utc)
    row = KeyPairRow(
        kid="key-1",
        algorithm="RS256",
        private_key_pem="-----BEGIN PRIVATE KEY-----",
        public_key_pem="-----BEGIN PUBLIC KEY-----",
        created_at=aware,
        is_active=True,
    )

    key_pair = _from_row(row)

    assert key_pair.created_at.tzinfo is not None
    assert key_pair.created_at.tzinfo == timezone.utc
