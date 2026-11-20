"""Tests de la persistance des clés de signature (repository SQL)."""

import asyncio
import sqlite3
from collections.abc import Awaitable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar

import pytest

from puridentityserver.application.jwks import JWKSetConfig, JWKSetUseCase
from puridentityserver.domain.jwks import JWTAlgorithm, KeyPair, KeyUse
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
from puridentityserver.interfaces.repositories.key_pair_repository import KeyPairConflictError

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
    repository = build_key_pair_repository(Settings(storage_type="memory"))

    assert isinstance(repository, InMemoryKeyPairRepository)


def test_factory_builds_sql_repository() -> None:
    repository = build_key_pair_repository(
        Settings(storage_type="sql", storage_dsn="sqlite:///memory")
    )

    assert isinstance(repository, SQLKeyPairRepository)


def test_factory_rejects_unknown_store_type() -> None:
    settings = Settings.model_construct(storage_type="cassandra")

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


def _credential_key(kid: str, *, slot: str | None) -> KeyPair:
    """Paire de clés minimale du périmètre credential (persistance seule)."""
    return KeyPair(algorithm=JWTAlgorithm.ES256, use=KeyUse.CREDENTIAL, kid=kid, slot=slot)


def _signing_key_with_slot(kid: str, slot: str) -> KeyPair:
    """Paire de clés de signature portant un slot homonyme (unicité par ``use``)."""
    return KeyPair(algorithm=JWTAlgorithm.RS256, use=KeyUse.SIG, kid=kid, slot=slot)


def _save_pair(repo: InMemoryKeyPairRepository | SQLKeyPairRepository, key_pair: KeyPair) -> None:
    """Écrit une paire de clés dans le store de façon synchrone.

    Sert de corps unique aux tests qui attendent une exception à la
    ``save`` : le ``with pytest.raises`` ne compte alors qu'une seule
    invocation possible (règle python:S5778).
    """
    asyncio.run(repo.save(key_pair))


def test_sql_repo_refuses_second_holder_of_family_slot(tmp_path: Path) -> None:
    """Le couple ``(use, slot)`` n'admet qu'une ligne : la course est tranchée."""
    repo = run(_make_repo(tmp_path))

    run(repo.save(_credential_key("first", slot="oid4vci")))
    rival = _credential_key("second", slot="oid4vci")

    with pytest.raises(KeyPairConflictError, match="oid4vci"):
        _save_pair(repo, rival)

    assert [key.kid for key in run(repo.find_all())] == ["first"]
    _close(repo)


def test_sql_repo_keeps_distinct_null_slots_for_drain_keys(tmp_path: Path) -> None:
    """Plusieurs clés drain coexistent : les ``slot`` NULL sont distincts."""
    repo = run(_make_repo(tmp_path))

    for kid in ("drain-a", "drain-b", "drain-c"):
        run(repo.save(_credential_key(kid, slot=None)))
    run(repo.save(_credential_key("current", slot="oid4vci")))

    assert len(run(repo.find_all())) == 4
    _close(repo)


def test_sql_repo_slot_uniqueness_is_scoped_to_use(tmp_path: Path) -> None:
    """Le même nom de slot sert une autre famille : l'unicité porte sur ``(use, slot)``."""
    repo = run(_make_repo(tmp_path))

    run(repo.save(_credential_key("credential", slot="shared")))
    run(repo.save(_signing_key_with_slot("signing", "shared")))

    assert len(run(repo.find_all())) == 2
    _close(repo)


_LEGACY_KEY_TABLE = """
CREATE TABLE key_pairs (
    kid VARCHAR(128) NOT NULL,
    algorithm VARCHAR(16) NOT NULL,
    use VARCHAR(16) NOT NULL,
    private_key_pem TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    is_active BOOLEAN NOT NULL,
    key_size INTEGER NOT NULL,
    PRIMARY KEY (kid)
)
"""


def test_sql_repo_migrates_legacy_table_without_slot(tmp_path: Path) -> None:
    """Une base antérieure à l'issue #310 reçoit la colonne ``slot`` et son index."""
    db_path = tmp_path / "keys.db"
    legacy = sqlite3.connect(db_path)
    legacy.execute(_LEGACY_KEY_TABLE)
    legacy.execute(
        "INSERT INTO key_pairs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("legacy", "ES256", "credential", "priv", "pub", "2026-01-01 00:00:00.000000", 1, 256),
    )
    legacy.commit()
    legacy.close()

    repo = run(_make_repo(tmp_path))

    stored = run(repo.find_all())
    assert [key.kid for key in stored] == ["legacy"]
    assert stored[0].use is KeyUse.CREDENTIAL
    assert stored[0].slot is None
    # La ligne héritée n'occupe aucun slot : le premier détenteur s'y installe,
    # le second est refusé (la traduction de ``IntegrityError`` fonctionne aussi
    # sur une table migrée).
    run(repo.save(_credential_key("current", slot="oid4vci")))
    rival = _credential_key("rival", slot="oid4vci")
    with pytest.raises(KeyPairConflictError, match="oid4vci"):
        _save_pair(repo, rival)
    _close(repo)

    # ``create_all`` ignore une table existante : l'index est créé par
    # ``initialise()`` malgré tout, et la colonne par la migration.
    checker = sqlite3.connect(db_path)
    columns = {row[1] for row in checker.execute("PRAGMA table_info(key_pairs)")}
    indexes = {
        row[0] for row in checker.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
    }
    checker.close()
    assert "slot" in columns
    assert "uq_key_pairs_family_slot" in indexes


def test_memory_repo_refuses_second_holder_of_family_slot() -> None:
    """Le store mémoire reproduit la contrainte ``(use, slot)`` sous son verrou."""
    repo = InMemoryKeyPairRepository()

    run(repo.save(_credential_key("first", slot="oid4vci")))
    # Ré-écriture de la même ligne (même ``kid``) : l'upsert reste idempotent.
    run(repo.save(_credential_key("first", slot="oid4vci")))
    rival = _credential_key("second", slot="oid4vci")
    with pytest.raises(KeyPairConflictError, match="oid4vci"):
        _save_pair(repo, rival)

    run(repo.save(_credential_key("drain", slot=None)))

    assert sorted(key.kid for key in run(repo.find_all())) == ["drain", "first"]


def test_memory_repo_slot_uniqueness_is_scoped_to_use() -> None:
    """Le même nom de slot sert une autre famille dans le store mémoire aussi."""
    repo = InMemoryKeyPairRepository()

    run(repo.save(_credential_key("credential", slot="shared")))
    run(repo.save(_signing_key_with_slot("signing", "shared")))

    assert len(run(repo.find_all())) == 2
