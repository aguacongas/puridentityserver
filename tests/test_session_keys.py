"""Tests de la stratégie de session RS256 et de l'isolation des familles de clés.

Le cookie de session est signé avec une clé rotative (``KeyUse.SESSION``)
distincte des clés de signature des tokens (``KeyUse.SIG``) : rotation,
période de grâce et séparation des familles sont couvertes ici au niveau
unitaire (``DefaultKeyManager`` + repository en mémoire).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from thepuroidc.application.jwks import JWKSetConfig, JWKSetUseCase
from thepuroidc.domain.jwks import JWTAlgorithm, KeyPair, KeyUse
from thepuroidc.identity.session_strategy import SessionJWTStrategy
from thepuroidc.infrastructure.jwks import DefaultKeyManager
from thepuroidc.infrastructure.persistence.memory import InMemoryKeyPairRepository

_USER_ID = uuid.UUID("10101010-1111-2222-3333-444455556666")


@dataclass(frozen=True, slots=True)
class _FakeUser:
    """Utilisateur minimal : le ``id`` est ce qui transite dans le ``sub``."""

    id: uuid.UUID = field(default_factory=lambda: _USER_ID)


class _FakeUserManager:
    """User manager minimal compatible avec ``read_token``."""

    def parse_id(self, value: str) -> uuid.UUID:
        return uuid.UUID(value)

    async def get(self, parsed_id: uuid.UUID) -> _FakeUser | None:
        return _FakeUser(id=parsed_id) if parsed_id == _USER_ID else None


def _session_manager() -> DefaultKeyManager:
    """Un gestionnaire de clés de session isolé, encrypté mémoire."""
    return DefaultKeyManager(InMemoryKeyPairRepository(), use=KeyUse.SESSION)


def _aged(key: KeyPair, *, created_at: datetime) -> KeyPair:
    """Recopie une clé en fixant ``created_at`` (pour simuler l'âge)."""
    return replace(key, created_at=created_at, is_active=True)


async def _sign(kid: str, manager: DefaultKeyManager) -> str:
    """Signe un JWT session arbitraire avec la clé ``kid`` (header identique)."""
    key = await manager.get_key_by_kid(kid)
    assert key is not None
    return jwt.encode(
        {"sub": str(_USER_ID), "aud": ["fastapi-users:auth"]},
        key.private_key_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


@pytest.mark.anyio
async def test_session_strategy_roundtrip() -> None:
    """write_token → read_token : cookie RS256 signé avec kid, session restituée."""
    strategy = SessionJWTStrategy(key_manager=_session_manager(), lifetime_seconds=3600)
    user = _FakeUser()

    token = await strategy.write_token(user)
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    assert header["kid"]

    restored = await strategy.read_token(token, _FakeUserManager())  # type: ignore[arg-type]
    assert restored is not None
    assert restored.id == _USER_ID


@pytest.mark.anyio
async def test_session_strategy_rejects_unknown_kid_and_bad_token() -> None:
    """read_token retourne None pour un kid inconnu ou un token illisible."""
    strategy = SessionJWTStrategy(key_manager=_session_manager(), lifetime_seconds=3600)
    manager = _FakeUserManager()

    assert await strategy.read_token(None, manager) is None  # type: ignore[arg-type]
    assert await strategy.read_token("not.a.jwt", manager) is None  # type: ignore[arg-type]

    other_manager = _session_manager()
    await other_manager.ensure_active_key(2048, JWTAlgorithm.RS256)
    foreign_keys = await other_manager.get_active_keys()
    foreign = await _sign(foreign_keys[0].kid, other_manager)
    assert await strategy.read_token(foreign, manager) is None  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_session_rotation_rotates_to_newest_and_forgets_expired() -> None:
    """Une clé dépassée rotation+grace est remplacée, l'ancien cookie est invalidé."""
    rotation, grace = 90, 7
    strategy = SessionJWTStrategy(
        key_manager=_session_manager(),
        lifetime_seconds=3600,
        rotation_days=rotation,
        grace_period_days=grace,
    )
    manager: DefaultKeyManager = strategy._key_manager  # type: ignore[attr-defined]

    old = _aged(
        await manager.generate_key_pair(2048, JWTAlgorithm.RS256),
        created_at=datetime.now(timezone.utc) - timedelta(days=rotation + grace + 1),
    )
    await manager._repository.update(old)  # type: ignore[attr-defined]
    stale_token = await _sign(old.kid, manager)

    token = await strategy.write_token(_FakeUser())
    assert jwt.get_unverified_header(token)["kid"] != old.kid
    assert await manager.get_key_by_kid(old.kid) is None  # supprimée hors grace

    assert await strategy.read_token(stale_token, _FakeUserManager()) is None  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_session_grace_period_still_validates_old_kid() -> None:
    """Une clé inactive mais encore en grâce continue de valider les sessions."""
    rotation, grace = 90, 7
    strategy = SessionJWTStrategy(
        key_manager=_session_manager(),
        lifetime_seconds=3600,
        rotation_days=rotation,
        grace_period_days=grace,
    )
    manager: DefaultKeyManager = strategy._key_manager  # type: ignore[attr-defined]

    old = _aged(
        await manager.generate_key_pair(2048, JWTAlgorithm.RS256),
        created_at=datetime.now(timezone.utc) - timedelta(days=rotation + 1),
    )
    await manager._repository.update(old)  # type: ignore[attr-defined]
    stale_token = await _sign(old.kid, manager)

    first = await strategy.write_token(_FakeUser())
    kid_after_rotation = jwt.get_unverified_header(first)["kid"]
    assert kid_after_rotation != old.kid
    assert (await manager.get_key_by_kid(old.kid)) is not None  # inactive mais pas supprimée

    restored = await strategy.read_token(stale_token, _FakeUserManager())  # type: ignore[arg-type]
    assert restored is not None and restored.id == _USER_ID

    beyond_grace = await manager.get_key_by_kid(old.kid)
    assert beyond_grace is not None
    await manager._repository.update(  # type: ignore[attr-defined]
        _aged(
            beyond_grace,
            created_at=datetime.now(timezone.utc) - timedelta(days=rotation + grace + 1),
        )
    )
    await strategy.write_token(_FakeUser())  # déclenche mark_expired → suppression
    assert await strategy.read_token(stale_token, _FakeUserManager()) is None  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_read_token_returns_none_for_bad_sub_and_missing_user() -> None:
    """read_token : sub non-UUID → None ; sub inconnu → None."""
    manager = _session_manager()
    await manager.ensure_active_key(2048, JWTAlgorithm.RS256)
    strategy = SessionJWTStrategy(key_manager=manager, lifetime_seconds=3600)
    key = (await manager.get_active_keys())[0]
    user_manager = _FakeUserManager()

    bad_sub = jwt.encode(
        {"sub": "not-a-uuid", "aud": ["fastapi-users:auth"]},
        key.private_key_pem,
        algorithm="RS256",
        headers={"kid": key.kid},
    )
    assert await strategy.read_token(bad_sub, user_manager) is None  # type: ignore[arg-type]

    unknown_id = uuid.uuid4()
    token_unknown = jwt.encode(
        {"sub": str(unknown_id), "aud": ["fastapi-users:auth"]},
        key.private_key_pem,
        algorithm="RS256",
        headers={"kid": key.kid},
    )
    assert await strategy.read_token(token_unknown, user_manager) is None  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_key_use_families_isolated_in_shared_repository() -> None:
    """Les managers sig/session partagent le repo mais ne se voient pas."""
    repository = InMemoryKeyPairRepository()
    sig_manager = DefaultKeyManager(repository)
    session_manager = DefaultKeyManager(repository, use=KeyUse.SESSION)

    await sig_manager.ensure_active_key(2048, JWTAlgorithm.RS256)
    await session_manager.ensure_active_key(2048, JWTAlgorithm.RS256)

    sig_keys = await sig_manager.get_active_keys()
    session_keys = await session_manager.get_active_keys()
    assert len(sig_keys) == 1 and len(session_keys) == 1
    assert sig_keys[0].kid != session_keys[0].kid
    assert all(key.use is KeyUse.SIG for key in sig_keys)
    assert all(key.use is KeyUse.SESSION for key in session_keys)

    # aucune fuite transversale : chaque manager ignore la clé de l'autre
    assert await sig_manager.get_key_by_kid(session_keys[0].kid) is None
    assert await session_manager.get_key_by_kid(sig_keys[0].kid) is None


@pytest.mark.anyio
async def test_jwks_publishes_only_sig_keys() -> None:
    """Le JWKS n'expose que les clés de tokens (jamais les clés de session)."""
    repository = InMemoryKeyPairRepository()
    sig_manager = DefaultKeyManager(repository)
    session_manager = DefaultKeyManager(repository, use=KeyUse.SESSION)

    jwks = JWKSetUseCase(
        JWKSetConfig(algorithms=(JWTAlgorithm.RS256,), key_size=2048),
        sig_manager,
    )
    await session_manager.ensure_active_key(2048, JWTAlgorithm.RS256)
    await jwks.initialise()

    published = await jwks.get_active_keys()
    assert len(published) == 1
    assert all(key.use is KeyUse.SIG for key in published)
