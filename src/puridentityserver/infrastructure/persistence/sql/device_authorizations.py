"""Repository SQL des sessions Device Authorization Grant (RFC 8628).

Seule l'empreinte SHA-256 du ``device_code`` y est stockée (jamais le
jeton en clair), comme pour les refresh tokens. Implémentation asynchrone
bâtie sur SQLAlchemy 2.0, compatible SQLite, PostgreSQL et MySQL.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.authorization import (
    DeviceAuthorization,
    DeviceAuthorizationStatus,
    Scope,
)

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


class DeviceAuthorizationRow(PersistenceBase):
    """Table stockant les sessions d'appareil du device authorization grant."""

    __tablename__ = "device_authorizations"

    device_code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_code: Mapped[str] = mapped_column(String(16), unique=True)
    client_id: Mapped[str] = mapped_column(String(128), index=True)
    subject: Mapped[str] = mapped_column(String(256), default="")
    scopes: Mapped[list[str]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    interval: Mapped[int] = mapped_column(Integer, default=5)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SQLDeviceAuthorizationRepository:
    """Persiste les sessions d'appareil dans une table relationnelle partagée.

    Grâce au stockage centralisé, l'autorisation effectuée sur une instance
    est reconnue par les polls du client sur une autre instance.
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``device_authorizations`` si nécessaire puis migre le schéma."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(
                lambda sync: migrate_add_missing_columns(sync, DeviceAuthorizationRow)
            )

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, device_session: DeviceAuthorization) -> None:
        """Insère ou remplace la session identifiée par ``device_code_hash``."""
        async with self._session_factory() as session:
            await session.merge(_to_row(device_session))
            await session.commit()

    async def find_by_device_code_hash(self, device_code_hash: str) -> DeviceAuthorization | None:
        """Retourne la session identifiée par ``device_code_hash``, ou ``None``."""
        async with self._session_factory() as session:
            row = await session.get(DeviceAuthorizationRow, device_code_hash)
        return _from_row(row) if row is not None else None

    async def find_by_user_code(self, user_code: str) -> DeviceAuthorization | None:
        """Retourne la session identifiée par ``user_code`` (normalisé)."""
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(DeviceAuthorizationRow).where(
                        DeviceAuthorizationRow.user_code == user_code
                    )
                )
            ).scalar_one_or_none()
        if row is None:
            return None
        return _from_row(row)

    async def approve(self, device_code_hash: str, subject: str) -> None:
        """Marque la session comme autorisée et fixe le ``subject``."""
        async with self._session_factory() as session:
            row = await session.get(DeviceAuthorizationRow, device_code_hash)
            if row is not None:
                row.status = DeviceAuthorizationStatus.APPROVED.value
                row.subject = subject
                await session.commit()

    async def deny(self, device_code_hash: str) -> None:
        """Marque la session comme refusée par l'utilisateur."""
        async with self._session_factory() as session:
            row = await session.get(DeviceAuthorizationRow, device_code_hash)
            if row is not None:
                row.status = DeviceAuthorizationStatus.DENIED.value
                await session.commit()

    async def delete(self, device_code_hash: str) -> None:
        """Supprime la session identifiée par ``device_code_hash``."""
        async with self._session_factory() as session:
            row = await session.get(DeviceAuthorizationRow, device_code_hash)
            if row is not None:
                await session.delete(row)
                await session.commit()


def _to_row(session: DeviceAuthorization) -> DeviceAuthorizationRow:
    """Convertit une session domaine en ligne de persistance."""
    return DeviceAuthorizationRow(
        device_code_hash=session.device_code_hash,
        user_code=session.user_code,
        client_id=session.client_id,
        subject=session.subject,
        scopes=sorted(scope.value for scope in session.scopes),
        status=session.status.value,
        expires_at=session.expires_at,
        interval=session.interval,
        last_polled_at=session.last_polled_at,
    )


def _from_row(row: DeviceAuthorizationRow) -> DeviceAuthorization:
    """Reconstruit une session domaine depuis une ligne persistée."""
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    last_polled_at = row.last_polled_at
    if last_polled_at is not None and last_polled_at.tzinfo is None:
        last_polled_at = last_polled_at.replace(tzinfo=timezone.utc)
    return DeviceAuthorization(
        device_code_hash=row.device_code_hash,
        user_code=row.user_code,
        client_id=row.client_id,
        subject=row.subject,
        scopes=frozenset(Scope(value) for value in row.scopes),
        status=DeviceAuthorizationStatus(row.status),
        expires_at=expires_at,
        interval=row.interval,
        last_polled_at=last_polled_at,
    )
