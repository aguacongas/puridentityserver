"""Repository SQL des demandes CIBA (OIDC CIBA 1.0).

Seule l'empreinte SHA-256 de l'``auth_req_id`` y est stockée (jamais le
jeton en clair), comme pour les device codes. Implémentation asynchrone
bâtie sur SQLAlchemy 2.0, compatible SQLite, PostgreSQL et MySQL.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.authorization import (
    BackchannelAuthenticationRequest,
    BackchannelAuthenticationStatus,
    Scope,
)

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


class BackchannelAuthenticationRow(PersistenceBase):
    """Table stockant les demandes du backchannel authentication endpoint."""

    __tablename__ = "backchannel_authentications"

    auth_req_id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(128), index=True)
    subject: Mapped[str] = mapped_column(String(256), default="")
    scopes: Mapped[list[str]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    delivery_mode: Mapped[str] = mapped_column(String(16), default="poll")
    client_notification_token: Mapped[str] = mapped_column(String(1024), default="")
    client_notification_endpoint: Mapped[str] = mapped_column(String(512), default="")
    binding_message: Mapped[str] = mapped_column(String(512), default="")
    acr: Mapped[str] = mapped_column(String(256), default="")
    interval: Mapped[int] = mapped_column(Integer, default=5)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SQLBackchannelAuthenticationRepository:
    """Persiste les demandes CIBA dans une table relationnelle partagée.

    Grâce au stockage centralisé, l'approbation effectuée sur une instance
    est reconnue par les polls du client sur une autre instance.
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``backchannel_authentications`` si nécessaire puis migre le schéma."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(
                lambda sync: migrate_add_missing_columns(sync, BackchannelAuthenticationRow)
            )

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, request: BackchannelAuthenticationRequest) -> None:
        """Insère ou remplace la demande identifiée par ``auth_req_id_hash``."""
        async with self._session_factory() as session:
            await session.merge(_to_row(request))
            await session.commit()

    async def find_by_auth_req_id_hash(
        self, auth_req_id_hash: str
    ) -> BackchannelAuthenticationRequest | None:
        """Retourne la demande identifiée par ``auth_req_id_hash``, ou ``None``."""
        async with self._session_factory() as session:
            row = await session.get(BackchannelAuthenticationRow, auth_req_id_hash)
        return _from_row(row) if row is not None else None

    async def approve(self, auth_req_id_hash: str) -> None:
        """Marque la demande comme autorisée par l'utilisateur."""
        async with self._session_factory() as session:
            row = await session.get(BackchannelAuthenticationRow, auth_req_id_hash)
            if row is not None:
                row.status = BackchannelAuthenticationStatus.APPROVED.value
                await session.commit()

    async def deny(self, auth_req_id_hash: str) -> None:
        """Marque la demande comme refusée par l'utilisateur."""
        async with self._session_factory() as session:
            row = await session.get(BackchannelAuthenticationRow, auth_req_id_hash)
            if row is not None:
                row.status = BackchannelAuthenticationStatus.DENIED.value
                await session.commit()

    async def delete(self, auth_req_id_hash: str) -> None:
        """Supprime la demande identifiée par ``auth_req_id_hash``."""
        async with self._session_factory() as session:
            row = await session.get(BackchannelAuthenticationRow, auth_req_id_hash)
            if row is not None:
                await session.delete(row)
                await session.commit()


def _to_row(request: BackchannelAuthenticationRequest) -> BackchannelAuthenticationRow:
    """Convertit une demande domaine en ligne de persistance."""
    return BackchannelAuthenticationRow(
        auth_req_id_hash=request.auth_req_id_hash,
        client_id=request.client_id,
        subject=request.subject,
        scopes=sorted(scope.value for scope in request.scopes),
        status=request.status.value,
        delivery_mode=request.delivery_mode,
        client_notification_token=request.client_notification_token,
        client_notification_endpoint=request.client_notification_endpoint,
        binding_message=request.binding_message,
        acr=request.acr,
        interval=request.interval,
        last_polled_at=request.last_polled_at,
        expires_at=request.expires_at,
    )


def _from_row(row: BackchannelAuthenticationRow) -> BackchannelAuthenticationRequest:
    """Reconstruit une demande domaine depuis une ligne persistée."""
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    last_polled_at = row.last_polled_at
    if last_polled_at is not None and last_polled_at.tzinfo is None:
        last_polled_at = last_polled_at.replace(tzinfo=timezone.utc)
    return BackchannelAuthenticationRequest(
        auth_req_id_hash=row.auth_req_id_hash,
        client_id=row.client_id,
        subject=row.subject,
        scopes=frozenset(Scope(value) for value in row.scopes),
        status=BackchannelAuthenticationStatus(row.status),
        delivery_mode=row.delivery_mode,
        client_notification_token=row.client_notification_token,
        client_notification_endpoint=row.client_notification_endpoint,
        binding_message=row.binding_message,
        acr=row.acr,
        interval=row.interval,
        last_polled_at=last_polled_at,
        expires_at=expires_at,
    )
