"""Repository SQL des requêtes d'autorisation poussées PAR (RFC 9126).

Implémentation asynchrone bâtie sur SQLAlchemy 2.0, compatible SQLite,
PostgreSQL et MySQL : le ``request_uri`` (usage unique, courte durée) est
partagé entre les instances d'un cluster.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.authorization import PushedAuthorization

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


class PushedAuthorizationRow(PersistenceBase):
    """Table stockant les requêtes d'autorisation poussées (RFC 9126)."""

    __tablename__ = "pushed_authorizations"

    request_uri: Mapped[str] = mapped_column(String(256), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(128), index=True)
    params: Mapped[dict[str, str]] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_consumed: Mapped[bool] = mapped_column(Boolean, default=False)


class SQLPushedAuthorizationRepository:
    """Persiste les requêtes poussées dans une table relationnelle partagée.

    Grâce au stockage centralisé, le ``request_uri`` poussé sur une instance
    est résolu par n'importe quelle autre instance du cluster.
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``pushed_authorizations`` si nécessaire puis migre le schéma."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(
                lambda sync: migrate_add_missing_columns(sync, PushedAuthorizationRow)
            )

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, pushed: PushedAuthorization) -> None:
        """Insère ou remplace la requête poussée identifiée par ``request_uri``."""
        async with self._session_factory() as session:
            await session.merge(_to_row(pushed))
            await session.commit()

    async def find_by_request_uri(self, request_uri: str) -> PushedAuthorization | None:
        """Retourne la requête poussée identifiée par ``request_uri``, ou ``None``."""
        async with self._session_factory() as session:
            row = await session.get(PushedAuthorizationRow, request_uri)
        return _from_row(row) if row is not None else None

    async def consume(self, request_uri: str) -> None:
        """Marque la requête poussée comme utilisée (usage unique)."""
        async with self._session_factory() as session:
            row = await session.get(PushedAuthorizationRow, request_uri)
            if row is not None:
                row.is_consumed = True
                await session.commit()

    async def delete(self, request_uri: str) -> None:
        """Supprime la requête poussée identifiée par ``request_uri``."""
        async with self._session_factory() as session:
            row = await session.get(PushedAuthorizationRow, request_uri)
            if row is not None:
                await session.delete(row)
                await session.commit()


def _to_row(pushed: PushedAuthorization) -> PushedAuthorizationRow:
    """Convertit une requête poussée domaine en ligne de persistance."""
    return PushedAuthorizationRow(
        request_uri=pushed.request_uri,
        client_id=pushed.client_id,
        params=pushed.params,
        expires_at=pushed.expires_at,
        is_consumed=pushed.is_consumed,
    )


def _from_row(row: PushedAuthorizationRow) -> PushedAuthorization:
    """Reconstruit une requête poussée domaine depuis une ligne persistée."""
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return PushedAuthorization(
        request_uri=row.request_uri,
        client_id=row.client_id,
        params=dict(row.params),
        expires_at=expires_at,
        is_consumed=row.is_consumed,
    )
