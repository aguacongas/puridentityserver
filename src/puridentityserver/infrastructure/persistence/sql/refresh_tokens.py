"""Repository SQL des refresh tokens — persistance partagée.

Seules les empreintes SHA-256 des jetons y sont stockées (jamais les
jetons en clair). Implémentation asynchrone bâtie sur SQLAlchemy 2.0,
compatible SQLite, PostgreSQL et MySQL.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.authorization import RefreshToken, Scope

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


class RefreshTokenRow(PersistenceBase):
    """Table stockant l'empreinte d'un refresh token rotatif."""

    __tablename__ = "refresh_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(128), index=True)
    subject: Mapped[str] = mapped_column(String(256), default="")
    scopes: Mapped[list[str]] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    is_consumed: Mapped[bool] = mapped_column(Boolean, default=False)


class SQLRefreshTokenRepository:
    """Persiste les refresh tokens dans une table relationnelle partagée.

    Grâce au stockage centralisé, toutes les instances du serveur
    reconnaissent la rotation d'un jeton (usage unique par jeton).
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``refresh_tokens`` si nécessaire puis migre le schéma."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(
                lambda sync: migrate_add_missing_columns(sync, RefreshTokenRow)
            )

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, token: RefreshToken) -> None:
        """Insère ou remplace le jeton identifié par ``token_hash``."""
        async with self._session_factory() as session:
            await session.merge(_to_row(token))
            await session.commit()

    async def find_by_token_hash(self, token_hash: str) -> RefreshToken | None:
        """Retourne le jeton identifié par ``token_hash``, ou ``None``."""
        async with self._session_factory() as session:
            row = await session.get(RefreshTokenRow, token_hash)
        return _from_row(row) if row is not None else None

    async def consume(self, token_hash: str) -> None:
        """Marque le jeton comme déjà utilisé (rotation)."""
        async with self._session_factory() as session:
            row = await session.get(RefreshTokenRow, token_hash)
            if row is not None:
                row.is_consumed = True
                await session.commit()

    async def delete(self, token_hash: str) -> None:
        """Supprime le jeton identifié par ``token_hash``."""
        async with self._session_factory() as session:
            row = await session.get(RefreshTokenRow, token_hash)
            if row is not None:
                await session.delete(row)
                await session.commit()


def _to_row(token: RefreshToken) -> RefreshTokenRow:
    """Convertit un RefreshToken domaine en ligne de persistance."""
    return RefreshTokenRow(
        token_hash=token.token_hash,
        client_id=token.client_id,
        subject=token.subject,
        scopes=sorted(scope.value for scope in token.scopes),
        expires_at=token.expires_at,
        is_consumed=token.is_consumed,
    )


def _from_row(row: RefreshTokenRow) -> RefreshToken:
    """Reconstruit un RefreshToken domaine depuis une ligne persistée."""
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return RefreshToken(
        token_hash=row.token_hash,
        client_id=row.client_id,
        subject=row.subject,
        scopes=frozenset(Scope(value) for value in row.scopes),
        expires_at=expires_at,
        is_consumed=row.is_consumed,
    )
