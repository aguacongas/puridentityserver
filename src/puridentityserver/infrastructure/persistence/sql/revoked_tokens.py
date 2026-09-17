"""Repository SQL des jetons révoqués — persistance partagée (multi-instance).

Les entrées partagées entre instances permettent de maintenir le denylist
à jour dans un cluster et de survivre aux redémarrages. Seules les
empreintes SHA-256 des jetons y sont stockées (jamais les jetons en clair).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import CursorResult, DateTime, String, delete
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.revocation import RevokedToken

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


def _utcnow() -> datetime:
    """Horodatage UTC courant pour la colonne ``revoked_at``."""
    return datetime.now(timezone.utc)


class RevokedTokenRow(PersistenceBase):
    """Table stockant une empreinte de jeton révoqué (RFC 7009)."""

    __tablename__ = "revoked_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class SQLRevokedTokenRepository:
    """Persiste le denylist dans une table relationnelle partagée.

    Grâce au stockage centralisé, toutes les instances du serveur
    reconnaissent un jeton révoqué sur l'une d'elles.
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``revoked_tokens`` si nécessaire puis migre le schéma."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(
                lambda sync: migrate_add_missing_columns(sync, RevokedTokenRow)
            )

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, revoked: RevokedToken) -> None:
        """Insère ou remplace l'entrée identifiée par ``token_hash``."""
        async with self._session_factory() as session:
            await session.merge(_to_row(revoked))
            await session.commit()

    async def is_revoked(self, token_hash: str) -> bool:
        """Indique si l'empreinte figure au denylist."""
        async with self._session_factory() as session:
            return await session.get(RevokedTokenRow, token_hash) is not None

    async def purge_expired(self) -> int:
        """Supprime les entrées expirées ; retourne le nombre supprimé."""
        now = datetime.now(timezone.utc)
        async with self._session_factory() as session:
            result = await session.execute(
                delete(RevokedTokenRow).where(RevokedTokenRow.expires_at <= now)
            )
            count = cast(CursorResult[Any], result).rowcount
            await session.commit()
        return int(count or 0)


def _to_row(revoked: RevokedToken) -> RevokedTokenRow:
    """Convertit un RevokedToken domaine en ligne de persistance."""
    return RevokedTokenRow(
        token_hash=revoked.token_hash,
        expires_at=revoked.expires_at,
        revoked_at=revoked.revoked_at,
    )
