"""Store anti-replay DPoP SQL — persistance partagée (multi-instance).

Les entrées partagées entre instances permettent de refuser un ``jti``
rejoué sur l'une d'elles et de survivre aux redémarrages. Seule
l'empreinte SHA-256 du ``jti`` y est stockée (jamais le ``jti`` en
clair).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import CursorResult, DateTime, String, delete
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.dpop import DPoPReplay

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


def _utcnow() -> datetime:
    """Horodatage UTC courant pour la colonne ``seen_at``."""
    return datetime.now(timezone.utc)


class DpopReplayRow(PersistenceBase):
    """Table stockant l'empreinte d'un ``jti`` DPoP déjà présenté (RFC 9449 §11)."""

    __tablename__ = "dpop_jtis"

    jti_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class SQLDpopReplayRepository:
    """Persiste le store anti-replay dans une table relationnelle partagée.

    Grâce au stockage centralisé, toutes les instances du serveur
    reconnaissent un ``jti`` déjà présenté sur l'une d'elles.
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``dpop_jtis`` si nécessaire puis migre le schéma."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(lambda sync: migrate_add_missing_columns(sync, DpopReplayRow))

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, replay: DPoPReplay) -> None:
        """Insère le ``jti`` présenté (insertion par ``jti_hash``)."""
        async with self._session_factory() as session:
            session.add(
                DpopReplayRow(
                    jti_hash=replay.jti_hash,
                    expires_at=replay.expires_at,
                    seen_at=replay.seen_at,
                )
            )
            await session.commit()

    async def is_used(self, jti_hash: str) -> bool:
        """Indique si l'empreinte figure déjà dans le store."""
        async with self._session_factory() as session:
            return await session.get(DpopReplayRow, jti_hash) is not None

    async def purge_expired(self) -> int:
        """Supprime les entrées expirées ; retourne le nombre supprimé."""
        now = datetime.now(timezone.utc)
        async with self._session_factory() as session:
            result = await session.execute(
                delete(DpopReplayRow).where(DpopReplayRow.expires_at <= now)
            )
            count = cast(CursorResult[Any], result).rowcount
            await session.commit()
        return int(count or 0)
