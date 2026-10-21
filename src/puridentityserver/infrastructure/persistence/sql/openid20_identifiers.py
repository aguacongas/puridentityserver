"""Store des associations OpenID 2.0 SQL — persistance partagée (multi-instance).

Le stockage centralisé permet à plusieurs instances du serveur de partager
la même association entre un compte OpenID Connect et son identifiant OpenID
2.0, et la fait survivre aux redémarrages.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, String, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.openid20 import OpenID20Identifier

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


def _utcnow() -> datetime:
    """Horodatage UTC courant pour la colonne ``created_at``."""
    return datetime.now(timezone.utc)


class OpenID20IdentifierRow(PersistenceBase):
    """Table stockant l'identifiant OpenID 2.0 associé à une `sub`."""

    __tablename__ = "openid20_identifiers"

    subject: Mapped[str] = mapped_column(String(255), primary_key=True)
    realm: Mapped[str] = mapped_column(String(255), primary_key=True, default="")
    identifier: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class SQLOpenID20IdentifierRepository:
    """Persiste les associations OpenID 2.0 dans une table relationnelle partagée."""

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``openid20_identifiers`` si nécessaire puis migre le schéma."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(
                lambda sync: migrate_add_missing_columns(sync, OpenID20IdentifierRow)
            )

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, identifier: OpenID20Identifier) -> None:
        """Enregistre l'association (remplace l'éventuelle association du même couple)."""
        async with self._session_factory() as session:
            await session.merge(
                OpenID20IdentifierRow(
                    subject=identifier.subject,
                    realm=identifier.realm,
                    identifier=identifier.identifier,
                    created_at=identifier.created_at,
                )
            )
            await session.commit()

    async def find(self, subject: str, realm: str = "") -> OpenID20Identifier | None:
        """Retourne l'association d'un compte pour le `realm` demandé."""
        async with self._session_factory() as session:
            row = await session.get(OpenID20IdentifierRow, (subject, realm))
        return _from_row(row) if row is not None else None

    async def find_by_identifier(self, identifier: str) -> OpenID20Identifier | None:
        """Retourne l'association portant l'identifiant OpenID 2.0 donné."""
        async with self._session_factory() as session:
            row = (
                (
                    await session.execute(
                        select(OpenID20IdentifierRow).where(
                            OpenID20IdentifierRow.identifier == identifier
                        )
                    )
                )
                .scalars()
                .first()
            )
        return _from_row(row) if row is not None else None

    async def find_all(self) -> list[OpenID20Identifier]:
        """Liste toutes les associations connues."""
        async with self._session_factory() as session:
            rows = (await session.execute(select(OpenID20IdentifierRow))).scalars().all()
            return [_from_row(row) for row in rows]


def _from_row(row: OpenID20IdentifierRow) -> OpenID20Identifier:
    """Convertit une ligne SQL en entité de domaine."""
    return OpenID20Identifier(
        subject=row.subject,
        identifier=row.identifier,
        realm=row.realm,
        created_at=row.created_at,
    )
