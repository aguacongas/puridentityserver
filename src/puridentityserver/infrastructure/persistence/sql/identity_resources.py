"""Repository IdentityResources SQL — registre partagé (multi-instance / reprise).

Implémentation asynchrone bâtie sur SQLAlchemy 2.0, compatible SQLite,
PostgreSQL et MySQL (dialecte dérivé du DSN fourni).
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, String, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.identity_resource import IdentityResource

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


class IdentityResourceRow(PersistenceBase):
    """Table enregistrant les IdentityResources (scopes identité)."""

    __tablename__ = "identity_resources"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    user_claims: Mapped[list[str]] = mapped_column(JSON, default=list)
    show_in_discovery_document: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default=text("1")
    )


class SQLIdentityResourceRepository:
    """Persiste les IdentityResources dans une table relationnelle partagée.

    Grâce au stockage centralisé, plusieurs instances du serveur voient
    les mêmes resources (load balancing) et le registre survit aux
    redémarrages.
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``identity_resources`` si nécessaire puis migre le schéma."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(
                lambda sync: migrate_add_missing_columns(sync, IdentityResourceRow)
            )

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, resource: IdentityResource) -> None:
        """Insère ou remplace la resource identifiée par ``name``."""
        async with self._session_factory() as session:
            await session.merge(_to_row(resource))
            await session.commit()

    async def find_by_name(self, name: str) -> IdentityResource | None:
        """Retourne la resource identifiée par ``name``, ou ``None``."""
        async with self._session_factory() as session:
            row = await session.get(IdentityResourceRow, name)
        return _from_row(row) if row is not None else None

    async def find_all(self) -> list[IdentityResource]:
        """Retourne toutes les resources enregistrées."""
        async with self._session_factory() as session:
            rows = (await session.execute(select(IdentityResourceRow))).scalars().all()
        return [_from_row(row) for row in rows]

    async def delete(self, name: str) -> None:
        """Supprime la resource identifiée par ``name`` (idempotent)."""
        async with self._session_factory() as session:
            row = await session.get(IdentityResourceRow, name)
            if row is not None:
                await session.delete(row)
                await session.commit()


def _to_row(resource: IdentityResource) -> IdentityResourceRow:
    """Convertit une IdentityResource domaine en ligne de persistance."""
    return IdentityResourceRow(
        name=resource.name,
        display_name=resource.display_name,
        user_claims=sorted(resource.user_claims),
        show_in_discovery_document=resource.show_in_discovery_document,
    )


def _from_row(row: IdentityResourceRow) -> IdentityResource:
    """Reconstruit une IdentityResource domaine depuis une ligne persistée."""
    return IdentityResource(
        name=row.name,
        display_name=row.display_name,
        user_claims=frozenset(row.user_claims or ()),
        show_in_discovery_document=row.show_in_discovery_document,
    )
