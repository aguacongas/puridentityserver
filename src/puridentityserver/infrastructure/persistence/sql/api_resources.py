"""Repository ApiResources SQL — registre partagé (multi-instance / reprise).

Implémentation asynchrone bâtie sur SQLAlchemy 2.0, compatible SQLite,
PostgreSQL et MySQL (dialecte dérivé du DSN fourni).
"""

from __future__ import annotations

from sqlalchemy import JSON, String, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.api_resource import ApiResource

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


class ApiResourceRow(PersistenceBase):
    """Table enregistrant les ApiResources (ressources protégées)."""

    __tablename__ = "api_resources"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list, server_default=text("'[]'"))
    allowed_access_token_signing_algos: Mapped[list[str]] = mapped_column(
        JSON, default=list, server_default=text("'[]'")
    )


class SQLApiResourceRepository:
    """Persiste les ApiResources dans une table relationnelle partagée.

    Grâce au stockage centralisé, plusieurs instances du serveur voient
    les mêmes resources (load balancing) et le registre survit aux
    redémarrages.
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``api_resources`` si nécessaire puis migre le schéma."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(
                lambda sync: migrate_add_missing_columns(sync, ApiResourceRow)
            )

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, resource: ApiResource) -> None:
        """Insère ou remplace la resource identifiée par ``name``."""
        async with self._session_factory() as session:
            await session.merge(_to_row(resource))
            await session.commit()

    async def find_by_name(self, name: str) -> ApiResource | None:
        """Retourne la resource identifiée par ``name``, ou ``None``."""
        async with self._session_factory() as session:
            row = await session.get(ApiResourceRow, name)
        return _from_row(row) if row is not None else None

    async def find_all(self) -> list[ApiResource]:
        """Retourne toutes les resources enregistrées."""
        async with self._session_factory() as session:
            rows = (await session.execute(select(ApiResourceRow))).scalars().all()
        return [_from_row(row) for row in rows]

    async def delete(self, name: str) -> None:
        """Supprime la resource identifiée par ``name`` (idempotent)."""
        async with self._session_factory() as session:
            row = await session.get(ApiResourceRow, name)
            if row is not None:
                await session.delete(row)
                await session.commit()


def _to_row(resource: ApiResource) -> ApiResourceRow:
    """Convertit une ApiResource domaine en ligne de persistance."""
    return ApiResourceRow(
        name=resource.name,
        display_name=resource.display_name,
        scopes=sorted(resource.scopes),
        allowed_access_token_signing_algos=sorted(resource.allowed_access_token_signing_algos),
    )


def _from_row(row: ApiResourceRow) -> ApiResource:
    """Reconstruit une ApiResource domaine depuis une ligne persistée."""
    return ApiResource(
        name=row.name,
        display_name=row.display_name,
        scopes=frozenset(row.scopes or ()),
        allowed_access_token_signing_algos=tuple(row.allowed_access_token_signing_algos or ()),
    )
