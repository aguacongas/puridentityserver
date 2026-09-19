"""Repository SQL des consentements — persistance partagée (OIDC §3.1.2.2).

Implémentation asynchrone bâtie sur SQLAlchemy 2.0, compatible SQLite,
PostgreSQL et MySQL. Une entrée par couple ``(subject, client_id)`` ;
les scopes accordés sont stockés en JSON et recomposés en domaine à la
lecture.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.authorization import Consent, Scope

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


class ConsentRow(PersistenceBase):
    """Table enregistrant les consentements utilisateur par client."""

    __tablename__ = "consents"

    subject: Mapped[str] = mapped_column(String(256), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scopes: Mapped[list[str]] = mapped_column(JSON)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SQLConsentRepository:
    """Persiste les consentements dans une table relationnelle partagée.

    Grâce au stockage centralisé, toutes les instances du serveur
    retrouvent les consentements déjà accordés (auto-approbation des
    demandes déjà couvertes, quel que soit le nœud sollicité).
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``consents`` si nécessaire puis migre le schéma."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(lambda sync: migrate_add_missing_columns(sync, ConsentRow))

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, consent: Consent) -> None:
        """Insère ou remplace le consentement du couple (``subject``, ``client_id``)."""
        async with self._session_factory() as session:
            await session.merge(_to_row(consent))
            await session.commit()

    async def find(self, subject: str, client_id: str) -> Consent | None:
        """Retourne le consentement de ``subject`` pour ``client_id``, ou ``None``."""
        async with self._session_factory() as session:
            row = await session.get(ConsentRow, (subject, client_id))
        return _from_row(row) if row is not None else None

    async def delete(self, subject: str, client_id: str) -> None:
        """Supprime le consentement du couple (``subject``, ``client_id``)."""
        async with self._session_factory() as session:
            row = await session.get(ConsentRow, (subject, client_id))
            if row is not None:
                await session.delete(row)
                await session.commit()


def _to_row(consent: Consent) -> ConsentRow:
    """Convertit un Consent domaine en ligne de persistance."""
    return ConsentRow(
        subject=consent.subject,
        client_id=consent.client_id,
        scopes=sorted(scope.value for scope in consent.scopes),
        granted_at=consent.granted_at,
    )


def _from_row(row: ConsentRow) -> Consent:
    """Reconstruit un Consent domaine depuis une ligne persistée."""
    granted_at = row.granted_at
    if granted_at.tzinfo is None:
        granted_at = granted_at.replace(tzinfo=timezone.utc)
    return Consent(
        subject=row.subject,
        client_id=row.client_id,
        scopes=frozenset(Scope(value) for value in row.scopes),
        granted_at=granted_at,
    )
