"""Repository SQL des offres de credential — persistance partagée.

Implémentation asynchrone bâtie sur SQLAlchemy 2.0, compatible SQLite,
PostgreSQL et MySQL : les instances d'un cluster partagent les offres et
la référence ``credential_offer_uri`` reste déréférençable après un
redémarrage.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.credential_offer import CredentialOffer

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


class CredentialOfferRow(PersistenceBase):
    """Table stockant une offre de credential adressable par ``offer_id``."""

    __tablename__ = "credential_offers"

    offer_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    credential_configuration_ids: Mapped[list[str]] = mapped_column(JSON)
    subject: Mapped[str] = mapped_column(String(256), default="")
    pre_authorized_code: Mapped[str] = mapped_column(String(256), default="")
    client_id: Mapped[str] = mapped_column(String(128), default="")
    tx_code_required: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SQLCredentialOfferRepository:
    """Persiste les offres de credential dans une table relationnelle partagée."""

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``credential_offers`` si nécessaire puis migre le schéma."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(
                lambda sync: migrate_add_missing_columns(sync, CredentialOfferRow)
            )

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, offer: CredentialOffer) -> None:
        """Insère ou remplace l'offre identifiée par ``offer_id``."""
        async with self._session_factory() as session:
            await session.merge(_to_row(offer))
            await session.commit()

    async def find_by_id(self, offer_id: str) -> CredentialOffer | None:
        """Retourne l'offre identifiée par ``offer_id``, ou ``None``."""
        async with self._session_factory() as session:
            row = await session.get(CredentialOfferRow, offer_id)
        return _from_row(row) if row is not None else None

    async def delete(self, offer_id: str) -> None:
        """Supprime l'offre identifiée par ``offer_id``."""
        async with self._session_factory() as session:
            row = await session.get(CredentialOfferRow, offer_id)
            if row is not None:
                await session.delete(row)
                await session.commit()


def _to_row(offer: CredentialOffer) -> CredentialOfferRow:
    """Convertit une offre domaine en ligne de persistance."""
    return CredentialOfferRow(
        offer_id=offer.offer_id,
        credential_configuration_ids=list(offer.credential_configuration_ids),
        subject=offer.subject,
        pre_authorized_code=offer.pre_authorized_code,
        client_id=offer.client_id,
        tx_code_required=offer.tx_code_required,
        created_at=offer.created_at,
        expires_at=offer.expires_at,
    )


def _from_row(row: CredentialOfferRow) -> CredentialOffer:
    """Reconstruit une offre domaine depuis une ligne persistée."""
    created_at = row.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return CredentialOffer(
        offer_id=row.offer_id,
        credential_configuration_ids=tuple(row.credential_configuration_ids or ()),
        subject=row.subject or "",
        pre_authorized_code=row.pre_authorized_code or "",
        client_id=row.client_id or "",
        tx_code_required=bool(row.tx_code_required),
        created_at=created_at,
        expires_at=expires_at,
    )
