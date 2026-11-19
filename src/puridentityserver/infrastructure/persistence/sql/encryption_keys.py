"""Repository SQL — persistance partagée (multi-instance / reprise au redémarrage).

Implémentation asynchrone bâtie sur SQLAlchemy 2.0. Compatible SQLite,
PostgreSQL et MySQL ; le dialecte est dérivé du DSN fourni.
"""

from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)

#: Emplacement unique de la clé de chiffrement de l'émetteur OID4VCI.
_OID4VCI_SLOT = "oid4vci"


class EncryptionKeyRow(PersistenceBase):
    """Table stockant la clé privée de chiffrement de l'émetteur (PEM)."""

    __tablename__ = "encryption_keys"

    slot: Mapped[str] = mapped_column(String(32), primary_key=True)
    private_key_pem: Mapped[str] = mapped_column(Text)


class SQLEncryptionKeyRepository:
    """Persiste la clé de chiffrement dans une table relationnelle partagée.

    Grâce au stockage centralisé, plusieurs instances du serveur voient
    la même clé (load balancing) et la clé survit aux redémarrages : les
    requêtes chiffrées déjà engagées restent déchiffrables après un cold
    start.
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``encryption_keys`` puis migre le schéma si nécessaire."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(
                lambda sync: migrate_add_missing_columns(sync, EncryptionKeyRow)
            )

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def load(self) -> str | None:
        """Retourne le PEM de la clé persistée, ou ``None``."""
        async with self._session_factory() as session:
            row = await session.get(EncryptionKeyRow, _OID4VCI_SLOT)
        return row.private_key_pem if row is not None else None

    async def save_if_absent(self, private_key_pem: str) -> None:
        """Insère le PEM seulement si aucune clé n'est déjà stockée.

        La clé primaire ``slot`` rend l'insertion unique : la course de
        deux instances simultanées est tranchée par ``IntegrityError``,
        l'insertion perdante étant ignorée.
        """
        async with self._session_factory() as session:
            existing = await session.get(EncryptionKeyRow, _OID4VCI_SLOT)
            if existing is not None:
                return
            session.add(EncryptionKeyRow(slot=_OID4VCI_SLOT, private_key_pem=private_key_pem))
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
