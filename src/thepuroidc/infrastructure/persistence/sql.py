"""Repository SQL — persistance partagée (multi-instance / reprise au redémarrage).

Implémentation asynchrone bâtie sur SQLAlchemy 2.0. Compatible SQLite,
PostgreSQL et MySQL ; le dialecte est dérivé du DSN fourni.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from thepuroidc.domain.jwks import JWTAlgorithm, KeyPair, KeyUse
from thepuroidc.infrastructure.persistence.base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


class KeyPairRow(PersistenceBase):
    """Table stockant une paire de clés (clé privée en PEM, RFC 7517)."""

    __tablename__ = "key_pairs"

    kid: Mapped[str] = mapped_column(String(128), primary_key=True)
    algorithm: Mapped[str] = mapped_column(String(16), index=True)
    use: Mapped[str] = mapped_column(String(16), default="sig")
    private_key_pem: Mapped[str] = mapped_column(Text)
    public_key_pem: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    key_size: Mapped[int] = mapped_column(Integer, default=4096)


class SQLKeyPairRepository:
    """Persiste les paires de clés dans une table relationnelle partagée.

    Grâce au stockage centralisé, plusieurs instances du serveur voient
    les mêmes clés (load balancing) et les clés survivent aux redémarrages.
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``key_pairs`` puis migre le schéma si nécessaire."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(lambda sync: migrate_add_missing_columns(sync, KeyPairRow))

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, key_pair: KeyPair) -> None:
        """Insère ou remplace la paire de clés identifiée par ``kid``."""
        async with self._session_factory() as session:
            await session.merge(_to_row(key_pair))
            await session.commit()

    async def find_all(self) -> list[KeyPair]:
        """Retourne toutes les paires de clés persistées."""
        async with self._session_factory() as session:
            rows = (await session.execute(select(KeyPairRow))).scalars().all()
        return [_from_row(row) for row in rows]

    async def update(self, key_pair: KeyPair) -> None:
        """Met à jour la paire de clés existante (par ``kid``)."""
        await self.save(key_pair)

    async def delete(self, kid: str) -> None:
        """Supprime la paire de clés identifiée par ``kid``."""
        async with self._session_factory() as session:
            key = await session.get(KeyPairRow, kid)
            if key is not None:
                await session.delete(key)
                await session.commit()


def _to_row(key_pair: KeyPair) -> KeyPairRow:
    """Convertit une KeyPair domaine en ligne de persistance."""
    return KeyPairRow(
        kid=key_pair.kid,
        algorithm=key_pair.algorithm.value,
        use=key_pair.use.value,
        private_key_pem=key_pair.private_key_pem,
        public_key_pem=key_pair.public_key_pem,
        created_at=key_pair.created_at,
        is_active=key_pair.is_active,
    )


def _from_row(row: KeyPairRow) -> KeyPair:
    """Reconstruit une KeyPair domaine depuis une ligne persistée."""
    created_at = row.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return KeyPair(
        algorithm=JWTAlgorithm(row.algorithm),
        kid=row.kid,
        private_key_pem=row.private_key_pem,
        public_key_pem=row.public_key_pem,
        created_at=created_at,
        is_active=row.is_active,
        use=KeyUse(row.use) if row.use else KeyUse.SIG,
    )
