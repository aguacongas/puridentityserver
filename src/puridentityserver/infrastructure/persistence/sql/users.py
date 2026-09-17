"""Repository utilisateurs SQL — persistance partagée (multi-instance / reprise).

Implémentation asynchrone bâtie sur SQLAlchemy 2.0, compatible SQLite,
PostgreSQL et MySQL (dialecte dérivé du DSN fourni).
"""

from __future__ import annotations

from sqlalchemy import JSON, String, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.userinfo import UserClaims

from .base import PersistenceBase, async_dsn


class UserRow(PersistenceBase):
    """Table stockant un profil utilisateur (subject + claims, OIDC Core §5.3)."""

    __tablename__ = "users"

    subject: Mapped[str] = mapped_column(String(256), primary_key=True)
    claims: Mapped[dict[str, object]] = mapped_column(JSON)


class SQLUserRepository:
    """Persiste les profils utilisateurs dans une table relationnelle partagée.

    Grâce au stockage centralisé, plusieurs instances du serveur voient
    les mêmes profils (load balancing) et les données survivent aux
    redémarrages.
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``users`` si elle n'existe pas encore."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, user: UserClaims) -> None:
        """Insère ou remplace le profil identifié par ``subject``."""
        async with self._session_factory() as session:
            await session.merge(_to_row(user))
            await session.commit()

    async def save_all(self, users: list[UserClaims]) -> None:
        """Enregistre plusieurs profils en une seule opération (seed)."""
        async with self._session_factory() as session:
            for user in users:
                await session.merge(_to_row(user))
            await session.commit()

    async def find_by_subject(self, subject: str) -> UserClaims | None:
        """Retourne le profil identifié par ``subject``, ou ``None``."""
        async with self._session_factory() as session:
            row = await session.get(UserRow, subject)
        return _from_row(row) if row is not None else None

    async def find_all(self) -> list[UserClaims]:
        """Retourne tous les profils enregistrés."""
        async with self._session_factory() as session:
            rows = (await session.execute(select(UserRow))).scalars().all()
        return [_from_row(row) for row in rows]


def _to_row(user: UserClaims) -> UserRow:
    """Convertit un UserClaims domaine en ligne de persistance."""
    return UserRow(subject=user.subject, claims=dict(user.claims))


def _from_row(row: UserRow) -> UserClaims:
    """Reconstruit un UserClaims domaine depuis une ligne persistée."""
    return UserClaims(subject=row.subject, claims=dict(row.claims))
