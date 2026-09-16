"""Repository SQL des codes d'autorisation — persistance partagée.

Implémentation asynchrone bâtie sur SQLAlchemy 2.0, compatible SQLite,
PostgreSQL et MySQL. Permet aux instances d'un cluster de partager les
codes (load balancing) et de survivre aux redémarrages.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from thepuroidc.domain.authorization import AuthorizationCode, Scope
from thepuroidc.infrastructure.persistence.base import PersistenceBase, async_dsn


class AuthorizationCodeRow(PersistenceBase):
    """Table stockant un code d'autorisation à usage unique."""

    __tablename__ = "authorization_codes"

    code: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(128), index=True)
    redirect_uri: Mapped[str] = mapped_column(String(1024), default="")
    subject: Mapped[str] = mapped_column(String(256), default="")
    scopes: Mapped[list[str]] = mapped_column(JSON)
    code_challenge: Mapped[str] = mapped_column(String(512), default="")
    code_challenge_method: Mapped[str] = mapped_column(String(8), default="S256")
    nonce: Mapped[str] = mapped_column(String(256), default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_consumed: Mapped[bool] = mapped_column(Boolean, default=False)


class SQLAuthorizationCodeRepository:
    """Persiste les codes d'autorisation dans une table relationnelle partagée."""

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``authorization_codes`` si elle n'existe pas encore."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, code: AuthorizationCode) -> None:
        """Insère ou remplace le code identifié par ``code``."""
        async with self._session_factory() as session:
            await session.merge(_to_row(code))
            await session.commit()

    async def find_by_code(self, code: str) -> AuthorizationCode | None:
        """Retourne le code identifié par ``code``, ou ``None``."""
        async with self._session_factory() as session:
            row = await session.get(AuthorizationCodeRow, code)
        return _from_row(row) if row is not None else None

    async def consume(self, code: str) -> None:
        """Marque le code comme déjà consommé (usage unique)."""
        async with self._session_factory() as session:
            row = await session.get(AuthorizationCodeRow, code)
            if row is not None:
                row.is_consumed = True
                await session.commit()

    async def delete(self, code: str) -> None:
        """Supprime le code identifié par ``code``."""
        async with self._session_factory() as session:
            row = await session.get(AuthorizationCodeRow, code)
            if row is not None:
                await session.delete(row)
                await session.commit()


def _to_row(code: AuthorizationCode) -> AuthorizationCodeRow:
    """Convertit un AuthorizationCode domaine en ligne de persistance."""
    return AuthorizationCodeRow(
        code=code.code,
        client_id=code.client_id,
        redirect_uri=code.redirect_uri,
        subject=code.subject,
        scopes=sorted(scope.value for scope in code.scopes),
        code_challenge=code.code_challenge,
        code_challenge_method=code.code_challenge_method,
        nonce=code.nonce,
        expires_at=code.expires_at,
        is_consumed=code.is_consumed,
    )


def _from_row(row: AuthorizationCodeRow) -> AuthorizationCode:
    """Reconstruit un AuthorizationCode domaine depuis une ligne persistée."""
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return AuthorizationCode(
        code=row.code,
        client_id=row.client_id,
        redirect_uri=row.redirect_uri,
        subject=row.subject,
        scopes=frozenset(Scope(value) for value in row.scopes),
        code_challenge=row.code_challenge,
        code_challenge_method=row.code_challenge_method,
        nonce=row.nonce,
        expires_at=expires_at,
        is_consumed=row.is_consumed,
    )
