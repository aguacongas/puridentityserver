"""Repository clients SQL — registre partagé (multi-instance / reprise).

Implémentation asynchrone bâtie sur SQLAlchemy 2.0, compatible SQLite,
PostgreSQL et MySQL (dialecte dérivé du DSN fourni).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from puridentityserver.domain.authorization import (
    Client,
    ClientType,
    Scope,
    TokenEndpointAuthMethod,
)

from .base import (
    PersistenceBase,
    async_dsn,
    migrate_add_missing_columns,
)


class ClientRow(PersistenceBase):
    """Table enregistrant les clients OAuth/OIDC du serveur."""

    __tablename__ = "clients"

    client_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    redirect_uris: Mapped[list[str]] = mapped_column(JSON)
    post_logout_redirect_uris: Mapped[list[str]] = mapped_column(
        JSON, default=list, server_default=text("'[]'")
    )
    web_origins: Mapped[list[str]] = mapped_column(JSON, default=list, server_default=text("'[]'"))
    scopes: Mapped[list[str]] = mapped_column(JSON)
    client_type: Mapped[str] = mapped_column(String(16))
    client_secret_hash: Mapped[str] = mapped_column(String(64), default="")
    client_secret_ciphertext: Mapped[str] = mapped_column(
        Text, default="", server_default=text("''")
    )
    token_endpoint_auth_method: Mapped[str | None] = mapped_column(String(32), nullable=True)
    jwks_uri: Mapped[str] = mapped_column(String(512), default="", server_default=text("''"))
    jwks: Mapped[list[dict[str, object]]] = mapped_column(
        JSON, default=list, server_default=text("'[]'")
    )
    tls_client_auth_subject_dn: Mapped[str] = mapped_column(
        String(1024), default="", server_default=text("''")
    )
    tls_client_certificate_hash: Mapped[str] = mapped_column(
        String(64), default="", server_default=text("''")
    )
    id_token_signed_response_alg: Mapped[str] = mapped_column(
        String(32), default="", server_default=text("''")
    )
    id_token_encrypted_response_alg: Mapped[str] = mapped_column(
        String(32), default="", server_default=text("''")
    )
    id_token_encrypted_response_enc: Mapped[str] = mapped_column(
        String(32), default="", server_default=text("''")
    )
    frontchannel_logout_uri: Mapped[str] = mapped_column(
        String(512), default="", server_default=text("''")
    )
    frontchannel_logout_session_required: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("0")
    )
    backchannel_logout_uri: Mapped[str] = mapped_column(
        String(512), default="", server_default=text("''")
    )
    backchannel_logout_session_required: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("0")
    )
    registration_access_token_hash: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    session_lifetime_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    access_token_lifetime_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    authorization_code_lifetime_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    refresh_token_lifetime_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    device_code_lifetime_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    device_code_interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    par_required: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"))
    require_consent: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"))


class SQLClientRepository:
    """Persiste les clients dans une table relationnelle partagée.

    Grâce au stockage centralisé, plusieurs instances du serveur voient
    les mêmes clients (load balancing) et le registre survit aux
    redémarrages.
    """

    def __init__(self, dsn: str) -> None:
        """Prépare le moteur asynchrone pour le DSN fourni."""
        self._engine: AsyncEngine = create_async_engine(async_dsn(dsn))
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialise(self) -> None:
        """Crée la table ``clients`` si elle n'existe pas encore puis migre le schéma."""
        async with self._engine.begin() as connection:
            await connection.run_sync(PersistenceBase.metadata.create_all)
            await connection.run_sync(lambda sync: migrate_add_missing_columns(sync, ClientRow))

    async def close(self) -> None:
        """Ferme proprement le moteur (libère les connexions)."""
        await self._engine.dispose()

    async def save(self, client: Client) -> None:
        """Insère ou remplace le client identifié par ``client_id``."""
        async with self._session_factory() as session:
            await session.merge(_to_row(client))
            await session.commit()

    async def find_by_id(self, client_id: str) -> Client | None:
        """Retourne le client identifié par ``client_id``, ou ``None``."""
        async with self._session_factory() as session:
            row = await session.get(ClientRow, client_id)
        return _from_row(row) if row is not None else None

    async def find_all(self) -> list[Client]:
        """Retourne tous les clients enregistrés."""
        async with self._session_factory() as session:
            rows = (await session.execute(select(ClientRow))).scalars().all()
        return [_from_row(row) for row in rows]

    async def delete(self, client_id: str) -> None:
        """Supprime le client identifié par ``client_id`` (idempotent)."""
        async with self._session_factory() as session:
            row = await session.get(ClientRow, client_id)
            if row is None:
                return
            await session.delete(row)
            await session.commit()

    async def is_cors_origin_allowed(self, origin: str) -> bool:
        """Vrai si un client actif autorise cette origine en CORS."""
        async with self._session_factory() as session:
            rows = (await session.execute(select(ClientRow))).scalars().all()
        return any(row.is_active and origin in _cors_origins(row) for row in rows)


def _to_row(client: Client) -> ClientRow:
    """Convertit un Client domaine en ligne de persistance."""
    return ClientRow(
        client_id=client.client_id,
        redirect_uris=sorted(client.redirect_uris),
        post_logout_redirect_uris=sorted(client.post_logout_redirect_uris),
        web_origins=sorted(client.web_origins),
        scopes=sorted(scope.value for scope in client.scopes),
        client_type=client.client_type.value,
        client_secret_hash=client.client_secret_hash,
        client_secret_ciphertext=client.client_secret_ciphertext,
        token_endpoint_auth_method=(
            client.token_endpoint_auth_method.value
            if client.token_endpoint_auth_method is not None
            else None
        ),
        jwks_uri=client.jwks_uri,
        jwks=list(client.jwks),
        tls_client_auth_subject_dn=client.tls_client_auth_subject_dn,
        tls_client_certificate_hash=client.tls_client_certificate_hash,
        id_token_signed_response_alg=client.id_token_signed_response_alg,
        id_token_encrypted_response_alg=client.id_token_encrypted_response_alg,
        id_token_encrypted_response_enc=client.id_token_encrypted_response_enc,
        frontchannel_logout_uri=client.frontchannel_logout_uri,
        frontchannel_logout_session_required=client.frontchannel_logout_session_required,
        backchannel_logout_uri=client.backchannel_logout_uri,
        backchannel_logout_session_required=client.backchannel_logout_session_required,
        registration_access_token_hash=client.registration_access_token_hash,
        created_at=client.created_at,
        is_active=client.is_active,
        session_lifetime_seconds=client.session_lifetime_seconds,
        access_token_lifetime_seconds=client.access_token_lifetime_seconds,
        authorization_code_lifetime_seconds=client.authorization_code_lifetime_seconds,
        refresh_token_lifetime_seconds=client.refresh_token_lifetime_seconds,
        device_code_lifetime_seconds=client.device_code_lifetime_seconds,
        device_code_interval_seconds=client.device_code_interval_seconds,
        par_required=client.par_required,
        require_consent=client.require_consent,
    )


def _cors_origins(row: ClientRow) -> frozenset[str]:
    """Origines CORS d'une ligne persistée (``redirect_uris`` + ``web_origins``).

    Délègue au domaine la normalisation (ports par défaut élidés,
    origines déduites des ``redirect_uris`` complétées des
    ``web_origins`` déclarées).
    """
    client = Client(
        client_id=row.client_id,
        redirect_uris=frozenset(row.redirect_uris),
        web_origins=frozenset(row.web_origins or ()),
    )
    return client.cors_allowed_origins()


def _from_row(row: ClientRow) -> Client:
    """Reconstruit un Client domaine depuis une ligne persistée."""
    created_at = row.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return Client(
        client_id=row.client_id,
        redirect_uris=frozenset(row.redirect_uris),
        post_logout_redirect_uris=frozenset(row.post_logout_redirect_uris or ()),
        web_origins=frozenset(row.web_origins or ()),
        scopes=frozenset(Scope(value) for value in row.scopes),
        client_type=ClientType(row.client_type),
        client_secret_hash=row.client_secret_hash,
        client_secret_ciphertext=row.client_secret_ciphertext or "",
        token_endpoint_auth_method=(
            TokenEndpointAuthMethod(row.token_endpoint_auth_method)
            if row.token_endpoint_auth_method
            else None
        ),
        jwks_uri=row.jwks_uri or "",
        jwks=tuple(dict(key) for key in (row.jwks or ())),
        tls_client_auth_subject_dn=row.tls_client_auth_subject_dn or "",
        tls_client_certificate_hash=row.tls_client_certificate_hash or "",
        id_token_signed_response_alg=row.id_token_signed_response_alg or "",
        id_token_encrypted_response_alg=row.id_token_encrypted_response_alg or "",
        id_token_encrypted_response_enc=row.id_token_encrypted_response_enc or "",
        frontchannel_logout_uri=row.frontchannel_logout_uri or "",
        frontchannel_logout_session_required=row.frontchannel_logout_session_required,
        backchannel_logout_uri=row.backchannel_logout_uri or "",
        backchannel_logout_session_required=row.backchannel_logout_session_required,
        registration_access_token_hash=row.registration_access_token_hash or "",
        created_at=created_at,
        is_active=row.is_active,
        session_lifetime_seconds=row.session_lifetime_seconds,
        access_token_lifetime_seconds=row.access_token_lifetime_seconds,
        authorization_code_lifetime_seconds=row.authorization_code_lifetime_seconds,
        refresh_token_lifetime_seconds=row.refresh_token_lifetime_seconds,
        device_code_lifetime_seconds=row.device_code_lifetime_seconds,
        device_code_interval_seconds=row.device_code_interval_seconds,
        par_required=row.par_required,
        require_consent=row.require_consent,
    )
