"""Fabrique des repositories persistance — choisit l'implémentation selon la config.

Le choix du backend (``memory`` ou ``sql``) est commun à l'ensemble des
stores (clés, clients, codes, utilisateurs, jetons révoqués) : il est dérivé de
``storage_type`` / ``storage_dsn``. Chaque fabrique retourne le port
correspondant, ce qui permet à la composition root d'injecter des
implémentations différentes sans toucher aux usecases.
"""

from __future__ import annotations

from puridentityserver.infrastructure.settings import Settings
from puridentityserver.interfaces.repositories.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from puridentityserver.interfaces.repositories.client_repository import ClientRepository
from puridentityserver.interfaces.repositories.key_pair_repository import KeyPairRepository
from puridentityserver.interfaces.repositories.revoked_token_repository import (
    RevokedTokenRepository,
)
from puridentityserver.interfaces.repositories.user_repository import UserRepository


def build_key_pair_repository(settings: Settings) -> KeyPairRepository:
    """Retourne le repository de clés correspondant à ``storage_type``."""
    if settings.storage_type == "memory":
        from puridentityserver.infrastructure.persistence.memory.keys import (
            InMemoryKeyPairRepository,
        )

        return InMemoryKeyPairRepository()
    if settings.storage_type == "sql":
        from puridentityserver.infrastructure.persistence.sql.keys import SQLKeyPairRepository

        return SQLKeyPairRepository(settings.storage_dsn)
    raise ValueError(f"Type de stockage non supporté : {settings.storage_type}")


def build_client_repository(settings: Settings) -> ClientRepository:
    """Retourne le repository de clients correspondant à ``storage_type``."""
    if settings.storage_type == "memory":
        from puridentityserver.infrastructure.persistence.memory.clients import (
            InMemoryClientRepository,
        )

        return InMemoryClientRepository()
    if settings.storage_type == "sql":
        from puridentityserver.infrastructure.persistence.sql.clients import SQLClientRepository

        return SQLClientRepository(settings.storage_dsn)
    raise ValueError(f"Type de stockage non supporté : {settings.storage_type}")


def build_authorization_code_repository(settings: Settings) -> AuthorizationCodeRepository:
    """Retourne le repository de codes correspondant à ``storage_type``."""
    if settings.storage_type == "memory":
        from puridentityserver.infrastructure.persistence.memory.codes import (
            InMemoryAuthorizationCodeRepository,
        )

        return InMemoryAuthorizationCodeRepository()
    if settings.storage_type == "sql":
        from puridentityserver.infrastructure.persistence.sql.codes import (
            SQLAuthorizationCodeRepository,
        )

        return SQLAuthorizationCodeRepository(settings.storage_dsn)
    raise ValueError(f"Type de stockage non supporté : {settings.storage_type}")


def build_user_repository(settings: Settings) -> UserRepository:
    """Retourne le repository utilisateurs correspondant à ``storage_type``."""
    if settings.storage_type == "memory":
        from puridentityserver.infrastructure.persistence.memory.users import (
            InMemoryUserRepository,
        )

        return InMemoryUserRepository()
    if settings.storage_type == "sql":
        from puridentityserver.infrastructure.persistence.sql.users import SQLUserRepository

        return SQLUserRepository(settings.storage_dsn)
    raise ValueError(f"Type de stockage non supporté : {settings.storage_type}")


def build_revoked_token_repository(settings: Settings) -> RevokedTokenRepository:
    """Retourne le denylist de jetons révoqués correspondant à ``storage_type``."""
    if settings.storage_type == "memory":
        from puridentityserver.infrastructure.persistence.memory.revoked_tokens import (
            InMemoryRevokedTokenRepository,
        )

        return InMemoryRevokedTokenRepository()
    if settings.storage_type == "sql":
        from puridentityserver.infrastructure.persistence.sql.revoked_tokens import (
            SQLRevokedTokenRepository,
        )

        return SQLRevokedTokenRepository(settings.storage_dsn)
    raise ValueError(f"Type de stockage non supporté : {settings.storage_type}")
