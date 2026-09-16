"""Fabrique des repositories persistance — choisit l'implémentation selon la config.

Le choix du backend (``memory`` ou ``sql``) est commun à l'ensemble des
stores (clés, clients, codes, utilisateurs) : il est dérivé de
``key_store_type`` / ``key_store_dsn``. Chaque fabrique retourne le port
correspondant, ce qui permet à la composition root d'injecter des
implémentations différentes sans toucher aux usecases.
"""

from __future__ import annotations

from thepuroidc.infrastructure.settings import Settings
from thepuroidc.interfaces.repositories.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from thepuroidc.interfaces.repositories.client_repository import ClientRepository
from thepuroidc.interfaces.repositories.key_pair_repository import KeyPairRepository
from thepuroidc.interfaces.repositories.user_repository import UserRepository


def build_key_pair_repository(settings: Settings) -> KeyPairRepository:
    """Retourne le repository de clés correspondant à ``key_store_type``."""
    if settings.key_store_type == "memory":
        from thepuroidc.infrastructure.persistence.memory import InMemoryKeyPairRepository

        return InMemoryKeyPairRepository()
    if settings.key_store_type == "sql":
        from thepuroidc.infrastructure.persistence.sql import SQLKeyPairRepository

        return SQLKeyPairRepository(settings.key_store_dsn)
    raise ValueError(f"Type de stockage de clés non supporté : {settings.key_store_type}")


def build_client_repository(settings: Settings) -> ClientRepository:
    """Retourne le repository de clients correspondant à ``key_store_type``."""
    if settings.key_store_type == "memory":
        from thepuroidc.infrastructure.persistence.clients_memory import (
            InMemoryClientRepository,
        )

        return InMemoryClientRepository()
    if settings.key_store_type == "sql":
        from thepuroidc.infrastructure.persistence.clients_sql import SQLClientRepository

        return SQLClientRepository(settings.key_store_dsn)
    raise ValueError(f"Type de stockage de clients non supporté : {settings.key_store_type}")


def build_authorization_code_repository(settings: Settings) -> AuthorizationCodeRepository:
    """Retourne le repository de codes correspondant à ``key_store_type``."""
    if settings.key_store_type == "memory":
        from thepuroidc.infrastructure.persistence.codes_memory import (
            InMemoryAuthorizationCodeRepository,
        )

        return InMemoryAuthorizationCodeRepository()
    if settings.key_store_type == "sql":
        from thepuroidc.infrastructure.persistence.codes_sql import (
            SQLAuthorizationCodeRepository,
        )

        return SQLAuthorizationCodeRepository(settings.key_store_dsn)
    raise ValueError(f"Type de stockage de codes non supporté : {settings.key_store_type}")


def build_user_repository(settings: Settings) -> UserRepository:
    """Retourne le repository utilisateurs correspondant à ``key_store_type``."""
    if settings.key_store_type == "memory":
        from thepuroidc.infrastructure.persistence.users_memory import (
            InMemoryUserRepository,
        )

        return InMemoryUserRepository()
    if settings.key_store_type == "sql":
        from thepuroidc.infrastructure.persistence.users_sql import SQLUserRepository

        return SQLUserRepository(settings.key_store_dsn)
    raise ValueError(f"Type de stockage utilisateurs non supporté : {settings.key_store_type}")
