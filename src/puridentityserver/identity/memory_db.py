"""Adaptateur FastAPI Users en mémoire — comptes de connexion sans driver SQL.

Alternative au ``SQLAlchemyUserDatabase`` lorsque
``Settings.identity_storage_type = "memory"`` (défaut) : les comptes vivent
dans un dict éphémère du processus, aucun moteur ni connexion n'est créé et
le serveur démarre sans l'extra ``sql`` (``aiosqlite``).

La sémantique reproduit celle de l'adaptateur SQL de ``fastapi-users`` :

- ``get_by_email`` est insensible à la casse (équivalent de ``func.lower``) ;
- ``create`` reçoit un dict et assigne un ``id`` UUID (le ``default=uuid4``
  de la colonne SQLAlchemy ne s'applique qu'à l'insertion) ;
- ``get_by_oauth_account`` lève ``NotImplementedError``, comme l'adaptateur
  SQL sans table OAuth (aucun fournisseur OAuth n'est configuré).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi_users.db import BaseUserDatabase

from puridentityserver.identity.user import User


class InMemoryUserDatabase(BaseUserDatabase[User, uuid.UUID]):
    """Comptes utilisateurs d'un processus, stockés dans un dict par identifiant."""

    def __init__(self) -> None:
        """Initialise le conteneur vide (aucune connexion, aucun schéma)."""
        self._users: dict[uuid.UUID, User] = {}

    async def get(self, user_id: uuid.UUID) -> User | None:
        """Retourne le compte portant ``user_id``, ou ``None``."""
        return self._users.get(user_id)

    async def get_by_email(self, email: str) -> User | None:
        """Retourne le compte dont l'email correspond (insensible à la casse)."""
        target = email.lower()
        for user in self._users.values():
            if user.email.lower() == target:
                return user
        return None

    async def get_by_oauth_account(self, oauth: str, account_id: str) -> User | None:
        """Refuse la recherche par compte OAuth : aucune table OAuth n'existe."""
        raise NotImplementedError()

    async def create(self, create_dict: dict[str, Any]) -> User:
        """Crée un compte : dict fourni, puis défauts de colonnes (insertion SQL).

        Sans cette étape, ``is_active``/``is_superuser``/``is_verified``
        resteraient ``None`` : ces valeurs sont posées par les ``default`` des
        colonnes au moment de l'insertion, jamais par ``fastapi-users``.
        """
        user = User()
        for key, value in create_dict.items():
            setattr(user, key, value)
        user.id = uuid.uuid4()
        for column in User.__table__.columns:
            default = column.default
            if default is None or getattr(user, column.key, None) is not None:
                continue
            value = default.arg
            setattr(user, column.key, value() if callable(value) else value)
        self._users[user.id] = user
        return user

    async def update(self, user: User, update_dict: dict[str, Any]) -> User:
        """Applique ``update_dict`` au compte (déjà indexé, même ``id``)."""
        for key, value in update_dict.items():
            setattr(user, key, value)
        return user

    async def delete(self, user: User) -> None:
        """Retire le compte du dict (aucun effet si déjà absent)."""
        self._users.pop(user.id, None)
