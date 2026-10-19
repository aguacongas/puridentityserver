"""Modèle utilisateur SQLAlchemy pour FastAPI Users.

La table ``user`` hérite du socle ``SQLAlchemyBaseUserTableUUID`` de
``fastapi-users-db-sqlalchemy`` : id UUID, email, hashed_password,
is_active, is_superuser, is_verified.

La colonne ``password_history`` ajoute l'empreinte des derniers mots de
passe (politique ``PasswordPolicy``, ``history_depth``) : la
réutilisation d'un ancien mot de passe est refusée lors d'une
réinitialisation. Le stockage mémoire (``InMemoryUserDatabase``) applique
le ``default`` des colonnes comme l'insertion SQL.
"""

from __future__ import annotations

from fastapi_users.db import SQLAlchemyBaseUserTableUUID
from sqlalchemy import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base SQLAlchemy pour le module d'identité."""

    pass


class User(SQLAlchemyBaseUserTableUUID, Base):
    """Utilisateur OIDC (identifiants, session, état vérification)."""

    #: Empreintes des derniers mots de passe (plus récent en tête), pour
    #: l'interdiction de réemploi configurée par ``PasswordPolicy``.
    password_history: Mapped[list[str]] = mapped_column(JSON, default=lambda: [])
