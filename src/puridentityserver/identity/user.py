"""Modèle utilisateur SQLAlchemy pour FastAPI Users.

La table ``user`` hérite du socle ``SQLAlchemyBaseUserTableUUID`` de
``fastapi_users-db-sqlalchemy`` : id UUID, email, hashed_password,
is_active, is_superuser, is_verified.
"""

from __future__ import annotations

from fastapi_users.db import SQLAlchemyBaseUserTableUUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base SQLAlchemy pour le module d'identité."""

    pass


class User(SQLAlchemyBaseUserTableUUID, Base):
    """Utilisateur OIDC (identifiants, session, état vérification)."""
