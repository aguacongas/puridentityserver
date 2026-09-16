"""Entités du périmètre UserInfo (OIDC Core 1.0 §5.3).

Le domaine ne contient ici que des entités pures, sans dépendance vers
FastAPI, SQLAlchemy ou PyJWT. Les ports associés vivent dans
``interfaces/`` et les implémentations dans l'infrastructure.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class UserClaims:
    """Claims d'un utilisateur (subject + attributs de profil).

    ``claims`` est un mapping claim-name → valeur, conforme aux claims
    standard d'OIDC Core 1.0 §5.4 (nom, email, adresse, téléphone…).
    """

    subject: str
    claims: Mapping[str, object] = field(default_factory=dict)
