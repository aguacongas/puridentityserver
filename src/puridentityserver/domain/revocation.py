"""Entités du périmètre de révocation de jeton (RFC 7009).

Le domaine ne contient que des entités pures, sans dépendance vers
FastAPI, SQLAlchemy ou PyJWT. Le port associé vit dans
``interfaces/repositories/`` et les implémentations dans l'infrastructure.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class RevokedToken:
    """Empreinte d'un jeton révoqué avant son expiration naturelle.

    Le jeton n'est jamais conservé en clair : seul son hash SHA-256 est
    stocké (``token_hash``), avec la date d'expiration du jeton
    (``expires_at``) afin de pouvoir purger la liste une fois l'expiration
    dépassée.
    """

    token_hash: str
    expires_at: datetime
    revoked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def token_hash(token: str) -> str:
    """Empreinte SHA-256 (hexadécimale) d'un jeton JWT.

    Seule cette forme est manipulée par le denylist : ni le jeton ni sa
    signature ne sont conservés en clair en persistance.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
