"""Entités du périmètre d'autorisation (RFC 6749 — OAuth 2.0, RFC 7636 — PKCE).

Le domaine ne contient ici que des entités pures, sans dépendance vers
FastAPI, SQLAlchemy ou PyJWT. Les ports associés vivent dans
``interfaces/`` et les implémentations dans l'infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4


class Scope(str, Enum):
    """Scopes OpenID Connect standard (OIDC Core 1.0 §5.4)."""

    OPENID = "openid"
    PROFILE = "profile"
    EMAIL = "email"
    ADDRESS = "address"
    PHONE = "phone"
    OFFLINE_ACCESS = "offline_access"

    @classmethod
    def from_space_separated(cls, value: str | None) -> frozenset[Scope]:
        """Décode une chaîne de scopes séparés par des espaces (RFC 6749 §3.3)."""
        if not value:
            return frozenset()
        return frozenset(Scope(token) for token in value.split() if token)


class ResponseMode(str, Enum):
    """Mode de réponse de l'endpoint d'autorisation (OIDC Core 1.0 §3.1.2.1)."""

    QUERY = "query"
    FRAGMENT = "fragment"


class ClientType(str, Enum):
    """Type de client OAuth 2.0 (RFC 6749 §2.1)."""

    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


@dataclass(frozen=True, slots=True)
class Client:
    """Client OAuth 2.0 / OIDC enregistré auprès du fournisseur.

    ``client_secret_hash`` conserve l'empreinte SHA-256 du secret (jamais
    le secret en clair). Les ``redirect_uris`` et ``scopes`` sont limités
    à ce que le serveur accepte pour ce client.
    """

    client_id: str
    redirect_uris: frozenset[str] = frozenset()
    scopes: frozenset[Scope] = frozenset((Scope.OPENID,))
    client_type: ClientType = ClientType.PUBLIC
    client_secret_hash: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True
    session_lifetime_seconds: int | None = None
    access_token_lifetime_seconds: int | None = None
    authorization_code_lifetime_seconds: int | None = None
    refresh_token_lifetime_seconds: int | None = None


def resolve_lifetime_seconds(configured: int | None, default: int) -> int:
    """Durée de vie effective : celle du client si renseignée, sinon le défaut serveur."""
    return configured if configured is not None and configured > 0 else default


@dataclass(frozen=True, slots=True)
class AuthorizationCode:
    """Code d'autorisation à usage unique (RFC 6749 §1.3.1, §4.1.2).

    Porte l'identifiant du client émetteur, l'URI de redirection attendue
    au moment de l'échange, les scopes accordés et le challenge PKCE
    (sélectionné par le client à l'étape ``/authorize``).

    ``subject`` est l'identifiant de l'utilisateur authentifié (UUID UUID
    issu de FastAPI Users, stocké en chaîne pour la flexibilité).
    """

    code: str = field(default_factory=lambda: f"{uuid4().hex[:16]}")
    client_id: str = ""
    redirect_uri: str = ""
    subject: str = ""
    scopes: frozenset[Scope] = frozenset()
    code_challenge: str = ""
    code_challenge_method: str = "S256"
    nonce: str = ""
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_consumed: bool = False


@dataclass(frozen=True, slots=True)
class RefreshToken:
    """Refresh token opaque (RFC 6749 §1.5, §6) — jamais stocké en clair.

    Seule l'empreinte SHA-256 du jeton est persistée (``token_hash``) :
    la valeur en clair n'existe que dans la réponse ``/token``. Le jeton
    est lié au client, au ``subject`` et aux scopes accordés ; il est
    rotatif — chaque usage consomme l'ancien jeton et en émet un nouveau.
    """

    token_hash: str
    client_id: str = ""
    subject: str = ""
    scopes: frozenset[Scope] = frozenset()
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_consumed: bool = False
