"""Entités du périmètre d'autorisation (RFC 6749 — OAuth 2.0, RFC 7636 — PKCE).

Le domaine ne contient ici que des entités pures, sans dépendance vers
FastAPI, SQLAlchemy ou PyJWT. Les ports associés vivent dans
``interfaces/`` et les implémentations dans l'infrastructure.
"""

from __future__ import annotations

import re
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
    device_code_lifetime_seconds: int | None = None
    device_code_interval_seconds: int | None = None


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


class DeviceAuthorizationStatus(str, Enum):
    """États d'une session du Device Authorization Grant (RFC 8628 §3).

    ``PENDING`` : le client a obtenu ses codes, l'utilisateur n'a pas
    encore validé l'appareil sur la page de vérification.
    ``APPROVED`` : l'utilisateur a autorisé l'appareil ; le poll du client
    peut alors obtenir les jetons.
    ``DENIED`` : l'utilisateur a refusé ; le poll retourne ``access_denied``.
    """

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


_USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def normalize_user_code(code: str) -> str:
    """Compacte un user code saisi (minuscules, tirets, espaces tolérés).

    ``"wdjb-mjht "`` et ``"WDJBMJHT"`` correspondent au même identifiant :
    seuls les 32 caractères non ambigus de l'alphabet sont conservés.
    """
    return re.sub(r"[^0-9A-Z]", "", code.upper())


def format_user_code(code: str) -> str:
    """Rend un user code lisible par l'humain (RFC 8628 §3.2 : ``WDJB-MJHT``)."""
    compact = normalize_user_code(code)
    return f"{compact[:4]}-{compact[4:]}"


@dataclass(frozen=True, slots=True)
class DeviceAuthorization:
    """Session du Device Authorization Grant (RFC 8628).

    Créée par ``/device_authorization``, elle lie le ``device_code`` opque
    (stocké en empreinte ``SHA-256``) au ``user_code`` court que l'utilisateur
    saisit sur la page de vérification. ``status`` passe de ``PENDING`` à
    ``APPROVED`` (sujet fixé) ou ``DENIED`` selon la décision de l'utilisateur ;
    le poll du client sur ``/token`` la consomme une fois les jetons émis.
    ``interval`` et ``last_polled_at`` alimentent l'anti-bourrage (``slow_down``).
    """

    device_code_hash: str
    user_code: str
    client_id: str
    scopes: frozenset[Scope] = frozenset()
    subject: str = ""
    status: DeviceAuthorizationStatus = DeviceAuthorizationStatus.PENDING
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    interval: int = 5
    last_polled_at: datetime | None = None
