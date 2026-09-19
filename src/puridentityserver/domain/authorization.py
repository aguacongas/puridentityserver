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
from urllib.parse import urlsplit
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

    ``client_secret_hash`` et ``registration_access_token_hash`` conservent
    des empreintes SHA-256 (jamais les valeurs en clair). Les
    ``redirect_uris``, ``post_logout_redirect_uris`` et ``scopes`` sont
    limités à ce que le serveur accepte pour ce client. L'empreinte du
    registration access token (RFC 7592) permet au client de gérer sa
    configuration enregistrée (lecture, mise à jour, suppression).
    ``par_required`` (RFC 9126 §6.1) force ce client à pousser ses
    demandes via ``/par`` : l'endpoint d'autorisation rejette alors toute
    demande directe sans ``request_uri``. ``require_consent`` (OAuth 2.0
    Consent, OIDC Core 1.0 §3.1.2.2) exige la confirmation de
    l'utilisateur connecté — mémorisée dans le store ``consents`` — avant
    d'émettre le moindre code ou jeton.

    ``web_origins`` déclare explicitement des origines internet autorisées
    à appeler les endpoints du serveur depuis le navigateur (CORS) au-delà
    de celles déduites des ``redirect_uris`` (OAuth 2.0 for Browser-Based
    Apps — la métadonnée ``web_origins`` du registration est prise en
    charge au RFC 7591).
    """

    client_id: str
    redirect_uris: frozenset[str] = frozenset()
    post_logout_redirect_uris: frozenset[str] = frozenset()
    web_origins: frozenset[str] = frozenset()
    scopes: frozenset[Scope] = frozenset((Scope.OPENID,))
    client_type: ClientType = ClientType.PUBLIC
    client_secret_hash: str = ""
    registration_access_token_hash: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True
    session_lifetime_seconds: int | None = None
    access_token_lifetime_seconds: int | None = None
    authorization_code_lifetime_seconds: int | None = None
    refresh_token_lifetime_seconds: int | None = None
    device_code_lifetime_seconds: int | None = None
    device_code_interval_seconds: int | None = None
    par_required: bool = False
    require_consent: bool = False

    def cors_allowed_origins(self) -> frozenset[str]:
        """Origines autorisées en CORS pour ce client (déduites + déclarées).

        Chaque ``redirect_uri`` contribue son origine (schéma+autorité,
        ports par défaut normalisés) ; ``web_origins`` les complète
        explicitement (ex. un alias ``localhost`` du même SPA).
        """
        origins = {origin_of_uri(uri) for uri in self.redirect_uris}
        origins |= {origin_of_uri(uri) for uri in self.web_origins}
        return frozenset(origin for origin in origins if origin is not None)


def origin_of_uri(uri: str) -> str | None:
    """Normalise une URL en origine (schéma+autorité, OAuth BCP §8).

    ``"https://app.example:443/callback"`` → ``"https://app.example"``
    (ports par défaut élidés, comparables à l'en-tête ``Origin`` émis par
    les navigateurs) ; retourne ``None`` si l'URL n'est pas http(s).
    """
    parsed = urlsplit(uri)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    default_port = 80 if parsed.scheme == "http" else 443
    if parsed.hostname is not None and parsed.port is not None and parsed.port != default_port:
        netloc = f"{parsed.hostname}:{parsed.port}"
    else:
        netloc = parsed.hostname or ""
    return f"{parsed.scheme}://{netloc}"


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


@dataclass(frozen=True, slots=True)
class PushedAuthorization:
    """Requête d'autorisation poussée au serveur (RFC 9126).

    Créée par ``POST /par``, elle lie le ``request_uri`` opque (supposé
    invérifiable, ``urn:ietf:params:oauth:request_uri:<value>``) aux paramètres
    de la demande d'autorisation (``params``, chaînes sérialisées). Le
    ``request_uri`` est à usage unique et lié au client qui l'a poussé ;
    ``is_consumed`` et ``expires_at`` le rendent impossible à réutiliser ou à
    rejouer après expiration.
    """

    request_uri: str
    client_id: str = ""
    params: dict[str, str] = field(default_factory=dict)
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_consumed: bool = False


@dataclass(frozen=True, slots=True)
class Consent:
    """Consentement accordé par un utilisateur à un client (OIDC Core §3.1.2.2).

    Mémorise l'ensemble des scopes déjà autorisés (``scopes``) par le
    ``subject`` pour le ``client_id`` : tant que la nouvelle demande est
    couverte par ce consentement, ``/authorize`` n'exige pas de nouvelle
    confirmation. ``covers`` teste cette inclusion ; une demande plus large
    (nouveau scope) nécessite un nouveau consentement, puis les scopes sont
    fusionnés (l'accord ne retire jamais un scope déjà donné).
    """

    subject: str
    client_id: str
    scopes: frozenset[Scope] = frozenset()
    granted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def covers(self, requested: frozenset[Scope]) -> bool:
        """Vrai si les scopes demandés sont déjà inclus dans le consentement."""
        return requested <= self.scopes
