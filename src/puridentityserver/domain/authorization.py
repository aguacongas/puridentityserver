"""Entités du périmètre d'autorisation (RFC 6749 — OAuth 2.0, RFC 7636 — PKCE).

Le domaine ne contient ici que des entités pures, sans dépendance vers
FastAPI, SQLAlchemy ou PyJWT. Les ports associés vivent dans
``interfaces/`` et les implémentations dans l'infrastructure.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import ClassVar
from urllib.parse import urlsplit
from uuid import uuid4


class Scope(str):
    """Scope OAuth 2.0 / OIDC : valeurs standard (RFC 6749 §3.3, §5.4) et libres.

    Sous-classe de ``str`` : toute chaîne (x. ``api.read``) est une valeur
    acceptée, ce qui permet de représenter les scopes d'API déclarés par
    les ``ApiResource``. Les constantes standard gardent leur sémantique
    (``openid`` requis, ``offline_access`` → refresh token…) ; ``value``
    rétro-compatibilise l'accès à la chaîne d'un scope, y compris pour une
    valeur libre.
    """

    OPENID: ClassVar[Scope]
    PROFILE: ClassVar[Scope]
    EMAIL: ClassVar[Scope]
    ADDRESS: ClassVar[Scope]
    PHONE: ClassVar[Scope]
    OFFLINE_ACCESS: ClassVar[Scope]

    @property
    def value(self) -> str:
        """Renvoie la valeur de la chaîne du scope."""
        return str(self)

    @classmethod
    def from_space_separated(cls, value: str | None) -> frozenset[Scope]:
        """Décode une chaîne de scopes séparés par des espaces (RFC 6749 §3.3).

        Aucun token n'est rejeté ici : les scopes standard comme les scopes
        d'API libres sont acceptés (la validation d'enregistrement est
        portée par le ``ScopeRegistry`` pull côté usecases).
        """
        if not value:
            return frozenset()
        return frozenset(Scope(token) for token in value.split() if token)


# Constantes standard (affectées après la définition de classe : le nom
# ``Scope`` n'est lié qu'une fois le corps de classe exécuté, une référence
# dans le corps lèverait ``NameError``).
Scope.OPENID = Scope("openid")
Scope.PROFILE = Scope("profile")
Scope.EMAIL = Scope("email")
Scope.ADDRESS = Scope("address")
Scope.PHONE = Scope("phone")
Scope.OFFLINE_ACCESS = Scope("offline_access")


class ResponseMode(str, Enum):
    """Mode de réponse de l'endpoint d'autorisation (OIDC Core 1.0 §3.1.2.1)."""

    QUERY = "query"
    FRAGMENT = "fragment"


class ClientType(str, Enum):
    """Type de client OAuth 2.0 (RFC 6749 §2.1)."""

    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


class TokenEndpointAuthMethod(str, Enum):
    """Méthode d'authentification du client au token endpoint.

    Les valeurs suivent les RFC 6749 §2.3, 7523 §2.2 et 8705 : ``none``
    (client public, aucune authentification), ``basic``/``post`` (secret
    client via en-tête HTTP Basic ou champ de formulaire),
    ``client_secret_jwt`` (assertion JWT signée HMAC avec le secret
    partagé), ``private_key_jwt`` (assertion signée avec une clé privée
    dont la publique est enregistrée via ``jwks`` / ``jwks_uri``) et
    ``tls_client_auth`` / ``self_signed_tls_client_auth`` (certificat
    client mTLS, RFC 8705).
    """

    NONE = "none"
    CLIENT_SECRET_BASIC = "client_secret_basic"  # ruff: ignore[hardcoded-password-string]  (nom de méthode, pas un secret)
    CLIENT_SECRET_POST = "client_secret_post"  # ruff: ignore[hardcoded-password-string]  (nom de méthode, pas un secret)
    CLIENT_SECRET_JWT = "client_secret_jwt"  # ruff: ignore[hardcoded-password-string]  (nom de méthode, pas un secret)
    PRIVATE_KEY_JWT = "private_key_jwt"
    TLS_CLIENT_AUTH = "tls_client_auth"
    SELF_SIGNED_TLS_CLIENT_AUTH = "self_signed_tls_client_auth"


@dataclass(frozen=True, slots=True)
class ClientCertificate:
    """Certificat client présenté en authentification TLS mutuelle (RFC 8705).

    ``der`` contient la forme DER du certificat (``None`` si aucun certificat
    n'a pu être extrait, ex. navire HTTP sans proxy de terminaison).
    ``subject_dn`` est le sujet au format one-line RFC 4514 et
    ``is_self_signed`` indique une signature auto-référée (RFC 8705 §2.3.2).
    """

    der: bytes | None = None
    subject_dn: str = ""
    is_self_signed: bool = False


def der_certificate_hash(der: bytes) -> str:
    """Empreinte base64url(SHA-256(DER)) d'un certificat client (RFC 8705 §2.1.2)."""
    digest = hashlib.sha256(der).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


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

    ``token_endpoint_auth_method`` sélectionne la méthode d'authentification
    au token endpoint : à défaut (``None``), ``effective_auth_method``
    dérive ``none`` pour un client public et ``client_secret_basic`` pour un
    client confidentiel. ``client_secret_ciphertext`` conserve le secret
    **chiffré** (RSA-OAEP, clé de scellement ``KeyUse.SECRET`` auto-rotée) des
    clients ``client_secret_jwt`` / grant jwt-bearer ; ``jwks_uri`` /
    ``jwks`` portent les clés publiques des
    clients ``private_key_jwt`` ; ``tls_client_auth_subject_dn`` et
    ``tls_client_certificate_hash`` lient le client à son certificat mTLS.
    ``id_token_signed_response_alg`` (OIDC Core 1.0 §3.1.3.7) impose un
    algorithme de signature d'``id_token`` par client : une valeur vide
    retombe sur l'algorithme de signature principal du serveur, une valeur
    symétrique HS* signe avec le secret partagé du client (conservé
    chiffré, cf. ``client_secret_ciphertext``).
    ``id_token_encrypted_response_alg`` / ``..._enc`` (OIDC Core 1.0
    §3.1.3.6) imposent un chiffrement JWE de l'``id_token`` : vide = le
    jeton JWS est émis tel quel ; sinon le JWS imbriqué est chiffré avec
    ``client_secret_ciphertext`` (familles symétriques) ou la clé publique
    RSA du ``jwks`` (RSA-OAEP).
    ``frontchannel_logout_uri`` / ``backchannel_logout_uri`` (OIDC
    Front-Channel Logout 1.0 §2 / Back-Channel Logout 1.0 §2) : URI de
    terminaison de session du client appelées par ``/end_session`` après la
    déconnexion — iframe (front-channel, ``iss``/``sid`` en query) ou
    ``POST logout_token`` direct serveur→client (back-channel).
    ``..._session_required`` impose l'envoi du ``sid`` (Session Management
    properly focus) ; sans ``sid`` vérifiable, la notification est omise.
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
    token_endpoint_auth_method: TokenEndpointAuthMethod | None = None
    client_secret_ciphertext: str = ""
    jwks_uri: str = ""
    jwks: tuple[dict[str, object], ...] = ()
    tls_client_auth_subject_dn: str = ""
    tls_client_certificate_hash: str = ""
    id_token_signed_response_alg: str = ""
    id_token_encrypted_response_alg: str = ""
    id_token_encrypted_response_enc: str = ""
    frontchannel_logout_uri: str = ""
    frontchannel_logout_session_required: bool = False
    backchannel_logout_uri: str = ""
    backchannel_logout_session_required: bool = False

    @property
    def effective_auth_method(self) -> TokenEndpointAuthMethod:
        """Méthode d'authentification effective (défauts dérivés du type pubic/confidentiel)."""
        if self.token_endpoint_auth_method is not None:
            return self.token_endpoint_auth_method
        if self.client_type is ClientType.PUBLIC:
            return TokenEndpointAuthMethod.NONE
        return TokenEndpointAuthMethod.CLIENT_SECRET_BASIC

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
    ``session_id`` (OIDC Session Management §2) porte le ``sid`` de la
    session navigateur au moment de l'émission : il relie le code au
    ``sid`` qui sera reproduit dans l'``id_token`` à l'échange.
    """

    code: str = field(default_factory=lambda: f"{uuid4().hex[:16]}")
    client_id: str = ""
    redirect_uri: str = ""
    subject: str = ""
    session_id: str = ""
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
