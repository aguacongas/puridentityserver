"""Cas d'utilisation : Dynamic Client Registration (RFC 7591) + gestion (RFC 7592).

``POST /register`` crée un client OAuth/OIDC à partir de ses métadonnées ;
``GET/PUT/DELETE /register/{client_id}`` (RFC 7592) permettent au client de
relire, remplacer ou supprimer sa configuration, autentifié par le
registration access token émis lors de l'enregistrement.

Périmètre maîtrisé (docson du registre) :

- grant type : ``authorization_code`` uniquement (le ``refresh_token``
  s'obtient via le scope ``offline_access``) ;
- response types : ``code`` uniquement — les flows implicit/hybrid via
  enregistrement dynamique sont refusés ;
- authentification du client : ``client_secret_basic`` /
  ``client_secret_post`` (client confidentiel, secret émis une seule fois)
  ou ``none`` (client public) ; ``private_key_jwt`` non supporté ;
- URI de redirection : absolues http(s), sans fragment ;
- scopes : sous-ensemble connu du serveur.

Protections anti abus :

- si ``requires_initial_access_token`` est actif, ``POST /register`` exige
  un initial access token (Bearer) dont l'empreinte est seedée en
  configuration — sinon 401 ;
- les opérations de gestion exigent le registration access token du client ;
- secrets et jetons ne sont jamais stockés en clair (empreintes SHA-256).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from secrets import token_urlsafe
from urllib.parse import urlsplit

from puridentityserver.domain.authorization import Client, ClientType, Scope
from puridentityserver.interfaces.repositories.client_repository import ClientRepository

_ALLOWED_GRANT_TYPES = frozenset({"authorization_code"})
_ALLOWED_RESPONSE_TYPES = frozenset({"code"})
_ALLOWED_AUTH_METHODS = frozenset({"none", "client_secret_basic", "client_secret_post"})
_AUTH_METHOD_DEFAULT = "client_secret_basic"
_MIN_SECRET_LENGTH = 8


@dataclass(frozen=True, slots=True)
class RegistrationConfig:
    """Configuration de l'enregistrement dynamique des clients."""

    issuer: str
    base_url: str = ""
    requires_initial_access_token: bool = True
    initial_access_token_hashes: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class RegistrationMetadata:
    """Métadonnées client normalisées et validées (RFC 7591 §2.1)."""

    redirect_uris: frozenset[str] = frozenset()
    post_logout_redirect_uris: frozenset[str] = frozenset()
    scopes: frozenset[Scope] = frozenset((Scope.OPENID,))
    client_type: ClientType = ClientType.CONFIDENTIAL
    token_endpoint_auth_method: str = _AUTH_METHOD_DEFAULT
    requested_secret: str | None = None
    par_required: bool = False


@dataclass(frozen=True, slots=True)
class RegisterRequest:
    """Demande de création d'un client (RFC 7591 §4)."""

    metadata: dict[str, object]
    initial_access_token: str = ""


@dataclass(frozen=True, slots=True)
class ReadClientRequest:
    """Demande de lecture de la configuration d'un client (RFC 7592 §2)."""

    client_id: str
    registration_access_token: str


@dataclass(frozen=True, slots=True)
class UpdateClientRequest:
    """Demande de remplacement de la configuration d'un client (RFC 7592 §3)."""

    client_id: str
    registration_access_token: str
    metadata: dict[str, object]


@dataclass(frozen=True, slots=True)
class DeleteClientRequest:
    """Demande de suppression d'un client (RFC 7592 §4)."""

    client_id: str
    registration_access_token: str


@dataclass(frozen=True, slots=True)
class ClientRegistration:
    """Réponse de registration/lecture/mise à jour (RFC 7591 §3.2.1).

    Le ``client_secret`` (client confidentiel) et le
    ``registration_access_token`` ne sont rendus en clair qu'une seule
    fois, à la création (et lors d'une rotation de secret en PUT) : le
    serveur n'en conserve que l'empreinte SHA-256.
    """

    client_id: str
    client_id_issued_at: int = 0
    client_type: ClientType = ClientType.CONFIDENTIAL
    token_endpoint_auth_method: str = _AUTH_METHOD_DEFAULT
    grant_types: list[str] = field(default_factory=lambda: ["authorization_code"])
    response_types: list[str] = field(default_factory=lambda: ["code"])
    scope: str = "openid"
    redirect_uris: list[str] = field(default_factory=list)
    post_logout_redirect_uris: list[str] = field(default_factory=list)
    client_secret: str = ""
    registration_access_token: str = ""
    registration_client_uri: str = ""
    require_pushed_authorization_requests: bool = False


@dataclass(frozen=True, slots=True)
class RegistrationError:
    """Rejet d'une demande d'enregistrement (RFC 7591 §3.2.2 + statut HTTP)."""

    error: str
    error_description: str = ""
    status_code: int = 400


@dataclass(frozen=True, slots=True)
class _SecretRotation:
    """Résultat d'une rotation de secret lors d'une mise à jour (RFC 7592 §3)."""

    secret_hash: str
    issued_secret: str


def hash_secret(value: str) -> str:
    """Calcule l'empreinte SHA-256 d'un secret ou jeton (jamais stocké en clair)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class RegistrationUseCase:
    """Crée et gère les clients enregistrés dynamiquement (RFC 7591 + 7592)."""

    def __init__(
        self,
        config: RegistrationConfig,
        client_repository: ClientRepository,
    ) -> None:
        """Injection de la configuration et du registre clients."""
        self._config = config
        self._clients = client_repository

    async def register(self, request: RegisterRequest) -> ClientRegistration | RegistrationError:
        """Crée un client et retourne sa configuration complète (RFC 7591 §4)."""
        if not self._authorise_initial(request.initial_access_token):
            return RegistrationError(
                "invalid_client",
                "Initial access token manquant ou invalide",
                401,
            )
        metadata = _parse_metadata(request.metadata)
        if isinstance(metadata, RegistrationError):
            return metadata

        client_id = token_urlsafe(24)
        client_secret = ""
        secret_hash = ""
        if metadata.client_type is ClientType.CONFIDENTIAL:
            client_secret = token_urlsafe(48)
            secret_hash = hash_secret(client_secret)
        registration_token = token_urlsafe(48)
        client = Client(
            client_id=client_id,
            redirect_uris=metadata.redirect_uris,
            post_logout_redirect_uris=metadata.post_logout_redirect_uris,
            scopes=metadata.scopes,
            client_type=metadata.client_type,
            client_secret_hash=secret_hash,
            registration_access_token_hash=hash_secret(registration_token),
            par_required=metadata.par_required,
        )
        await self._clients.save(client)
        return self._response(
            client,
            client_secret=client_secret,
            registration_access_token=registration_token,
        )

    async def read(self, request: ReadClientRequest) -> ClientRegistration | RegistrationError:
        """Relit la configuration d'un client (RFC 7592 §2)."""
        client = await self._resolve_managed(request)
        if isinstance(client, RegistrationError):
            return client
        return self._response(client)

    async def update(self, request: UpdateClientRequest) -> ClientRegistration | RegistrationError:
        """Remplace la configuration d'un client (RFC 7592 §3).

        Les identifiants restent stables (``client_id``, registration
        access token). Un nouveau ``client_secret`` fourni dans la requête
        fait tourner le secret (émis une seule fois) ; sans valeur fournie,
        le secret courant est conservé et jamais re-émis.
        """
        client = await self._resolve_managed(
            ReadClientRequest(
                client_id=request.client_id,
                registration_access_token=request.registration_access_token,
            )
        )
        if isinstance(client, RegistrationError):
            return client
        metadata = _parse_metadata(request.metadata)
        if isinstance(metadata, RegistrationError):
            return metadata

        rotation = self._updated_secret(client, metadata)
        updated = Client(
            client_id=client.client_id,
            redirect_uris=metadata.redirect_uris,
            post_logout_redirect_uris=metadata.post_logout_redirect_uris,
            scopes=metadata.scopes,
            client_type=metadata.client_type,
            client_secret_hash=rotation.secret_hash,
            registration_access_token_hash=client.registration_access_token_hash,
            created_at=client.created_at,
            is_active=client.is_active,
            session_lifetime_seconds=client.session_lifetime_seconds,
            access_token_lifetime_seconds=client.access_token_lifetime_seconds,
            authorization_code_lifetime_seconds=client.authorization_code_lifetime_seconds,
            refresh_token_lifetime_seconds=client.refresh_token_lifetime_seconds,
            device_code_lifetime_seconds=client.device_code_lifetime_seconds,
            device_code_interval_seconds=client.device_code_interval_seconds,
            par_required=metadata.par_required,
        )
        await self._clients.save(updated)
        return self._response(updated, client_secret=rotation.issued_secret)

    async def delete(self, request: DeleteClientRequest) -> RegistrationError | None:
        """Supprime le client et sa configuration (RFC 7592 §4 ; 204 ou erreur)."""
        client = await self._resolve_managed(
            ReadClientRequest(
                client_id=request.client_id,
                registration_access_token=request.registration_access_token,
            )
        )
        if isinstance(client, RegistrationError):
            return client
        await self._clients.delete(client.client_id)
        return None

    async def _resolve_managed(self, request: ReadClientRequest) -> Client | RegistrationError:
        """Charge le client et vérifie son registration access token."""
        client = await self._clients.find_by_id(request.client_id)
        if client is None:
            return RegistrationError("invalid_client", "Client inconnu", 404)
        if not self._authorise_registration(client, request.registration_access_token):
            return RegistrationError(
                "invalid_client",
                "Registration access token manquant ou invalide",
                401,
            )
        return client

    def _updated_secret(self, client: Client, metadata: RegistrationMetadata) -> _SecretRotation:
        """Détermine la rotation de secret ; ``issued_secret`` reste vide sans rotation.

        Le secret est émis en clair uniquement quand une rotation est
        demandée ou qu'un secret est généré pour la première fois (passage
        en client confidentiel).
        """
        if metadata.client_type is ClientType.PUBLIC:
            return _SecretRotation("", "")
        if metadata.requested_secret is not None:
            requested_hash = hash_secret(metadata.requested_secret)
            if requested_hash == client.client_secret_hash:
                return _SecretRotation(client.client_secret_hash, "")
            return _SecretRotation(requested_hash, metadata.requested_secret)
        if client.client_secret_hash:
            return _SecretRotation(client.client_secret_hash, "")
        generated = token_urlsafe(48)
        return _SecretRotation(hash_secret(generated), generated)

    def _authorise_initial(self, token: str) -> bool:
        """Vérifie l'initial access token (RFC 7591 §4.1) si exigé par la config."""
        if not self._config.requires_initial_access_token:
            return True
        if not token or not self._config.initial_access_token_hashes:
            return False
        return any(
            hmac.compare_digest(hash_secret(token), expected)
            for expected in self._config.initial_access_token_hashes
        )

    @staticmethod
    def _authorise_registration(client: Client, token: str) -> bool:
        """Vérifie le registration access token du client (RFC 7592 §1.2)."""
        if not token or not client.registration_access_token_hash:
            return False
        return hmac.compare_digest(hash_secret(token), client.registration_access_token_hash)

    def _response(
        self,
        client: Client,
        *,
        client_secret: str = "",
        registration_access_token: str = "",
    ) -> ClientRegistration:
        """Construit la réponse de registration depuis le client persisté."""
        auth_method = "none" if client.client_type is ClientType.PUBLIC else "client_secret_basic"
        return ClientRegistration(
            client_id=client.client_id,
            client_id_issued_at=int(client.created_at.timestamp()),
            client_type=client.client_type,
            token_endpoint_auth_method=auth_method,
            scope=" ".join(sorted(scope.value for scope in client.scopes)),
            redirect_uris=sorted(client.redirect_uris),
            post_logout_redirect_uris=sorted(client.post_logout_redirect_uris),
            client_secret=client_secret,
            registration_access_token=registration_access_token,
            registration_client_uri=f"{self._base_url()}/register/{client.client_id}",
            require_pushed_authorization_requests=client.par_required,
        )

    def _base_url(self) -> str:
        """URL de base du serveur (raccourci de discovery ou issuer)."""
        return (self._config.base_url or self._config.issuer).rstrip("/")


def _parse_metadata(raw: object) -> RegistrationMetadata | RegistrationError:
    """Valide les métadonnées reçues et les normalise (RFC 7591 §2)."""
    if not isinstance(raw, dict):
        return RegistrationError(
            "invalid_client_metadata", "Métadonnées non conforme (objet JSON attendu)"
        )
    redirect_uris = _parse_uri_list(raw, "redirect_uris", required=True)
    if isinstance(redirect_uris, RegistrationError):
        return redirect_uris
    post_logout_uris = _parse_uri_list(raw, "post_logout_redirect_uris")
    if isinstance(post_logout_uris, RegistrationError):
        return post_logout_uris
    scopes = _parse_scopes(raw)
    if isinstance(scopes, RegistrationError):
        return scopes
    auth_method = _parse_auth_method(raw)
    if isinstance(auth_method, RegistrationError):
        return auth_method
    grants = _parse_members(raw, "grant_types", _ALLOWED_GRANT_TYPES, "authorization_code")
    if isinstance(grants, RegistrationError):
        return grants
    responses = _parse_members(raw, "response_types", _ALLOWED_RESPONSE_TYPES, "code")
    if isinstance(responses, RegistrationError):
        return responses
    requested_secret = _parse_requested_secret(raw)
    if isinstance(requested_secret, RegistrationError):
        return requested_secret
    par_required = _parse_par_required(raw)
    if isinstance(par_required, RegistrationError):
        return par_required

    client_type = ClientType.PUBLIC if auth_method == "none" else ClientType.CONFIDENTIAL
    return RegistrationMetadata(
        redirect_uris=redirect_uris,
        post_logout_redirect_uris=post_logout_uris,
        scopes=scopes,
        client_type=client_type,
        token_endpoint_auth_method=auth_method,
        requested_secret=requested_secret,
        par_required=par_required,
    )


def _parse_uri_list(
    raw: dict[str, object], key: str, *, required: bool = False
) -> frozenset[str] | RegistrationError:
    """Lit une liste d'URI de redirection et valide chaque membre (§2.1)."""
    value = raw.get(key)
    if value is None:
        if required:
            return RegistrationError("invalid_client_metadata", "redirect_uris manquant")
        return frozenset()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return RegistrationError("invalid_client_metadata", f"{key} doit être une liste de chaînes")
    for uri in value:
        if not _is_redirect_uri(uri):
            return RegistrationError(
                "invalid_redirect_uri", f"{key} contient une URI invalide : {uri}"
            )
    return frozenset(value)


def _is_redirect_uri(uri: str) -> bool:
    """Vérifie qu'une URI est absolue, http(s), sans fragment (RFC 7591 §2)."""
    parsed = urlsplit(uri)
    return parsed.scheme in ({"http", "https"}) and bool(parsed.netloc) and parsed.fragment == ""


def _parse_scopes(raw: dict[str, object]) -> frozenset[Scope] | RegistrationError:
    """Valide le scope (chaîne espacée) contre les scopes connus du serveur."""
    value = raw.get("scope")
    if value is None or value == "":
        return frozenset((Scope.OPENID,))
    if not isinstance(value, str):
        return RegistrationError("invalid_client_metadata", "scope doit être une chaîne")
    try:
        return frozenset(Scope(token) for token in value.split())
    except ValueError:
        return RegistrationError("invalid_client_metadata", f"scope inconnu : {value}")


def _parse_auth_method(raw: dict[str, object]) -> str | RegistrationError:
    """Valide la méthode d'authentification du client (RFC 7591 §2.1)."""
    value = raw.get("token_endpoint_auth_method")
    if value is None:
        return "client_secret_basic"
    if not isinstance(value, str) or value not in _ALLOWED_AUTH_METHODS:
        return RegistrationError(
            "invalid_client_metadata",
            "token_endpoint_auth_method non supporté (attendu : "
            "client_secret_basic, client_secret_post ou none)",
        )
    return value


def _parse_members(
    raw: dict[str, object],
    key: str,
    allowed: frozenset[str],
    default: str,
) -> frozenset[str] | RegistrationError:
    """Valide une liste de membres (grant_types / response_types) permise."""
    value = raw.get(key)
    if value is None:
        return frozenset({default})
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return RegistrationError("invalid_client_metadata", f"{key} doit être une liste de chaînes")
    unknown = set(value) - allowed
    if unknown:
        return RegistrationError(
            "invalid_client_metadata",
            f"{key} non supporté : {', '.join(sorted(unknown))}",
        )
    return frozenset(value)


def _parse_requested_secret(raw: dict[str, object]) -> str | RegistrationError | None:
    """Lit un éventuel ``client_secret`` fourni en mise à jour (rotation RFC 7592)."""
    value = raw.get("client_secret")
    if value is None:
        return None
    if not isinstance(value, str) or len(value) < _MIN_SECRET_LENGTH:
        return RegistrationError(
            "invalid_client_metadata",
            f"client_secret doit comporter au moins {_MIN_SECRET_LENGTH} caractères",
        )
    return value


def _parse_par_required(raw: dict[str, object]) -> bool | RegistrationError:
    """Lit ``require_pushed_authorization_requests`` (RFC 9126 §5.2, par défaut false)."""
    value = raw.get("require_pushed_authorization_requests")
    if value is None:
        return False
    if not isinstance(value, bool):
        return RegistrationError(
            "invalid_client_metadata",
            "require_pushed_authorization_requests doit être un booléen",
        )
    return value
