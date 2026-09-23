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
- authentification du client : les sept méthodes de ``token_endpoint_auth``
  (RFC 6749 §2.3.1, RFC 7523 §2.2, RFC 8705) — ``none`` (client public),
  ``client_secret_basic`` / ``client_secret_post`` / ``client_secret_jwt``
  (client confidentiel, secret émis une seule fois), ``private_key_jwt``
  (clé publique via ``jwks`` ou ``jwks_uri``) et ``tls_client_auth`` /
  ``self_signed_tls_client_auth`` (liens certificat/subject DN) ;
- URI de redirection : absolues http(s), sans fragment ;
- scopes : sous-ensemble connu du serveur ;
- extensions : ``require_pushed_authorization_requests`` (RFC 9126 §5.2) et
  ``require_consent`` (écran de consentement OIDC Core 1.0 §3.1.2.2),
  booléens optionnels par client (défaut ``false``).

Les secrets des méthodes HMAC (``client_secret_jwt``) sont **chiffrés au
repos** (RSA-OAEP, clé de scellement ``KeyUse.SECRET`` gérée par le store
``key_pair`` — générée et entrée en rotation automatiquement) — le serveur doit pouvoir
les déchiffrer au moment de vérifier les assertions ; à défaut de chiffreur,
l'enregistrement de tels clients est refusé.

Protections anti abus :

- si ``requires_initial_access_token`` est actif, ``POST /register`` exige
  un initial access token (Bearer) dont l'empreinte est seedée en
  configuration — sinon 401 ;
- les opérations de gestion exigent le registration access token du client ;
- secrets et jetons ne sont jamais stockés en clair (empreinte SHA-256 pour
  les secrets ``basic``/``post``, chiffrement RSA-OAEP pour ``client_secret_jwt``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from secrets import token_urlsafe
from typing import cast
from urllib.parse import urlsplit

from puridentityserver.application.claim_authorizer import BearerClaimAuthorizer
from puridentityserver.application.scope_registry import ScopeRegistry
from puridentityserver.domain.authorization import (
    Client,
    ClientType,
    Scope,
    TokenEndpointAuthMethod,
    der_certificate_hash,
    origin_of_uri,
)
from puridentityserver.domain.identity_resource import DEFAULT_IDENTITY_RESOURCES
from puridentityserver.domain.jwe import (
    ALL_ENCRYPTION_ALGORITHMS,
    ALL_ENCRYPTION_METHODS,
    ASYMMETRIC_ENCRYPTION_ALGORITHMS,
    SYMMETRIC_ENCRYPTION_ALGORITHMS,
)
from puridentityserver.domain.jwks import SYMMETRIC_ALGORITHMS, JWTAlgorithm
from puridentityserver.domain.key_validation import (
    require_encryption_rsa_key,
    require_signing_key,
    validate_client_jwks,
)
from puridentityserver.interfaces.domain.secrets import SecretCipher
from puridentityserver.interfaces.repositories.client_repository import ClientRepository

_ALLOWED_GRANT_TYPES = frozenset({"authorization_code"})
_ALLOWED_RESPONSE_TYPES = frozenset({"code"})
_ALLOWED_AUTH_METHODS = frozenset(
    {
        "none",
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
        "tls_client_auth",
        "self_signed_tls_client_auth",
    }
)
_AUTH_METHOD_DEFAULT = "client_secret_basic"
_TLS_KEY_AUTH_METHODS = frozenset({"tls_client_auth", "self_signed_tls_client_auth"})
_KEYLESS_AUTH_METHODS = frozenset({"none", "private_key_jwt"}) | _TLS_KEY_AUTH_METHODS
_SYMMETRIC_SIGNING_VALUES = frozenset(algorithm.value for algorithm in SYMMETRIC_ALGORITHMS)
_ASYMMETRIC_ENCRYPTION_VALUES = frozenset(
    algorithm.value for algorithm in ASYMMETRIC_ENCRYPTION_ALGORITHMS
)
_SYMMETRIC_ENCRYPTION_VALUES = frozenset(
    algorithm.value for algorithm in SYMMETRIC_ENCRYPTION_ALGORITHMS
)
_ALGORITHM_ENCRYPTION_VALUES = frozenset(algorithm.value for algorithm in ALL_ENCRYPTION_ALGORITHMS)
_METHOD_ENCRYPTION_VALUES = frozenset(method.value for method in ALL_ENCRYPTION_METHODS)
_MIN_SECRET_LENGTH = 8
_STANDARD_SCOPES = frozenset(resource.name for resource in DEFAULT_IDENTITY_RESOURCES)


@dataclass(frozen=True, slots=True)
class RegistrationConfig:
    """Configuration de l'enregistrement dynamique des clients."""

    issuer: str
    base_url: str = ""
    requires_initial_access_token: bool = True
    initial_access_token_hashes: frozenset[str] = frozenset()
    initial_access_token_mode: str = "static"  # ruff: ignore[hardcoded-password-string] (nom de mode, pas un secret)


@dataclass(frozen=True, slots=True)
class RegistrationMetadata:
    """Métadonnées client normalisées et validées (RFC 7591 §2.1)."""

    redirect_uris: frozenset[str] = frozenset()
    post_logout_redirect_uris: frozenset[str] = frozenset()
    web_origins: frozenset[str] = frozenset()
    scopes: frozenset[Scope] = frozenset((Scope.OPENID,))
    client_type: ClientType = ClientType.CONFIDENTIAL
    token_endpoint_auth_method: str = _AUTH_METHOD_DEFAULT
    jwks_uri: str = ""
    jwks: str = ""
    tls_client_auth_subject_dn: str = ""
    tls_client_certificate_hash: str = ""
    requested_secret: str | None = None
    par_required: bool = False
    require_consent: bool = False
    id_token_signed_response_alg: str = ""
    id_token_encrypted_response_alg: str = ""
    id_token_encrypted_response_enc: str = ""


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
    serveur n'en conserve que l'empreinte SHA-256 (ou le chiffrement
    RSA-OAEP de la clé de scellement pour les méthodes HMAC).
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
    web_origins: list[str] = field(default_factory=list)
    jwks_uri: str = ""
    jwks: str = ""
    tls_client_auth_subject_dn: str = ""
    tls_client_certificate_hash: str = ""
    client_secret: str = ""
    registration_access_token: str = ""
    registration_client_uri: str = ""
    require_pushed_authorization_requests: bool = False
    require_consent: bool = False
    id_token_signed_response_alg: str = ""
    id_token_encrypted_response_alg: str = ""
    id_token_encrypted_response_enc: str = ""


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
    secret_ciphertext: str = ""


def hash_secret(value: str) -> str:
    """Calcule l'empreinte SHA-256 d'un secret ou jeton (jamais stocké en clair)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class RegistrationUseCase:
    """Crée et gère les clients enregistrés dynamiquement (RFC 7591 + 7592)."""

    def __init__(
        self,
        config: RegistrationConfig,
        client_repository: ClientRepository,
        scope_registry: ScopeRegistry | None = None,
        initial_access_authorizer: BearerClaimAuthorizer | None = None,
        secret_cipher: SecretCipher | None = None,
    ) -> None:
        """Injection de la configuration, des registres, de l'autoriseur initial et du chiffreur."""
        self._config = config
        self._clients = client_repository
        self._scope_registry = scope_registry
        self._initial_access_authorizer = initial_access_authorizer
        self._secret_cipher = secret_cipher

    async def _known_scopes(self) -> frozenset[str]:
        """Scopes acceptés à l'enregistrement (scopes standard si pas de registre)."""
        if self._scope_registry is None:
            return _STANDARD_SCOPES
        return await self._scope_registry.known_scope_names()

    async def register(self, request: RegisterRequest) -> ClientRegistration | RegistrationError:
        """Crée un client et retourne sa configuration complète (RFC 7591 §4)."""
        if not await self._authorise_initial(request.initial_access_token):
            return RegistrationError(
                "invalid_client",
                "Initial access token manquant ou invalide",
                401,
            )
        known = await self._known_scopes()
        metadata = _parse_metadata(request.metadata, known)
        if isinstance(metadata, RegistrationError):
            return metadata
        material_error = self._validate_method_material(metadata)
        if material_error is not None:
            return material_error
        usage_error = self._validate_jwks_usage(metadata)
        if usage_error is not None:
            return usage_error
        signing_error = self._validate_signing_material(metadata)
        if signing_error is not None:
            return signing_error
        encryption_error = self._validate_encryption_material(metadata)
        if encryption_error is not None:
            return encryption_error

        client_id = token_urlsafe(24)
        secret_hash, secret_ciphertext, client_secret = await self._credentials_for(metadata)
        registration_token = token_urlsafe(48)
        client = Client(
            client_id=client_id,
            redirect_uris=metadata.redirect_uris,
            post_logout_redirect_uris=metadata.post_logout_redirect_uris,
            web_origins=metadata.web_origins,
            scopes=metadata.scopes,
            client_type=metadata.client_type,
            client_secret_hash=secret_hash,
            client_secret_ciphertext=secret_ciphertext,
            registration_access_token_hash=hash_secret(registration_token),
            token_endpoint_auth_method=TokenEndpointAuthMethod(metadata.token_endpoint_auth_method),
            jwks_uri=metadata.jwks_uri,
            jwks=_keys_from_jwks_json(metadata.jwks),
            tls_client_auth_subject_dn=metadata.tls_client_auth_subject_dn,
            tls_client_certificate_hash=metadata.tls_client_certificate_hash,
            par_required=metadata.par_required,
            require_consent=metadata.require_consent,
            id_token_signed_response_alg=metadata.id_token_signed_response_alg,
            id_token_encrypted_response_alg=metadata.id_token_encrypted_response_alg,
            id_token_encrypted_response_enc=metadata.id_token_encrypted_response_enc,
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
        known = await self._known_scopes()
        metadata = _parse_metadata(request.metadata, known)
        if isinstance(metadata, RegistrationError):
            return metadata
        material_error = self._validate_method_material(metadata)
        if material_error is not None:
            return material_error
        usage_error = self._validate_jwks_usage(metadata)
        if usage_error is not None:
            return usage_error
        signing_error = self._validate_signing_material(metadata)
        if signing_error is not None:
            return signing_error
        encryption_error = self._validate_encryption_material(metadata)
        if encryption_error is not None:
            return encryption_error
        rotation_error = self._validate_signing_rotation(client, metadata)
        if rotation_error is not None:
            return rotation_error
        encryption_rotation = self._validate_encryption_rotation(client, metadata)
        if encryption_rotation is not None:
            return encryption_rotation

        rotation = await self._updated_credentials(client, metadata)
        if isinstance(rotation, RegistrationError):
            return rotation
        updated = Client(
            client_id=client.client_id,
            redirect_uris=metadata.redirect_uris,
            post_logout_redirect_uris=metadata.post_logout_redirect_uris,
            web_origins=metadata.web_origins,
            scopes=metadata.scopes,
            client_type=metadata.client_type,
            client_secret_hash=rotation.secret_hash,
            client_secret_ciphertext=rotation.secret_ciphertext,
            registration_access_token_hash=client.registration_access_token_hash,
            token_endpoint_auth_method=TokenEndpointAuthMethod(metadata.token_endpoint_auth_method),
            jwks_uri=metadata.jwks_uri,
            jwks=_keys_from_jwks_json(metadata.jwks),
            tls_client_auth_subject_dn=metadata.tls_client_auth_subject_dn,
            tls_client_certificate_hash=metadata.tls_client_certificate_hash,
            created_at=client.created_at,
            is_active=client.is_active,
            session_lifetime_seconds=client.session_lifetime_seconds,
            access_token_lifetime_seconds=client.access_token_lifetime_seconds,
            authorization_code_lifetime_seconds=client.authorization_code_lifetime_seconds,
            refresh_token_lifetime_seconds=client.refresh_token_lifetime_seconds,
            device_code_lifetime_seconds=client.device_code_lifetime_seconds,
            device_code_interval_seconds=client.device_code_interval_seconds,
            par_required=metadata.par_required,
            require_consent=metadata.require_consent,
            id_token_signed_response_alg=metadata.id_token_signed_response_alg,
            id_token_encrypted_response_alg=metadata.id_token_encrypted_response_alg,
            id_token_encrypted_response_enc=metadata.id_token_encrypted_response_enc,
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

    def _validate_method_material(self, metadata: RegistrationMetadata) -> RegistrationError | None:
        """Vérifie que le matériel requis par la méthode d'auth est présent (RFC 7591 §2.3)."""
        method = metadata.token_endpoint_auth_method
        if method == "client_secret_jwt" and self._secret_cipher is None:
            return RegistrationError(
                "invalid_client_metadata",
                "client_secret_jwt exige un chiffreur de secrets disponible "
                "(clé de scellement KeyUse.SECRET)",
            )
        if method == "private_key_jwt" and not (metadata.jwks or metadata.jwks_uri):
            return RegistrationError(
                "invalid_client_metadata",
                "private_key_jwt exige jwks ou jwks_uri",
            )
        if method in _TLS_KEY_AUTH_METHODS and not (
            metadata.tls_client_auth_subject_dn or metadata.tls_client_certificate_hash
        ):
            return RegistrationError(
                "invalid_client_metadata",
                f"{method} exige tls_client_auth_subject_dn ou tls_client_certificate",
            )
        return None

    def _validate_signing_material(
        self, metadata: RegistrationMetadata
    ) -> RegistrationError | None:
        """Vérifie que la signature d'``id_token`` demandée est réalisable (OIDC §3.1.3.7)."""
        if metadata.id_token_signed_response_alg not in _SYMMETRIC_SIGNING_VALUES:
            return None
        if metadata.token_endpoint_auth_method in _KEYLESS_AUTH_METHODS:
            return RegistrationError(
                "invalid_client_metadata",
                "Un algorithme symétrique HS* signe l'id_token avec le secret partagé : "
                "la méthode d'authentification doit produire un secret client",
            )
        if self._secret_cipher is None:
            return RegistrationError(
                "invalid_client_metadata",
                "Un algorithme symétrique HS* exige un chiffreur de secrets disponible "
                "(clé de scellement KeyUse.SECRET)",
            )
        return None

    def _validate_signing_rotation(
        self, client: Client, metadata: RegistrationMetadata
    ) -> RegistrationError | None:
        """Vérifie qu'un passage vers HS* du client courant est réalisable (RFC 7592 §3)."""
        if metadata.id_token_signed_response_alg not in _SYMMETRIC_SIGNING_VALUES:
            return None
        method = metadata.token_endpoint_auth_method
        if method in ("client_secret_basic", "client_secret_post"):
            if not client.client_secret_ciphertext and metadata.requested_secret is None:
                return RegistrationError(
                    "invalid_client_metadata",
                    "Passage vers un algorithme HS* : le secret du client n'étant pas "
                    "conservé, fournir un nouveau client_secret",
                )
            if metadata.requested_secret is not None and (
                hash_secret(metadata.requested_secret) == client.client_secret_hash
                and not client.client_secret_ciphertext
            ):
                return RegistrationError(
                    "invalid_client_metadata",
                    "Passage vers un algorithme HS* : fournir un nouveau client_secret "
                    "(le secret actuel n'est pas récupérable)",
                )
        return None

    def _validate_encryption_material(
        self, metadata: RegistrationMetadata
    ) -> RegistrationError | None:
        """Vérifie que le chiffrement JWE d'``id_token`` demandé est réalisable (§3.1.3.6)."""
        algorithm = metadata.id_token_encrypted_response_alg
        method = metadata.id_token_encrypted_response_enc
        if not algorithm and not method:
            return None
        if not algorithm:
            return RegistrationError(
                "invalid_client_metadata",
                "id_token_encrypted_response_enc exige id_token_encrypted_response_alg",
            )
        if method and method not in _METHOD_ENCRYPTION_VALUES:
            return RegistrationError(
                "invalid_client_metadata",
                "id_token_encrypted_response_enc non supporté (attendu une méthode JWE)",
            )
        if algorithm in _ASYMMETRIC_ENCRYPTION_VALUES:
            problem = require_encryption_rsa_key(_keys_from_jwks_json(metadata.jwks))
            if problem:
                return RegistrationError("invalid_client_metadata", problem)
            return None
        if algorithm not in _ALGORITHM_ENCRYPTION_VALUES:
            return RegistrationError(
                "invalid_client_metadata",
                "id_token_encrypted_response_alg non supporté (attendu un algorithme JWE)",
            )
        if metadata.token_endpoint_auth_method in _KEYLESS_AUTH_METHODS:
            return RegistrationError(
                "invalid_client_metadata",
                "Un algorithme symétrique chiffre l'id_token avec le secret partagé : "
                "la méthode d'authentification doit produire un secret client",
            )
        if self._secret_cipher is None:
            return RegistrationError(
                "invalid_client_metadata",
                "Un algorithme symétrique exige un chiffreur de secrets disponible "
                "(clé de scellement KeyUse.SECRET)",
            )
        return None

    def _validate_encryption_rotation(
        self, client: Client, metadata: RegistrationMetadata
    ) -> RegistrationError | None:
        """Vérifie qu'un passage vers un chiffrement symétrique est réalisable (§3.1.3.6)."""
        if metadata.id_token_encrypted_response_alg not in _SYMMETRIC_ENCRYPTION_VALUES:
            return None
        method = metadata.token_endpoint_auth_method
        if method in ("client_secret_basic", "client_secret_post"):
            if not client.client_secret_ciphertext and metadata.requested_secret is None:
                return RegistrationError(
                    "invalid_client_metadata",
                    "Passage vers un chiffrement symétrique : le secret du client "
                    "n'étant pas conservé, fournir un nouveau client_secret",
                )
            if metadata.requested_secret is not None and (
                hash_secret(metadata.requested_secret) == client.client_secret_hash
                and not client.client_secret_ciphertext
            ):
                return RegistrationError(
                    "invalid_client_metadata",
                    "Passage vers un chiffrement symétrique : fournir un nouveau "
                    "client_secret (le secret actuel n'est pas récupérable)",
                )
        return None

    @staticmethod
    def _validate_jwks_usage(metadata: RegistrationMetadata) -> RegistrationError | None:
        """Vérifie la conformité d'usage du JWKS embarqué avec la méthode d'auth."""
        if (
            metadata.token_endpoint_auth_method != TokenEndpointAuthMethod.PRIVATE_KEY_JWT.value
            or not metadata.jwks
            or metadata.jwks_uri
        ):
            return None
        problem = require_signing_key(_keys_from_jwks_json(metadata.jwks))
        if problem:
            return RegistrationError("invalid_client_metadata", problem)
        return None

    async def _credentials_for(self, metadata: RegistrationMetadata) -> tuple[str, str, str]:
        """Génère et prépare le secret client (empreinte, chiffrement, valeur émise)."""
        method = metadata.token_endpoint_auth_method
        needs_seal = (
            method == "client_secret_jwt"
            or metadata.id_token_signed_response_alg in _SYMMETRIC_SIGNING_VALUES
            or metadata.id_token_encrypted_response_alg in _SYMMETRIC_ENCRYPTION_VALUES
        )
        if needs_seal:
            secret = token_urlsafe(48)
            ciphertext = await self._secret_cipher.encrypt(secret)  # type: ignore[union-attr]  # validé par _validate_method_material/_validate_signing_material
            if method == "client_secret_jwt":
                return "", ciphertext, secret
            return hash_secret(secret), ciphertext, secret
        if method in ("client_secret_basic", "client_secret_post"):
            secret = token_urlsafe(48)
            return hash_secret(secret), "", secret
        return "", "", ""

    async def _updated_credentials(
        self, client: Client, metadata: RegistrationMetadata
    ) -> _SecretRotation | RegistrationError:
        """Détermine la rotation de secret selon la méthode ; secret jamais ré-émis."""
        method = metadata.token_endpoint_auth_method
        if method in _KEYLESS_AUTH_METHODS:
            return _SecretRotation("", "")
        if method == "client_secret_jwt":
            return await self._rotate_jwt_secret(client, metadata)
        needs_seal = (
            metadata.id_token_signed_response_alg in _SYMMETRIC_SIGNING_VALUES
            or metadata.id_token_encrypted_response_alg in _SYMMETRIC_ENCRYPTION_VALUES
        )
        if metadata.requested_secret is not None:
            requested_hash = hash_secret(metadata.requested_secret)
            if requested_hash == client.client_secret_hash and client.client_secret_ciphertext:
                ciphertext = await self._recover_ciphertext(client, needs_seal)
                return _SecretRotation(client.client_secret_hash, "", ciphertext)
            ciphertext = await self._seal_secret(needs_seal, metadata.requested_secret)
            return _SecretRotation(requested_hash, metadata.requested_secret, ciphertext)
        if client.client_secret_hash:
            ciphertext = await self._recover_ciphertext(client, needs_seal)
            return _SecretRotation(client.client_secret_hash, "", ciphertext)
        generated = token_urlsafe(48)
        ciphertext = await self._seal_secret(needs_seal, generated)
        return _SecretRotation(hash_secret(generated), generated, ciphertext)

    async def _seal_secret(self, needs_seal: bool, value: str) -> str:
        """Chiffre ``value`` sous la clé de scellement si la signature HS* l'exige."""
        if not needs_seal or self._secret_cipher is None:
            return ""
        return await self._secret_cipher.encrypt(value)

    async def _recover_ciphertext(self, client: Client, needs_seal: bool) -> str:
        """Retourne le secret chiffré courant, re-scellé si la clé a tourné (drain)."""
        if not needs_seal or not client.client_secret_ciphertext or self._secret_cipher is None:
            return client.client_secret_ciphertext if not needs_seal else ""
        if not await self._secret_cipher.is_current(client.client_secret_ciphertext):
            return await self._secret_cipher.reencrypt(client.client_secret_ciphertext)
        return client.client_secret_ciphertext

    async def _rotate_jwt_secret(
        self, client: Client, metadata: RegistrationMetadata
    ) -> _SecretRotation:
        """Fait tourner le secret HMAC chiffré (RFC 7592 §3, méthode ``client_secret_jwt``).

        Un nouveau ``client_secret`` fourni est chiffré avec la clé la plus
        récente du trousseau et émis une seule fois. Sans valeur fournie, le
        secret courant est **conservé** ; s'il était chiffré sous une clé
        sortante, son chiffré est re-scellé sous la clé la plus récente
        (drain de la rotation de la clé de scellement).
        """
        if self._secret_cipher is None:
            return _SecretRotation("", "")
        if metadata.requested_secret is not None:
            ciphertext = await self._secret_cipher.encrypt(metadata.requested_secret)
            return _SecretRotation("", metadata.requested_secret, ciphertext)
        if not client.client_secret_ciphertext:
            return _SecretRotation("", "")
        if not await self._secret_cipher.is_current(client.client_secret_ciphertext):
            ciphertext = await self._secret_cipher.reencrypt(client.client_secret_ciphertext)
            return _SecretRotation("", "", ciphertext)
        return _SecretRotation("", "", client.client_secret_ciphertext)

    async def _authorise_initial(self, token: str) -> bool:
        """Autorise la création selon le mode configuré (RFC 7591 §4.1).

        - ``disabled`` : aucune autorisation ;
        - ``jwt`` : le Bearer doit être un JWT valide portant le claim
          configuré (vérifié par l'autoriseur injecté) ;
        - ``static`` : le Bearer doit correspondre à un initial access token
          haché de la configuration (comportement historique).
        """
        mode = self._config.initial_access_token_mode
        if mode == "disabled":
            return True
        if mode == "jwt":
            if not token or self._initial_access_authorizer is None:
                return False
            return await self._initial_access_authorizer.authorise(token)
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
        if client.token_endpoint_auth_method is not None:
            auth_method = client.token_endpoint_auth_method.value
        elif client.client_type is ClientType.PUBLIC:
            auth_method = "none"
        else:
            auth_method = "client_secret_basic"
        return ClientRegistration(
            client_id=client.client_id,
            client_id_issued_at=int(client.created_at.timestamp()),
            client_type=client.client_type,
            token_endpoint_auth_method=auth_method,
            scope=" ".join(sorted(scope.value for scope in client.scopes)),
            redirect_uris=sorted(client.redirect_uris),
            post_logout_redirect_uris=sorted(client.post_logout_redirect_uris),
            web_origins=sorted(client.web_origins),
            jwks_uri=client.jwks_uri,
            jwks=_jwks_json(client.jwks),
            tls_client_auth_subject_dn=client.tls_client_auth_subject_dn,
            tls_client_certificate_hash=client.tls_client_certificate_hash,
            client_secret=client_secret,
            registration_access_token=registration_access_token,
            registration_client_uri=f"{self._base_url()}/register/{client.client_id}",
            require_pushed_authorization_requests=client.par_required,
            require_consent=client.require_consent,
            id_token_signed_response_alg=client.id_token_signed_response_alg,
            id_token_encrypted_response_alg=client.id_token_encrypted_response_alg,
            id_token_encrypted_response_enc=client.id_token_encrypted_response_enc,
        )

    def _base_url(self) -> str:
        """URL de base du serveur (raccourci de discovery ou issuer)."""
        return (self._config.base_url or self._config.issuer).rstrip("/")


def _parse_metadata(
    raw: object, known_scopes: frozenset[str]
) -> RegistrationMetadata | RegistrationError:
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
    web_origins = _parse_web_origins(raw)
    if isinstance(web_origins, RegistrationError):
        return web_origins
    extras = _parse_metadata_extras(raw, known_scopes)
    if isinstance(extras, RegistrationError):
        return extras
    (
        scopes,
        auth_method,
        requested_secret,
        par_required,
        require_consent,
        jwks_uri,
        jwks,
        tls_subject_dn,
        tls_certificate_hash,
        id_token_signing_alg,
        id_token_encryption_alg,
        id_token_encryption_enc,
    ) = extras

    client_type = ClientType.PUBLIC if auth_method == "none" else ClientType.CONFIDENTIAL
    return RegistrationMetadata(
        redirect_uris=redirect_uris,
        post_logout_redirect_uris=post_logout_uris,
        web_origins=web_origins,
        scopes=scopes,
        client_type=client_type,
        token_endpoint_auth_method=auth_method,
        jwks_uri=jwks_uri,
        jwks=jwks,
        tls_client_auth_subject_dn=tls_subject_dn,
        tls_client_certificate_hash=tls_certificate_hash,
        requested_secret=requested_secret,
        par_required=par_required,
        require_consent=require_consent,
        id_token_signed_response_alg=id_token_signing_alg,
        id_token_encrypted_response_alg=id_token_encryption_alg,
        id_token_encrypted_response_enc=id_token_encryption_enc,
    )


_MetadataParser = Callable[[dict[str, object], frozenset[str]], object]


def _parse_metadata_extras(
    raw: dict[str, object], known_scopes: frozenset[str]
) -> (
    tuple[
        frozenset[Scope],
        str,
        str | None,
        bool,
        bool,
        str,
        str,
        str,
        str,
        str,
        str,
        str,
    ]
    | RegistrationError
):
    """Valide scopes, méthode d'authentification, matériel de clé et exigences (RFC 7591 §2).

    Chaque membre est passé à son parseur ; le premier rejet (ou la
    première erreur) est renvoyé tel quel. ``grant_types`` et
    ``response_types`` sont bornés au périmètre maîtrisé du registre
    (``authorization_code``/``code``) : seule leur validité est vérifiée,
    la valeur étant imposée par le serveur.
    """
    parsers: tuple[tuple[str, _MetadataParser], ...] = (
        ("scopes", _parse_scopes),
        ("auth_method", lambda raw, _known: _parse_auth_method(raw)),
        (
            "grant_types",
            lambda raw, _known: _parse_members(
                raw, "grant_types", _ALLOWED_GRANT_TYPES, "authorization_code"
            ),
        ),
        (
            "response_types",
            lambda raw, _known: _parse_members(
                raw, "response_types", _ALLOWED_RESPONSE_TYPES, "code"
            ),
        ),
        ("requested_secret", lambda raw, _known: _parse_requested_secret(raw)),
        ("par_required", lambda raw, _known: _parse_par_required(raw)),
        ("require_consent", lambda raw, _known: _parse_require_consent(raw)),
        ("jwks_uri", lambda raw, _known: _parse_jwks_uri(raw)),
        ("jwks", lambda raw, _known: _parse_jwks(raw)),
        ("tls_subject_dn", lambda raw, _known: _parse_tls_subject_dn(raw)),
        ("tls_certificate_hash", lambda raw, _known: _parse_tls_certificate(raw)),
        ("id_token_signing_alg", lambda raw, _known: _parse_id_token_signing_alg(raw)),
        ("id_token_encryption_alg", lambda raw, _known: _parse_id_token_encryption_alg(raw)),
        ("id_token_encryption_enc", lambda raw, _known: _parse_id_token_encryption_enc(raw)),
    )
    results: dict[str, object] = {}
    for name, parser in parsers:
        value = parser(raw, known_scopes)
        if isinstance(value, RegistrationError):
            return value
        results[name] = value
    return _assemble_extras(results)


def _assemble_extras(
    results: dict[str, object],
) -> tuple[frozenset[Scope], str, str | None, bool, bool, str, str, str, str, str, str, str]:
    """Recompose le tuple de métadonnées extraites (types garantis par les parseurs)."""
    return (
        cast(frozenset[Scope], results["scopes"]),
        cast(str, results["auth_method"]),
        cast(str | None, results["requested_secret"]),
        cast(bool, results["par_required"]),
        cast(bool, results["require_consent"]),
        cast(str, results["jwks_uri"]),
        cast(str, results["jwks"]),
        cast(str, results["tls_subject_dn"]),
        cast(str, results["tls_certificate_hash"]),
        cast(str, results["id_token_signing_alg"]),
        cast(str, results["id_token_encryption_alg"]),
        cast(str, results["id_token_encryption_enc"]),
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


def _parse_web_origins(raw: dict[str, object]) -> frozenset[str] | RegistrationError:
    """Lit ``web_origins`` (RFC 7591 §2.1, OAuth 2.0 for Browser-Based Apps).

    Chaque origine doit être un schéma http(s) + autorité (path optionnel
    vide ou ``/``, sans query ni fragment) ; les origines sont normalisées
    (ports par défaut élidés) avant stockage.
    """
    value = raw.get("web_origins")
    if value is None:
        return frozenset()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return RegistrationError(
            "invalid_client_metadata", "web_origins doit être une liste de chaînes"
        )
    for origin in value:
        if not _is_web_origin(origin):
            return RegistrationError(
                "invalid_redirect_uri", f"web_origins contient une origine invalide : {origin}"
            )
    origins = [origin_of_uri(o) for o in value]
    return frozenset(origin for origin in origins if origin is not None)


def _is_web_origin(uri: str) -> bool:
    """Vérifie qu'une valeur désigne bien une origine web (pas un chemin, ni query/fragment)."""
    parsed = urlsplit(uri)
    if parsed.scheme not in ({"http", "https"}) or not parsed.netloc:
        return False
    return parsed.path in ("", "/") and parsed.query == "" and parsed.fragment == ""


def _parse_scopes(
    raw: dict[str, object], known_scopes: frozenset[str]
) -> frozenset[Scope] | RegistrationError:
    """Valide le scope (chaîne espacée) contre les scopes connus du serveur."""
    value = raw.get("scope")
    if value is None or value == "":
        return frozenset((Scope.OPENID,))
    if not isinstance(value, str):
        return RegistrationError("invalid_client_metadata", "scope doit être une chaîne")
    tokens = value.split()
    unknown = [token for token in tokens if token not in known_scopes]
    if unknown:
        return RegistrationError(
            "invalid_client_metadata",
            "scope(s) non enregistré(s) : " + ", ".join(sorted(unknown)),
        )
    return frozenset(Scope(token) for token in tokens)


def _parse_auth_method(raw: dict[str, object]) -> str | RegistrationError:
    """Valide la méthode d'authentification du client (RFC 7591 §2.1)."""
    value = raw.get("token_endpoint_auth_method")
    if value is None:
        return "client_secret_basic"
    if not isinstance(value, str) or value not in _ALLOWED_AUTH_METHODS:
        return RegistrationError(
            "invalid_client_metadata",
            "token_endpoint_auth_method non supporté (attendu : "
            + ", ".join(sorted(_ALLOWED_AUTH_METHODS)),
        )
    return value


def _parse_id_token_signing_alg(raw: dict[str, object]) -> str | RegistrationError:
    """Lit ``id_token_signed_response_alg`` (OIDC Core §3.1.3.7, RFC 7591 §2.1).

    Vide par défaut (algorithme principal du serveur) ; toute autre valeur
    doit être un algorithme JWS supporté (RS*/PS*/ES*/HS*, jamais
    ``none``, ni un algorithme JWE).
    """
    value = raw.get("id_token_signed_response_alg")
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or value not in JWTAlgorithm._value2member_map_:
        return RegistrationError(
            "invalid_client_metadata",
            "id_token_signed_response_alg non supporté (attendu un algorithme JWS)",
        )
    return value


def _parse_id_token_encryption_alg(raw: dict[str, object]) -> str | RegistrationError:
    """Lit ``id_token_encrypted_response_alg`` (OIDC Core §3.1.3.6, RFC 7591 §2.1).

    Vide par défaut (id_token non chiffré) ; toute autre valeur doit être un
    algorithme de gestion de clé JWE supporté (RSA-OAEP*, A*KW, ``dir``).
    """
    value = raw.get("id_token_encrypted_response_alg")
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or value not in _ALGORITHM_ENCRYPTION_VALUES:
        return RegistrationError(
            "invalid_client_metadata",
            "id_token_encrypted_response_alg non supporté (attendu un algorithme JWE)",
        )
    return value


def _parse_id_token_encryption_enc(raw: dict[str, object]) -> str | RegistrationError:
    """Lit ``id_token_encrypted_response_enc`` (OIDC Core §3.1.3.6, RFC 7591 §2.1).

    Vide par défaut (le serveur applique sa méthode par défaut, ex.
    ``A128CBC-HS256``) ; toute autre valeur doit être une méthode JWE
    supportée (``A*CBC-HS*``, ``A*GCM``).
    """
    value = raw.get("id_token_encrypted_response_enc")
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or value not in _METHOD_ENCRYPTION_VALUES:
        return RegistrationError(
            "invalid_client_metadata",
            "id_token_encrypted_response_enc non supporté (attendu une méthode JWE)",
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


def _parse_bool_flag(
    raw: dict[str, object], key: str, *, default: bool
) -> bool | RegistrationError:
    """Lit un drapeau booléen de métadonnées client (défaut si absent)."""
    value = raw.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        return RegistrationError(
            "invalid_client_metadata",
            f"{key} doit être un booléen",
        )
    return value


def _parse_par_required(raw: dict[str, object]) -> bool | RegistrationError:
    """Lit ``require_pushed_authorization_requests`` (RFC 9126 §5.2, par défaut false)."""
    return _parse_bool_flag(raw, "require_pushed_authorization_requests", default=False)


def _parse_require_consent(raw: dict[str, object]) -> bool | RegistrationError:
    """Lit ``require_consent`` (OIDC Core 1.0 §3.1.2.2, par défaut false).

    Drapeau d'extension PurIdentityServer : contraint la demande
    d'autorisation à passer par l'écran de consentement de l'utilisateur
    connecté avant d'émettre le moindre code ou jeton.
    """
    return _parse_bool_flag(raw, "require_consent", default=False)


def _parse_jwks_uri(raw: dict[str, object]) -> str | RegistrationError:
    """Lit ``jwks_uri`` (RFC 7591 §2.1, RFC 7523 §2.2) — https, loopback http accepté."""
    value = raw.get("jwks_uri")
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or not _is_jwks_uri(value):
        return RegistrationError(
            "invalid_client_metadata", "jwks_uri doit être une URI http(s) sans fragment"
        )
    return value


def _is_jwks_uri(uri: str) -> bool:
    """Vérifie qu'une ``jwks_uri`` est https (ou http loopback, pour le dev local)."""
    parsed = urlsplit(uri)
    if parsed.scheme not in ({"http", "https"}) or not parsed.netloc or parsed.fragment:
        return False
    if parsed.scheme == "https":
        return True
    host = parsed.hostname or ""
    return host in {"localhost", "127.0.0.1", "::1"}


def _parse_jwks(raw: dict[str, object]) -> str | RegistrationError:
    """Lit ``jwks`` (RFC 7591 §2.1) : objet JSON avec une liste ``keys``, normalisé compact."""
    value = raw.get("jwks")
    if value is None:
        return ""
    if not isinstance(value, dict):
        return RegistrationError(
            "invalid_client_metadata", "jwks doit être un objet JSON (JWK Set)"
        )
    keys = value.get("keys")
    if not isinstance(keys, list) or not all(isinstance(key, dict) for key in keys):
        return RegistrationError(
            "invalid_client_metadata", "jwks doit porter une liste keys de JWK"
        )
    problems = validate_client_jwks(cast(tuple[dict[str, object], ...], tuple(keys)))
    if problems:
        return RegistrationError("invalid_client_metadata", problems[0])
    return json.dumps({"keys": keys}, separators=(",", ":"), sort_keys=True)


def _keys_from_jwks_json(jwks: str) -> tuple[dict[str, object], ...]:
    """Dé-sérialise le JWKS compact normalisé en tuple de clés (pour le domaine Client)."""
    if not jwks:
        return ()
    keys = json.loads(jwks).get("keys", [])
    return tuple(dict(key) for key in keys)


def _jwks_json(keys: tuple[dict[str, object], ...]) -> str:
    """Sérialise les clés du client en JWKS JSON compact (écho à la registration)."""
    if not keys:
        return ""
    return json.dumps({"keys": list(keys)}, separators=(",", ":"), sort_keys=True)


def _parse_tls_subject_dn(raw: dict[str, object]) -> str | RegistrationError:
    """Lit ``tls_client_auth_subject_dn`` (RFC 8705 §2.1.1) — chaîne DN non vide."""
    value = raw.get("tls_client_auth_subject_dn")
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        return RegistrationError(
            "invalid_client_metadata", "tls_client_auth_subject_dn doit être une chaîne"
        )
    return value


def _parse_tls_certificate(raw: dict[str, object]) -> str | RegistrationError:
    """Lit ``tls_client_certificate`` (RFC 8705 §2.1.2) et en dérive l'empreinte.

    Seule l'empreinte base64url(SHA-256) du certificat est conservée : le
    serveur la compare à celle du certificat présenté à chaque usage du
    token endpoint (RFC 8705 §2.1.2, hash alg SH-256).
    """
    value = raw.get("tls_client_certificate")
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        return RegistrationError(
            "invalid_client_metadata", "tls_client_certificate doit être une chaîne base64"
        )
    try:
        der = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return RegistrationError(
            "invalid_client_metadata", "tls_client_certificate n'est pas du base64 valide"
        )
    if not der:
        return RegistrationError(
            "invalid_client_metadata", "tls_client_certificate ne contient aucun octet"
        )
    return der_certificate_hash(der)
