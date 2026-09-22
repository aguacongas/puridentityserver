"""Configuration de l'infrastructure (variable d'environnement, .env, config.toml)."""

import os
from functools import cached_property
from hashlib import sha256
from pathlib import Path
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import (
    BaseSettings,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

from puridentityserver.domain.api_resource import ApiResource
from puridentityserver.domain.authorization import (
    Client,
    ClientType,
    Scope,
    TokenEndpointAuthMethod,
    origin_of_uri,
)
from puridentityserver.domain.identity_resource import (
    DEFAULT_IDENTITY_RESOURCES,
    IdentityResource,
)
from puridentityserver.domain.jwks import ALL_SIGNING_ALGORITHMS, JWTAlgorithm

_STORAGE_TYPES = ("memory", "sql")

# Rôles de déploiement : `full` (tout), `protocol` (OIDC/OAuth seul),
# `admin` (gestion des resources seul, sans endpoints de protocole).
_ROLES = ("full", "protocol", "admin")

# Modes d'autorisation de la création de client (RFC 7591 §4.1).
_REGISTRATION_INITIAL_ACCESS_TOKEN_MODES = ("static", "jwt", "disabled")

_SETTINGS_FILE_ENV = "PURIDENTITYSERVER_SETTINGS_FILE"


def _hash_client_secret(secret: str) -> str:
    """Calcule l'empreinte SHA-256 du secret client (jamais stocké en clair)."""
    return sha256(secret.encode("utf-8")).hexdigest()


def _optional_int(raw: dict[str, object], key: str) -> int | None:
    """Lit un entier facultatif de la configuration d'un client (ou ``None``)."""
    value = raw.get(key)
    return int(str(value)) if value is not None else None


def _parse_client(raw: dict[str, object]) -> Client:
    """Convertit un dictionnaire de configuration en Client domaine."""
    client_id = str(raw["client_id"])
    secret = str(raw.get("client_secret", ""))
    redirect_raw = raw.get("redirect_uris", ())
    if isinstance(redirect_raw, (list, tuple)):
        redirect_uris = frozenset(str(uri) for uri in redirect_raw)
    else:
        redirect_uris = frozenset()
    logout_redirect_raw = raw.get("post_logout_redirect_uris", ())
    if isinstance(logout_redirect_raw, (list, tuple)):
        post_logout_redirect_uris = frozenset(str(uri) for uri in logout_redirect_raw)
    else:
        post_logout_redirect_uris = frozenset()
    web_origins_raw = raw.get("web_origins", ())
    if isinstance(web_origins_raw, (list, tuple)):
        web_origins = frozenset(
            origin for origin in map(origin_of_uri, map(str, web_origins_raw)) if origin is not None
        )
    else:
        web_origins = frozenset()
    scopes = frozenset(Scope(token) for token in str(raw.get("scopes", "openid")).split() if token)
    client_type = _parse_client_type(raw.get("client_type", "public"))
    auth_method = _parse_auth_method(raw)
    jwks_raw = raw.get("jwks")
    jwks = tuple(dict(key) for key in jwks_raw) if isinstance(jwks_raw, (list, tuple)) else ()
    return Client(
        client_id=client_id,
        redirect_uris=redirect_uris,
        post_logout_redirect_uris=post_logout_redirect_uris,
        web_origins=web_origins,
        scopes=scopes,
        client_type=client_type,
        client_secret_hash=_hash_client_secret(secret),
        client_secret_ciphertext=str(raw.get("client_secret_encrypted", "")),
        token_endpoint_auth_method=auth_method,
        jwks_uri=str(raw.get("jwks_uri", "")),
        jwks=jwks,
        tls_client_auth_subject_dn=str(raw.get("tls_client_auth_subject_dn", "")),
        tls_client_certificate_hash=str(raw.get("tls_client_certificate_hash", "")),
        id_token_signed_response_alg=str(raw.get("id_token_signed_response_alg", "")),
        session_lifetime_seconds=_optional_int(raw, "session_lifetime_seconds"),
        access_token_lifetime_seconds=_optional_int(raw, "access_token_lifetime_seconds"),
        authorization_code_lifetime_seconds=_optional_int(
            raw, "authorization_code_lifetime_seconds"
        ),
        refresh_token_lifetime_seconds=_optional_int(raw, "refresh_token_lifetime_seconds"),
        device_code_lifetime_seconds=_optional_int(raw, "device_code_lifetime_seconds"),
        device_code_interval_seconds=_optional_int(raw, "device_code_interval_seconds"),
        par_required=bool(raw.get("par_required")),
        require_consent=bool(raw.get("require_consent")),
    )


def _parse_auth_method(raw: dict[str, object]) -> TokenEndpointAuthMethod | None:
    """Résout la méthode d'authentification déclarée par un client seedé."""
    value = raw.get("token_endpoint_auth_method")
    if value is None:
        return None
    method = str(value)
    if method not in TokenEndpointAuthMethod._value2member_map_:
        raise ValueError(f"Méthode d'authentification non supportée : {method}")
    return TokenEndpointAuthMethod(method)


def _parse_client_type(raw: object) -> ClientType:
    """Résout le type de client déclaré dans la configuration."""
    value = str(raw)
    if value not in ClientType.__members__ and value not in ("confidential", "public"):
        raise ValueError(f"Type de client non supporté : {value}")
    return ClientType(value)


def _parse_identity_resource(raw: dict[str, object]) -> IdentityResource:
    """Convertit un dictionnaire de configuration en IdentityResource domaine."""
    claims_raw = raw.get("user_claims", ())
    if isinstance(claims_raw, (list, tuple)):
        user_claims = frozenset(str(claim) for claim in claims_raw)
    else:
        user_claims = frozenset()
    return IdentityResource(
        name=str(raw["name"]),
        display_name=str(raw.get("display_name", "")),
        user_claims=user_claims,
        show_in_discovery_document=bool(raw.get("show_in_discovery_document", True)),
    )


def _parse_api_resource(raw: dict[str, object]) -> ApiResource:
    """Convertit un dictionnaire de configuration en ApiResource domaine.

    Les scopes et les algorithmes de signature autorisés sont normalisés
    (triés, dédupliqués) ; un algorithme inconnu de ``JWTAlgorithm`` est
    rejeté (ValueError) pour garantir un jeton validable.
    """
    scopes_raw = raw.get("scopes", ())
    scopes = (
        frozenset(str(scope) for scope in scopes_raw)
        if isinstance(scopes_raw, (list, tuple))
        else frozenset()
    )
    algos_raw = raw.get("allowed_access_token_signing_algos", ())
    algos = tuple(str(algo) for algo in algos_raw) if isinstance(algos_raw, (list, tuple)) else ()
    unknown = [
        name
        for name in algos
        if name not in JWTAlgorithm.__members__ and name not in JWTAlgorithm._value2member_map_
    ]
    if unknown:
        raise ValueError(f"Algorithme(s) de signature non supportés : {', '.join(unknown)}")
    return ApiResource(
        name=str(raw["name"]),
        display_name=str(raw.get("display_name", "")),
        scopes=scopes,
        allowed_access_token_signing_algos=tuple(sorted(set(algos))),
    )


class Settings(BaseSettings):
    """Réglages du serveur, surchargeables via l'environnement (préfixe `PURIDENTITYSERVER_`)."""

    model_config = SettingsConfigDict(
        env_prefix="PURIDENTITYSERVER_", env_file=".env", extra="ignore"
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Surcharge la hiérarchie de sources avec le fichier `config.toml` du dépôt.

        La table `[settings]` du fichier fournit les valeurs par défaut du projet
        ; l'environnement (`PURIDENTITYSERVER_*`) reste prioritaire. Le chemin est
        surchargeable via `PURIDENTITYSERVER_SETTINGS_FILE`.
        """
        toml_path = Path(os.environ.get(_SETTINGS_FILE_ENV, "config.toml"))
        toml_settings = TomlConfigSettingsSource(
            settings_cls,
            toml_file=toml_path,
            toml_table_header=("settings",),
        )
        return (init_settings, env_settings, toml_settings, dotenv_settings, file_secret_settings)

    issuer: str = "http://127.0.0.1:8000"
    base_url: str = ""
    host: str = "127.0.0.1"
    port: int = 8000

    # Stockage de l'état persistant du serveur (clés de signature, clients,
    # codes d'autorisation, utilisateurs) : "memory" (monoprocess) ou "sql".
    storage_type: str = "memory"
    storage_dsn: str = "sqlite:///puridentityserver.db"

    # JWKS (RFC 7517)
    jwks_key_size: int = 4096
    jwks_algorithms: Annotated[tuple[str, ...], NoDecode] = tuple(
        algorithm.value for algorithm in ALL_SIGNING_ALGORITHMS
    )
    jwks_rotation_days: int = 90
    jwks_grace_period_days: int = 7

    # OAuth 2.0 / OIDC (RFC 6749, RFC 7636) — durées de vie par défaut du
    # serveur. Un client peut les surcharger via `access_token_lifetime_seconds`
    # et/ou `authorization_code_lifetime_seconds` dans `clients_seed`.
    # L'`id_token` et l'`access_token` partagent la même durée de vie.
    authorization_code_ttl_seconds: int = 600
    access_token_ttl_seconds: int = 3600
    refresh_token_ttl_seconds: int = 2592000

    # Device Authorization Grant (RFC 8628) — durée de vie du device code
    # (fenêtre pendant laquelle l'utilisateur peut autoriser l'appareil) et
    # intervalle minimal conseillé entre deux polls du client sur /token.
    device_code_ttl_seconds: int = 900
    device_code_interval_seconds: int = 5
    clients_seed: Annotated[tuple[dict[str, object], ...], NoDecode] = ()

    # UserInfo (OIDC Core §5.4) — seed du user store (`sub` -> claims)
    users_seed: Annotated[dict[str, dict[str, object]], NoDecode] = {}

    # IdentityResources (OIDC Core §5.4) — scopes identité et claims exposés.
    # Les resources par défaut de `DEFAULT_IDENTITY_RESOURCES` (openid,
    # profile, email, address, phone, offline_access) sont seedées quoi
    # qu'il arrive ; `identity_resources_seed` ajoute des resources
    # supplémentaires (un nom égal à un défaut surcharge celui-ci). Elles
    # alimentent `scopes_supported` / `claims_supported` du discovery et le
    # filtrage des claims de `/userinfo` par scope accordé.
    identity_resources_seed: Annotated[tuple[dict[str, object], ...], NoDecode] = ()

    # ApiResources (OAuth 2.0 — ressources protégées) — registre des
    # audiences API et de leurs scopes. Aucun scope non enregistré (ni
    # IdentityResource, ni scope d'ApiResource) n'est accepté aux endpoints
    # d'émission ; l'`aud` d'un access token porte le nom des resources
    # dont des scopes ont été accordés.
    # `api_resources_seed` ajoute des ressources au démarrage : name,
    # display_name, scopes (liste) et, facultativement,
    # allowed_access_token_signing_algos (restriction des algorithmes de
    # signature acceptables pour cette resource).
    api_resources_seed: Annotated[tuple[dict[str, object], ...], NoDecode] = ()

    # Dynamic Client Registration (RFC 7591 + 7592) — endpoint /register.
    # `registration_enabled` expose POST /register + GET/PUT/DELETE
    # /register/{client_id}. Si `requires_initial_access_token` est vrai, la
    # création exige un initial access token (Bearer) figurant dans
    # `registration_initial_access_tokens` (liste, sép. virgules) ; le
    # hash SHA-256 est comparé, jamais la valeur en clair.
    registration_enabled: bool = False
    registration_requires_initial_access_token: bool = True
    registration_initial_access_tokens: Annotated[tuple[str, ...], NoDecode] = ()

    # Secrets des méthodes HMAC (``client_secret_jwt`` et grant
    # ``jwt-bearer`` signés secret partagé) : chiffrement **au repos** avec
    # la clé de scellement de la famille ``KeyUse.SECRET`` — une clé RSA
    # générée automatiquement au démarrage, persisée dans le store
    # ``key_pair`` (comme les clés de signature/cookies) et qui tourne suivant
    # ``jwks_rotation_days``. Aucune clé à configurer ; les anciennes clés
    # ne sont **jamais purgées** (un secret est chiffré à vie) : retrait
    # manuel une fois le drain terminé.
    #
    # **Seed facultatif** : `client_secret_seal_key_pem` fournit la clé
    # privée RSA (PEM) à enregistrer au démarrage si aucune clé de
    # scellement n'existe encore — utile aux serveurs en mémoire
    # (déterminisme d'un redémarrage à l'autre).
    client_secret_seal_key_pem: str = ""

    # Séparation administration / protocole. `role` sélectionne les endpoints
    # montés : `full` (défaut) expose protocole + administration ; `protocol`
    # n'expose que les endpoints OIDC/OAuth ; `admin` n'expose que la gestion
    # des resources (CRUD `/identity-resources` et `/api-resources`). Deux
    # processus déployés séparément partagent le même état via `storage_type=sql`.
    role: str = "full"

    # Authentification JWT des endpoints de gestion (CRUD resources) et, en
    # mode `jwt`, de la création de client. Le JWT est validé contre l'issuer
    # de gestion (signature JWKS, `iss`, `exp`) puis un claim configurable est
    # exigé. `management_jwt_issuer` vide signifie « cet issuer » ; une valeur
    # différente (déploiement séparé) fait valider le jeton à distance via le
    # JWKS découvert sur cet issuer. `management_jwt_audience` vide désactive
    # le contrôle d'audience.
    management_jwt_issuer: str = ""
    management_jwt_jwks_url: str = ""
    management_jwt_audience: str = ""

    # Claim exigé pour les CRUD d'administration. `scope` (chaîne espacée) est
    # interprété comme une appartenance ; les autres claims sont comparés par
    # égalité (valeur unique ou liste). Une liste vide désactive la protection
    # (dérogation explicite : à réserver aux tests/mono-utilisateur).
    admin_required_claim: str = "scope"
    admin_required_claim_values: Annotated[tuple[str, ...], NoDecode] = ("admin",)

    # Mode d'autorisation de `POST /register` : `static` (défaut, initial
    # access tokens hachés de `registration_initial_access_tokens`), `jwt`
    # (Bearer JWT validé contre l'issuer de gestion + claim configurable
    # ci-dessous) ou `disabled` (aucune autorisation).
    registration_initial_access_token_mode: str = "static"  # ruff: ignore[hardcoded-password-string] (nom de mode, pas un secret)
    registration_required_claim: str = "scope"
    registration_required_claim_values: Annotated[tuple[str, ...], NoDecode] = ("register",)

    # Pushed Authorization Request (RFC 9126) — endpoint /par.
    # `par_enabled` expose POST /par. Le `request_uri` retourné est à usage
    # unique et expire au bout de `par_ttl_seconds` (5 ≤ durée ≤ 600, durée
    # recommandée 90) : plus courte que `authorization_code_ttl_seconds`, la
    # fenêtre limite le stockage des demandes poussées.
    par_enabled: bool = True
    par_ttl_seconds: int = 90

    # Identité (FastAPI Users, spike) — durée par défaut du cookie de session.
    # Le cookie est signé RS256 avec une clé rotative dédiée (KeyUse.SESSION,
    # jamais publiée) : ni secret statique, ni collision avec les clés de
    # signature des tokens OIDC. La durée effective peut être surchargée par
    # client via ``session_lifetime_seconds`` dans ``clients_seed``.
    identity_jwt_lifetime_seconds: int = 3600
    identity_seed_users: Annotated[dict[str, dict[str, str]], NoDecode] = {}

    @field_validator("jwks_algorithms", mode="before")
    @classmethod
    def _split_algorithms(cls, value: object) -> object:
        """Transforme `PURIDENTITYSERVER_JWKS_ALGORITHMS="RS256,ES256"` en tuple."""
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("registration_initial_access_tokens", mode="before")
    @classmethod
    def _split_initial_access_tokens(cls, value: object) -> object:
        """Transforme `PURIDENTITYSERVER_REGISTRATION_INITIAL_ACCESS_TOKENS` en tuple."""
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("admin_required_claim_values", mode="before")
    @classmethod
    def _split_admin_required_claim_values(cls, value: object) -> object:
        """Transforme `PURIDENTITYSERVER_ADMIN_REQUIRED_CLAIM_VALUES="admin,x"` en tuple."""
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("registration_required_claim_values", mode="before")
    @classmethod
    def _split_registration_required_claim_values(cls, value: object) -> object:
        """Transforme `PURIDENTITYSERVER_REGISTRATION_REQUIRED_CLAIM_VALUES` en tuple."""
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("clients_seed", mode="before")
    @classmethod
    def _parse_clients_seed(cls, value: object) -> object:
        """Transforme `PURIDENTITYSERVER_CLIENTS='[...]'` (JSON) en tuple de dicts."""
        if isinstance(value, str):
            import json

            parsed = json.loads(value)
            if not isinstance(parsed, list):
                raise ValueError("PURIDENTITYSERVER_CLIENTS doit être une liste JSON")
            return tuple(parsed)
        return value

    @field_validator("identity_resources_seed", mode="before")
    @classmethod
    def _parse_identity_resources_seed(cls, value: object) -> object:
        """Transforme `PURIDENTITYSERVER_IDENTITY_RESOURCES_SEED='[...]'` (JSON)."""
        if isinstance(value, str):
            import json

            parsed = json.loads(value)
            if not isinstance(parsed, list):
                raise ValueError(
                    "PURIDENTITYSERVER_IDENTITY_RESOURCES_SEED doit être une liste JSON"
                )
            return tuple(parsed)
        return value

    @field_validator("api_resources_seed", mode="before")
    @classmethod
    def _parse_api_resources_seed(cls, value: object) -> object:
        """Transforme `PURIDENTITYSERVER_API_RESOURCES_SEED='[...]'` (JSON)."""
        if isinstance(value, str):
            import json

            parsed = json.loads(value)
            if not isinstance(parsed, list):
                raise ValueError("PURIDENTITYSERVER_API_RESOURCES_SEED doit être une liste JSON")
            return tuple(parsed)
        return value

    @field_validator("users_seed", mode="before")
    @classmethod
    def _parse_users_seed(cls, value: object) -> object:
        """Transforme `PURIDENTITYSERVER_USERS_SEED='{...}'` (JSON) en dict."""
        if isinstance(value, str):
            import json

            parsed = json.loads(value)
            if not isinstance(parsed, dict):
                raise ValueError("PURIDENTITYSERVER_USERS_SEED doit être un objet JSON")
            return parsed
        return value

    @field_validator("identity_seed_users", mode="before")
    @classmethod
    def _parse_identity_seed_users(cls, value: object) -> object:
        """Transforme `PURIDENTITYSERVER_IDENTITY_SEED_USERS='{...}'` (JSON) en dict."""
        if isinstance(value, str):
            import json

            parsed = json.loads(value)
            if not isinstance(parsed, dict):
                raise ValueError("PURIDENTITYSERVER_IDENTITY_SEED_USERS doit être un objet JSON")
            return parsed
        return value

    @field_validator("storage_type")
    @classmethod
    def _validate_storage_type(cls, value: str) -> str:
        """Garantit que le type de stockage est supporté."""
        if value not in _STORAGE_TYPES:
            raise ValueError(f"Type de stockage non supporté : {value}")
        return value

    @field_validator("role")
    @classmethod
    def _validate_role(cls, value: str) -> str:
        """Garantit que le rôle de déploiement est supporté."""
        if value not in _ROLES:
            raise ValueError(f"Rôle non supporté : {value} (attendu : {', '.join(_ROLES)})")
        return value

    @field_validator("registration_initial_access_token_mode")
    @classmethod
    def _validate_registration_access_token_mode(cls, value: str) -> str:
        """Garantit que le mode d'autorisation de la registration est supporté."""
        if value not in _REGISTRATION_INITIAL_ACCESS_TOKEN_MODES:
            raise ValueError(
                f"Mode d'initial access token non supporté : {value} "
                f"(attendu : {', '.join(_REGISTRATION_INITIAL_ACCESS_TOKEN_MODES)})"
            )
        return value

    @field_validator("par_ttl_seconds")
    @classmethod
    def _validate_par_ttl(cls, value: int) -> int:
        """Garantit une durée de vie du request_uri dans la fenêtre 5-600 s (RFC 9126 §2)."""
        if not 5 <= value <= 600:
            raise ValueError("par_ttl_seconds doit être compris entre 5 et 600 secondes")
        return value

    @field_validator("jwks_algorithms")
    @classmethod
    def _validate_algorithms(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Garantit que chaque algorithme configuré est supporté."""
        unknown = [
            name
            for name in value
            if name not in JWTAlgorithm.__members__ and name not in JWTAlgorithm._value2member_map_
        ]
        if unknown:
            raise ValueError(f"Algorithmes de signature non supportés : {', '.join(unknown)}")
        return value

    @cached_property
    def jwks_signing_algorithms(self) -> tuple[JWTAlgorithm, ...]:
        """Algorithmes de signature résolus en membres JWTAlgorithm."""
        return tuple(JWTAlgorithm(name) for name in self.jwks_algorithms)

    @cached_property
    def seed_clients(self) -> tuple[Client, ...]:
        """Clients initiaux déclarés dans la configuration (seed au démarrage)."""
        return tuple(_parse_client(raw) for raw in self.clients_seed)

    @cached_property
    def seed_identity_resources(self) -> tuple[IdentityResource, ...]:
        """Resources de démarrage : défauts toujours seedés, config en sus.

        Les resources standard d'`DEFAULT_IDENTITY_RESOURCES` sont toujours
        présentes ; chaque entrée d'`identity_resources_seed` ajoute une
        resource (un nom déjà porté par un défaut le surcharge, en
        conservant sa position).
        """
        by_name = {resource.name: resource for resource in DEFAULT_IDENTITY_RESOURCES}
        for raw in self.identity_resources_seed:
            resource = _parse_identity_resource(raw)
            by_name[resource.name] = resource
        return tuple(by_name.values())

    @cached_property
    def seed_api_resources(self) -> tuple[ApiResource, ...]:
        """Resources protégées de démarrage, déclarées dans la configuration."""
        return tuple(_parse_api_resource(raw) for raw in self.api_resources_seed)

    @cached_property
    def registration_initial_access_token_hashes(self) -> frozenset[str]:
        """Empreintes SHA-256 des initial access tokens seedés (jamais en clair)."""
        return frozenset(
            _hash_client_secret(token) for token in self.registration_initial_access_tokens
        )

    @cached_property
    def management_issuer(self) -> str:
        """Issuer de confiance des jetons de gestion (défaut : l'issuer du serveur)."""
        return self.management_jwt_issuer or self.issuer

    @cached_property
    def admin_protected(self) -> bool:
        """Vrai si les CRUD d'administration exigent un JWT à claim configurable."""
        return bool(self.admin_required_claim_values)
