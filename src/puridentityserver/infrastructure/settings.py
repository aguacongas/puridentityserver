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

from puridentityserver.domain.authorization import Client, ClientType, Scope
from puridentityserver.domain.jwks import ALL_SIGNING_ALGORITHMS, JWTAlgorithm

_KEY_STORE_TYPES = ("memory", "sql")

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
    scopes = frozenset(Scope(token) for token in str(raw.get("scopes", "openid")).split() if token)
    client_type = _parse_client_type(raw.get("client_type", "public"))
    return Client(
        client_id=client_id,
        redirect_uris=redirect_uris,
        scopes=scopes,
        client_type=client_type,
        client_secret_hash=_hash_client_secret(secret),
        session_lifetime_seconds=_optional_int(raw, "session_lifetime_seconds"),
        access_token_lifetime_seconds=_optional_int(raw, "access_token_lifetime_seconds"),
        authorization_code_lifetime_seconds=_optional_int(
            raw, "authorization_code_lifetime_seconds"
        ),
    )


def _parse_client_type(raw: object) -> ClientType:
    """Résout le type de client déclaré dans la configuration."""
    value = str(raw)
    if value not in ClientType.__members__ and value not in ("confidential", "public"):
        raise ValueError(f"Type de client non supporté : {value}")
    return ClientType(value)


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

    # JWKS (RFC 7517)
    key_store_type: str = "memory"
    key_store_dsn: str = "sqlite:///puridentityserver_keys.db"
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
    clients_seed: Annotated[tuple[dict[str, object], ...], NoDecode] = ()

    # UserInfo (OIDC Core §5.4) — seed du user store (`sub` -> claims)
    users_seed: Annotated[dict[str, dict[str, object]], NoDecode] = {}

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

    @field_validator("key_store_type")
    @classmethod
    def _validate_key_store_type(cls, value: str) -> str:
        """Garantit que le type de stockage de clés est supporté."""
        if value not in _KEY_STORE_TYPES:
            raise ValueError(f"Type de stockage de clés non supporté : {value}")
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
