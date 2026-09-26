"""OpenID Connect Discovery metadata (schema d'après la spec OIDC Discovery 1.0 §4)."""

from pydantic import BaseModel, ConfigDict, Field

from puridentityserver.domain.jwe import (
    ALL_ENCRYPTION_ALGORITHMS,
    ALL_ENCRYPTION_METHODS,
)
from puridentityserver.domain.jwks import ALL_SIGNING_ALGORITHMS


class DiscoveryDocument(BaseModel):
    """Métadonnées publiées sur `/.well-known/openid-configuration`."""

    model_config = ConfigDict(extra="ignore")

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    introspection_endpoint: str | None = None
    revocation_endpoint: str | None = None
    end_session_endpoint: str | None = None
    check_session_iframe: str | None = None
    frontchannel_logout_supported: bool = True
    frontchannel_logout_session_supported: bool = True
    backchannel_logout_supported: bool = True
    backchannel_logout_session_supported: bool = True
    registration_endpoint: str | None = None
    device_authorization_endpoint: str | None = None
    pushed_authorization_request_endpoint: str | None = None
    request_object_signing_alg_values_supported: list[str] = Field(default_factory=list)
    request_parameter_supported: bool = False
    request_uri_parameter_supported: bool = False
    scopes_supported: list[str] = Field(
        default_factory=lambda: [
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
        ]
    )
    response_types_supported: list[str] = Field(
        default_factory=lambda: [
            "code",
            "id_token",
            "token",
            "id_token token",
            "code id_token",
            "code token",
            "code id_token token",
        ]
    )
    response_modes_supported: list[str] = Field(default_factory=lambda: ["query", "fragment"])
    grant_types_supported: list[str] = Field(
        default_factory=lambda: [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ]
    )
    token_endpoint_auth_methods_supported: list[str] = Field(
        default_factory=lambda: [
            "none",
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
            "tls_client_auth",
            "self_signed_tls_client_auth",
        ]
    )
    subject_types_supported: list[str] = Field(default_factory=lambda: ["public"])
    id_token_signing_alg_values_supported: list[str] = Field(
        default_factory=lambda: [algorithm.value for algorithm in ALL_SIGNING_ALGORITHMS]
    )
    id_token_encryption_alg_values_supported: list[str] = Field(
        default_factory=lambda: [algorithm.value for algorithm in ALL_ENCRYPTION_ALGORITHMS]
    )
    id_token_encryption_enc_values_supported: list[str] = Field(
        default_factory=lambda: [method.value for method in ALL_ENCRYPTION_METHODS]
    )
    claims_supported: list[str] = Field(
        default_factory=lambda: [
            "sub",
            "name",
            "family_name",
            "given_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
            "email",
            "email_verified",
            "address",
            "phone_number",
            "phone_number_verified",
            "roles",
        ]
    )
