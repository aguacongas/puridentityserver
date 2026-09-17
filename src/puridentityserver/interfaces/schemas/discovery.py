"""OpenID Connect Discovery metadata (schema d'après la spec OIDC Discovery 1.0 §4)."""

from pydantic import BaseModel, ConfigDict, Field

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
    registration_endpoint: str | None = None
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
    response_types_supported: list[str] = Field(default_factory=lambda: ["code"])
    response_modes_supported: list[str] = Field(default_factory=lambda: ["query", "fragment"])
    grant_types_supported: list[str] = Field(
        default_factory=lambda: ["authorization_code", "refresh_token", "client_credentials"]
    )
    subject_types_supported: list[str] = Field(default_factory=lambda: ["public"])
    id_token_signing_alg_values_supported: list[str] = Field(
        default_factory=lambda: [algorithm.value for algorithm in ALL_SIGNING_ALGORITHMS]
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
