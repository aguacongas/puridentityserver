"""OpenID Connect Discovery metadata (schema d'après la spec OIDC Discovery 1.0 §4)."""

from pydantic import BaseModel, ConfigDict, Field

from puridentityserver.application.authorize import SUPPORTED_ACR_VALUES
from puridentityserver.domain.authorization import SubjectType
from puridentityserver.domain.jwe import (
    ALL_ENCRYPTION_ALGORITHMS,
    ALL_ENCRYPTION_METHODS,
)
from puridentityserver.domain.jwks import (
    ALL_SIGNING_ALGORITHMS,
    DPOP_SIGNING_ALGORITHMS,
    JARM_SIGNING_ALGORITHMS,
    USERINFO_SIGNING_ALGORITHMS,
)


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
    # RFC 9126 §2 : ``true`` uniquement quand le serveur impose PAR à tous
    # les clients — omis sinon (la suite tolère l'absence, PAR-5).
    require_pushed_authorization_requests: bool | None = None
    # CIBA (OIDC CIBA 1.0 §5.1) : absents (``None`` / vide) tant que
    # ``ciba_enabled`` est désactivé — ``backchannel_authentication_endpoint``
    # n'est publié que couplé aux modes livrés et à l'endpoint réel.
    backchannel_authentication_endpoint: str | None = None
    backchannel_token_delivery_modes_supported: list[str] = Field(default_factory=list)
    backchannel_user_code_parameter_supported: bool | None = None
    backchannel_authentication_request_signing_alg_values_supported: list[str] = Field(
        default_factory=list
    )
    request_object_signing_alg_values_supported: list[str] = Field(default_factory=list)
    request_parameter_supported: bool = False
    request_uri_parameter_supported: bool = False
    dpop_signing_alg_values_supported: list[str] = Field(
        default_factory=lambda: list(DPOP_SIGNING_ALGORITHMS)
    )
    claims_parameter_supported: bool = False
    # RFC 9207 §2.3 : ``iss`` accompagne toute réponse d'autorisation
    # réussie — OAuth2-iss-3, FAPI2-SP-FINAL-5.3.2.2-7.
    authorization_response_iss_parameter_supported: bool = True
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
    # RFC 6749 §3.1.2.1 + ``form_post`` (Form Post Response Mode 1.0 §2) +
    # ``jwt`` (JARM Final 1.0 §3) : la suite exige la présence exacte de
    # ``jwt`` — ``CheckDiscEndpointResponseModesSupportedContainsJwt``.
    response_modes_supported: list[str] = Field(
        default_factory=lambda: ["query", "fragment", "form_post", "jwt"]
    )
    authorization_signing_alg_values_supported: list[str] = Field(
        default_factory=lambda: list(JARM_SIGNING_ALGORITHMS)
    )
    # Réponses UserInfo signées (OIDC Core 1.0 §5.3.2) : algorithme admis
    # pour ``userinfo_signed_response_alg`` (§5.3.1) — sans déclaration du
    # client, la réponse reste en JSON non signé.
    userinfo_signing_alg_values_supported: list[str] = Field(
        default_factory=lambda: list(USERINFO_SIGNING_ALGORITHMS)
    )
    # Valeurs de ``prompt`` honorées (OIDC Core 1.0 §3.1.2.1 ; ``create`` :
    # Initiating User Registration via OIDC 1.0, issue #166 — champ de
    # convention, non mandate par Core).
    prompt_values_supported: list[str] = Field(
        default_factory=lambda: ["none", "login", "consent", "create"]
    )
    # ACR atteignables par l'OP (OIDC Discovery 1.0 §2) : une valeur
    # étrangère avec session active et ``prompt=none`` produit
    # ``unmet_authentication_requirements`` (RFC 9470 §2, issue #167).
    acr_values_supported: list[str] = Field(default_factory=lambda: list(SUPPORTED_ACR_VALUES))
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
    token_endpoint_auth_signing_alg_values_supported: list[str] = Field(
        default_factory=lambda: ["PS256", "ES256"]
    )
    code_challenge_methods_supported: list[str] = Field(default_factory=lambda: ["S256", "plain"])
    tls_client_certificate_bound_access_tokens: bool = True
    subject_types_supported: list[str] = Field(
        default_factory=lambda: [subject_type.value for subject_type in SubjectType]
    )
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
