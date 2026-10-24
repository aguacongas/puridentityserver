"""Cas d'utilisation : découverte du serveur OpenID Connect (Discovery 1.0).

Construit le document ``/.well-known/openid-configuration`` : endpoints du
serveur plus ``scopes_supported`` / ``claims_supported`` dérivés des
IdentityResources enregistrées (OIDC Core 1.0 §5.4). Sans repository
injecté, les resources par défaut s'appliquent.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from puridentityserver.application.authorize import SUPPORTED_ACR_VALUES
from puridentityserver.application.identity_assurance import IdentityAssuranceUseCase
from puridentityserver.application.request_object import (
    PUBLISHED_REQUEST_OBJECT_SIGNING_ALGORITHMS,
    REQUEST_OBJECT_ENCRYPTION_ALGORITHMS,
    REQUEST_OBJECT_ENCRYPTION_METHODS,
)
from puridentityserver.domain.authorization import SubjectType, TokenEndpointAuthMethod
from puridentityserver.domain.identity_resource import DEFAULT_IDENTITY_RESOURCES
from puridentityserver.domain.jwe import (
    ALL_ENCRYPTION_ALGORITHMS,
    ALL_ENCRYPTION_METHODS,
)
from puridentityserver.domain.jwks import (
    ALL_SIGNING_ALGORITHMS,
    CIBA_REQUEST_SIGNING_ALGORITHMS,
    DPOP_SIGNING_ALGORITHMS,
    JARM_SIGNING_ALGORITHMS,
    USERINFO_SIGNING_ALGORITHMS,
    JWTAlgorithm,
)
from puridentityserver.interfaces.repositories.readers import (
    ApiResourceReader,
    IdentityResourceReader,
)


@dataclass(frozen=True, slots=True)
class DiscoveryConfig:
    """Configuration de base de l'émission du document de discovery."""

    issuer: str
    base_url: str = ""
    registration_enabled: bool = False
    par_enabled: bool = True
    par_required: bool = False
    ciba_enabled: bool = False
    ciba_request_signing_algorithms: tuple[str, ...] = CIBA_REQUEST_SIGNING_ALGORITHMS
    signing_algorithms: tuple[str, ...] = tuple(
        algorithm.value for algorithm in ALL_SIGNING_ALGORITHMS
    )
    encryption_algorithms: tuple[str, ...] = tuple(
        algorithm.value for algorithm in ALL_ENCRYPTION_ALGORITHMS
    )
    encryption_methods: tuple[str, ...] = tuple(method.value for method in ALL_ENCRYPTION_METHODS)
    token_endpoint_auth_methods: tuple[str, ...] = field(
        default_factory=lambda: tuple(method.value for method in TokenEndpointAuthMethod)
    )
    token_endpoint_auth_signing_algorithms: tuple[str, ...] = ("PS256", "ES256")
    code_challenge_methods: tuple[str, ...] = ("S256", "plain")
    grant_types_supported: tuple[str, ...] = (
        "authorization_code",
        "implicit",
        "refresh_token",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
    )
    request_object_signing_algorithms: tuple[str, ...] = PUBLISHED_REQUEST_OBJECT_SIGNING_ALGORITHMS
    # Chiffrement des request objects (OIDC Core 1.0 §10.1, issue #204) :
    # publiés seulement si les deux listes sont renseignées — un OP qui
    # ferme la porte n'en annonce rien, et la suite de certification saute
    # alors son module ``…-with-jar-and-encrypted-request-object``.
    request_object_encryption_algorithms: tuple[str, ...] = REQUEST_OBJECT_ENCRYPTION_ALGORITHMS
    request_object_encryption_methods: tuple[str, ...] = REQUEST_OBJECT_ENCRYPTION_METHODS
    dpop_signing_algorithms: tuple[str, ...] = DPOP_SIGNING_ALGORITHMS
    # RFC 6749 §3.1.2.1 + ``form_post`` (Form Post Response Mode 1.0 §2) +
    # ``jwt`` (JARM Final 1.0 §3, ``CheckDiscEndpointResponseModesSupportedContainsJwt``).
    response_modes_supported: tuple[str, ...] = ("query", "fragment", "form_post", "jwt")
    authorization_signing_alg_values_supported: tuple[str, ...] = JARM_SIGNING_ALGORITHMS
    # Réponses UserInfo signées (OIDC Core 1.0 §5.3.2) : algorithmes admis
    # pour ``userinfo_signed_response_alg`` à l'enregistrement (§5.3.1) —
    # sans déclaration du client, la réponse reste en JSON non signé.
    userinfo_signing_alg_values_supported: tuple[str, ...] = USERINFO_SIGNING_ALGORITHMS
    # Valeurs de ``prompt`` honorées sur /authorize (OIDC Core 1.0 §3.1.2.1) :
    # ``create`` = Initiating User Registration via OIDC 1.0 (issue #166) —
    # champ ``prompt_values_supported`` de convention, non mandate par Core.
    prompt_values_supported: tuple[str, ...] = ("none", "login", "consent", "create")
    # ACR atteignables (OIDC Discovery 1.0 §2) : base du contrôle
    # ``unmet_authentication_requirements`` (RFC 9470 §2, issue #167).
    acr_values_supported: tuple[str, ...] = SUPPORTED_ACR_VALUES
    # Fédération (OpenID Federation 1.1 §12) : modes d'enregistrement des
    # clients (``automatic`` / ``explicit``) et endpoint d'enregistrement
    # par la fédération. Publiés seulement quand la Fédération est activée.
    client_registration_types_supported: tuple[str, ...] = ()
    federation_registration_endpoint: str = ""


#: Types de réponse publiés au discovery ET dans l'entity statement
#: fédération (OIDC Discovery 1.0 §3 : ``response_types_supported`` est
#: REQUIRED) : les combinaisons honorées par /authorize (Core §3.1.2.1).
RESPONSE_TYPES_SUPPORTED: tuple[str, ...] = (
    "code",
    "id_token",
    "token",
    "id_token token",
    "code id_token",
    "code token",
    "code id_token token",
)


class DiscoveryUseCase:
    """Produit les métadonnées de discovery depuis la configuration de l'émetteur."""

    def __init__(
        self,
        config: DiscoveryConfig,
        identity_resources: IdentityResourceReader | None = None,
        api_resources: ApiResourceReader | None = None,
        identity_assurance: IdentityAssuranceUseCase | None = None,
    ) -> None:
        """Injection de la configuration de l'émetteur et des registres de resources.

        ``identity_assurance`` publie la metadata eKYC (OpenID Identity
        Assurance 1.0) : les listes advertised sont dérivées des profils
        vérifiés connus ; sans injection, la metadata eKYC est absente.
        """
        self._config = config
        self._identity_resources = identity_resources
        self._api_resources = api_resources
        self._identity_assurance = identity_assurance

    async def execute(self) -> dict[str, object]:
        """Construit les métadonnées OIDC Discovery (§3 OIDC Discovery 1.0)."""
        base = self._resolve_base_url()
        scopes_supported, claims_supported = await self._scopes_and_claims()
        metadata: dict[str, object] = {
            "issuer": self._config.issuer,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "userinfo_endpoint": f"{base}/userinfo",
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "introspection_endpoint": f"{base}/introspect",
            "revocation_endpoint": f"{base}/revoke",
            "end_session_endpoint": f"{base}/end_session",
            "check_session_iframe": f"{base}/session_state",
            "frontchannel_logout_supported": True,
            "frontchannel_logout_session_supported": True,
            "backchannel_logout_supported": True,
            "backchannel_logout_session_supported": True,
            "device_authorization_endpoint": f"{base}/device_authorization",
            # ``none`` complète la liste : l'OP émet un id_token sans
            # signature pour un client qui l'enregistre (OIDC Core 1.0
            # §3.1.3.7, JWA RFC 7519 §6) — aucune clé n'est publiée pour lui.
            "id_token_signing_alg_values_supported": [
                *self._config.signing_algorithms,
                JWTAlgorithm.NONE.value,
            ],
            "id_token_encryption_alg_values_supported": list(self._config.encryption_algorithms),
            "id_token_encryption_enc_values_supported": list(self._config.encryption_methods),
            "token_endpoint_auth_methods_supported": list(self._config.token_endpoint_auth_methods),
            # Algorithmes admis pour la ``client_assertion`` signée (RFC 7523
            # §3, FAPI1-ADV-8.6) : ``private_key_jwt`` exige au moins l'un des
            # deux familles PS/ES publiés ici.
            "token_endpoint_auth_signing_alg_values_supported": list(
                self._config.token_endpoint_auth_signing_algorithms
            ),
            # Méthodes PKCE réellement honorées sur /authorize (RFC 7636 §4.4,
            # FAPI1-ADV-5.2.2-18).
            "code_challenge_methods_supported": list(self._config.code_challenge_methods),
            # Liaison mTLS des access tokens réellement implémentée :
            # ``cnf.x5t#S256`` émis pour un client mTLS (RFC 8705 §3.3) et
            # opposé sur /userinfo et la ressource protégée.
            "tls_client_certificate_bound_access_tokens": True,
            "grant_types_supported": list(self._config.grant_types_supported),
            "scopes_supported": scopes_supported,
            "claims_supported": claims_supported,
            # OIDC Discovery 1.0 §3 : ``response_types_supported`` et
            # ``subject_types_supported`` sont REQUIRED — émis par le cas
            # d'usage pour que l'entity statement fédération (§5.1.1,
            # ``metadata``/``openid_provider``) les porte aussi : le schéma
            # du endpoint ne les complétait qu'en défaut.
            "response_types_supported": list(RESPONSE_TYPES_SUPPORTED),
            "subject_types_supported": [subject_type.value for subject_type in SubjectType],
            # Paramètre claims (OIDC Core 1.0 §5.5) : parsé, validé et honoré
            # sur /authorize — les members userinfo/id_token sont rendus.
            "claims_parameter_supported": True,
            # RFC 9207 §2.3 : l'émetteur accompagne toute réponse
            # d'autorisation réussie (paramètre ``iss`` émis par
            # ``_build_success_params``) — OAuth2-iss-3,
            # FAPI2-SP-FINAL-5.3.2.2-7.
            "authorization_response_iss_parameter_supported": True,
            # Modes de réponse autorisés (RFC 6749 §3.1.2.1, OIDC Core
            # §3.1.2.1) + ``jwt`` : JARM Final 1.0 §3 enveloppe la réponse
            # d'autorisation (succès ou erreur redirigeable) dans un JWT
            # signé — ``CheckDiscEndpointResponseModesSupportedContainsJwt``.
            "response_modes_supported": list(self._config.response_modes_supported),
            # Algorithmes admis pour signer ces enveloppes JARM côté OP
            # (JARM Final 1.0 §4.1, ``authorization_signed_response_alg``
            # déclaré par les clients).
            "authorization_signing_alg_values_supported": list(
                self._config.authorization_signing_alg_values_supported
            ),
            # Réponses UserInfo signées (OIDC Core 1.0 §5.3.2) : algorithme
            # exigé pour ``userinfo_signed_response_alg`` (§5.3.1) — la
            # réponse devient alors ``application/jwt``, ``iss``/``aud``
            # obligatoires ; sans déclaration, JSON non signé.
            "userinfo_signing_alg_values_supported": list(
                self._config.userinfo_signing_alg_values_supported
            ),
            # Valeurs de ``prompt`` honorées (OIDC Core 1.0 §3.1.2.1 ;
            # ``create`` : Initiating User Registration via OIDC 1.0,
            # issue #166 — champ de convention, non mandate par Core).
            "prompt_values_supported": list(self._config.prompt_values_supported),
            # ACR atteignables déclarés (OIDC Discovery 1.0 §2) : une valeur
            # étrangère avec session active et ``prompt=none`` produit
            # ``unmet_authentication_requirements`` (RFC 9470 §2, issue #167).
            "acr_values_supported": list(self._config.acr_values_supported),
        }
        if self._config.registration_enabled:
            metadata["registration_endpoint"] = f"{base}/register"
        if self._config.par_enabled:
            metadata["pushed_authorization_request_endpoint"] = f"{base}/par"
            if self._config.par_required:
                # RFC 9126 §2 : le serveur n'accepte que les demandes
                # poussées — PAR-5, FAPI2-SP-FINAL-5.3.2.2-2.
                metadata["require_pushed_authorization_requests"] = True
        # CIBA (OIDC CIBA 1.0 §5.1) : modes poll/ping livrés, endpoint dédié,
        # grant publiquement annoncé et algorithmes de signature des request
        # objects (CIBA §5.2.2, check ``*SigningAlgValuesSupported``).
        # ``user_code`` n'est pas supporté (§5.1).
        if self._config.ciba_enabled:
            metadata["backchannel_token_delivery_modes_supported"] = ["poll", "ping"]
            metadata["backchannel_authentication_endpoint"] = f"{base}/bc-authorize"
            metadata["backchannel_user_code_parameter_supported"] = False
            metadata["backchannel_authentication_request_signing_alg_values_supported"] = list(
                self._config.ciba_request_signing_algorithms
            )
            metadata["grant_types_supported"] = [
                *self._config.grant_types_supported,
                "urn:openid:params:grant-type:ciba",
            ]
        # Request objects (RFC 9101 §5.2) : ``alg=none`` pour les clients
        # standards, ``PS256``/``ES256`` pour le profil FAPI1 Advanced
        # (FAPI1-ADV-5.2.2-1) ; les indicateurs restent à ``true`` pour
        # que la suite de certification n'émette aucun avertissement
        # (``CheckDiscEndpointRequest*ParameterSupported``).
        metadata["request_object_signing_alg_values_supported"] = list(
            self._config.request_object_signing_algorithms
        )
        metadata["request_parameter_supported"] = bool(
            self._config.request_object_signing_algorithms
        )
        metadata["request_uri_parameter_supported"] = bool(
            self._config.request_object_signing_algorithms
        )
        # Chiffrement des request objects (OIDC Core 1.0 §10.1, issue #204) :
        # les deux metadata ne sont publiées que si l'OP y est ouvert — la
        # suite de certification lit celles de l'entity statement fédéré
        # (``metadata.openid_provider``) pour décider de jouer ou de sauter
        # son module ``…-with-jar-and-encrypted-request-object``.
        if (
            self._config.request_object_encryption_algorithms
            and self._config.request_object_encryption_methods
        ):
            metadata["request_object_encryption_alg_values_supported"] = list(
                self._config.request_object_encryption_algorithms
            )
            metadata["request_object_encryption_enc_values_supported"] = list(
                self._config.request_object_encryption_methods
            )
        # DPoP (RFC 9449 §5.1) : algorithmes asymétriques acceptés pour
        # signer une preuve — ``none`` et les familles symétriques HS*
        # y sont exclus (le RS partage leur secret : preuve forgeable).
        metadata["dpop_signing_alg_values_supported"] = list(self._config.dpop_signing_algorithms)
        # Identité assurance (OpenID Identity Assurance 1.0) : la metadata
        # eKYC décrit ce que l'OP sait servir ; elle est dérivée des profils
        # vérifiés connus et reste absente si l'OP n'en expose aucun.
        ekyc = await self._identity_assurance_metadata()
        if ekyc:
            metadata.update(ekyc)
        # Fédération (OpenID Federation 1.1 §12) : modes d'enregistrement
        # acceptés et endpoint d'enregistrement par la fédération. Publiés
        # seulement quand la Fédération est activée.
        if self._config.client_registration_types_supported:
            metadata["client_registration_types_supported"] = list(
                self._config.client_registration_types_supported
            )
        if self._config.federation_registration_endpoint:
            metadata["federation_registration_endpoint"] = (
                self._config.federation_registration_endpoint
            )
        return metadata

    async def _identity_assurance_metadata(self) -> dict[str, list[str]]:
        """Metadata eKYC publiée (listes dérivées des profils vérifiés)."""
        if self._identity_assurance is None:
            return {}
        metadata = await self._identity_assurance.metadata()
        return {name: list(values) for name, values in metadata.items() if values}

    async def _scopes_and_claims(self) -> tuple[list[str], list[str]]:
        """Scopes et claims publiés, dérivés des IdentityResources + scopes d'API."""
        resources = DEFAULT_IDENTITY_RESOURCES
        if self._identity_resources is not None:
            stored = await self._identity_resources.find_all()
            if stored:
                resources = tuple(stored)
        scopes = [resource.name for resource in resources if resource.show_in_discovery_document]
        claims: list[str] = []
        seen: set[str] = set()
        for resource in resources:
            for claim in sorted(resource.user_claims):
                if claim not in seen:
                    seen.add(claim)
                    claims.append(claim)
        scopes.extend(sorted(await self._api_scope_names()))
        return scopes, claims

    async def _api_scope_names(self) -> set[str]:
        """Scopes d'API déclarés par les ApiResources enregistrées."""
        if self._api_resources is None:
            return set()
        stored = await self._api_resources.find_all()
        return {scope for resource in stored for scope in resource.scopes}

    def _resolve_base_url(self) -> str:
        return (self._config.base_url or self._config.issuer).rstrip("/")
