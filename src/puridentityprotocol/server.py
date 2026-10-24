"""Composition root du serveur protocole OIDC/OAuth — accès en lecture seule.

Assemble l'application FastAPI du serveur **protocole** : endpoints
OIDC/OAuth, identité (``/auth/*``, ``/login``), discovery, JWKS et ses
stores privés (clés, codes, refresh/revoked tokens, consentements,
sessions d'appareil, requêtes PAR). Les resources administrées (clients,
utilisateurs, IdentityResources, ApiResources) ne sont **jamais
modifiées** par ce serveur : il y accède exclusivement via les ports de
lecture seule ``Readers`` (exception : la Dynamic Client Registration,
RFC 7591, qui crée des clients et reçoit donc le port d'écriture
``ClientRepository``).

Déployé seul (``puridentityprotocol.server:app``), il construit ses
propres stores depuis la configuration ; le serveur ``full`` le compose
par-dessus des stores partagés (``puridentityfull.server``) en
l'instanciant avec les mêmes instances qu'en déploiement séparé.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from puridentityserver.application.authorize import AuthorizeConfig, AuthorizeUseCase
from puridentityserver.application.backchannel_authorize import (
    BackchannelAuthenticationConfig,
    BackchannelAuthenticationUseCase,
    CibaApprovalUseCase,
)
from puridentityserver.application.claim_authorizer import BearerClaimAuthorizer, ClaimRule
from puridentityserver.application.consent import ConsentUseCase
from puridentityserver.application.device_authorize import (
    DeviceAuthorizationUseCase,
    DeviceConfig,
)
from puridentityserver.application.discovery import DiscoveryConfig, DiscoveryUseCase
from puridentityserver.application.dpop import DpopGrantGuard
from puridentityserver.application.federated_client import TrustChainClientResolver
from puridentityserver.application.federation import (
    DiscoveryFederationMetadataProvider,
    FederationConfig,
    FederationUseCase,
)
from puridentityserver.application.identity_assurance import IdentityAssuranceUseCase
from puridentityserver.application.introspect import IntrospectConfig, IntrospectUseCase
from puridentityserver.application.jarm import JarmSigner
from puridentityserver.application.jwks import JWKSetConfig, JWKSetUseCase
from puridentityserver.application.logout import LogoutConfig, LogoutUseCase
from puridentityserver.application.openid20_migration import OpenID20MigrationUseCase
from puridentityserver.application.openid20_provider import OpenID20ProviderUseCase
from puridentityserver.application.par import PushedAuthorizationConfig, PushedAuthorizationUseCase
from puridentityserver.application.protected_resource import (
    ProtectedResourceConfig,
    ProtectedResourceUseCase,
)
from puridentityserver.application.registration import RegistrationConfig, RegistrationUseCase
from puridentityserver.application.request_object import RequestObjectConfig, RequestObjectResolver
from puridentityserver.application.revocation import RevocationConfig, RevocationUseCase
from puridentityserver.application.scope_registry import ScopeRegistry
from puridentityserver.application.session_management import SessionManagementUseCase
from puridentityserver.application.token import TokenConfig, TokenDependencies, TokenUseCase
from puridentityserver.application.userinfo import UserInfoConfig, UserInfoUseCase
from puridentityserver.domain.authorization import Scope, TokenEndpointAuthMethod
from puridentityserver.domain.jwks import SYMMETRIC_ALGORITHMS, JWTAlgorithm, KeyUse
from puridentityserver.domain.password_policy import PasswordPolicy
from puridentityserver.domain.userinfo import UserClaims
from puridentityserver.identity.config import (
    auth_router,
    configure_identity,
    login_router,
    register_router,
    seed_users,
    signup_router,
)
from puridentityserver.infrastructure.backchannel import (
    HTTPBackchannelNotifier,
    HTTPCibaPingNotifier,
)
from puridentityserver.infrastructure.bearer import build_bearer_verifier
from puridentityserver.infrastructure.claims import UserStoreClaimsProvider
from puridentityserver.infrastructure.client_assertions import PyJWTClientAssertionVerifier
from puridentityserver.infrastructure.client_tls import ClientCertificateHeaderNames
from puridentityserver.infrastructure.dpop import PyJWTDpopProofValidator
from puridentityserver.infrastructure.federation import (
    ClientRegistrySubordinateSource,
    HTTPFederationEntityFetcher,
    KeyManagerFederationKeyProvider,
    PyJWTFederationTokenManager,
)
from puridentityserver.infrastructure.jarm import PyJarmEnvelopeSigner
from puridentityserver.infrastructure.jwe import JWEIdTokenEncrypter
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.readers import build_readers_from_stores
from puridentityserver.infrastructure.persistence.stores import (
    Stores,
    build_stores,
    close_protocol_stores,
    close_resources,
    initialise_protocol_stores,
    initialise_resources,
)
from puridentityserver.infrastructure.request_object import (
    HTTPRequestObjectFetcher,
    loopback_bind,
)
from puridentityserver.infrastructure.secrets import AsymmetricSecretCipher, load_seal_key_pair
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.signed_request_object import (
    PyJWTSignedRequestObjectVerifier,
)
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.interfaces.api.authorize import authorize_router
from puridentityserver.interfaces.api.backchannel_authorize import (
    backchannel_authorization_router,
    ciba_approval_router,
)
from puridentityserver.interfaces.api.consent import consent_router
from puridentityserver.interfaces.api.cors import DynamicCORSMiddleware
from puridentityserver.interfaces.api.device_authorize import device_authorization_router
from puridentityserver.interfaces.api.device_page import device_page_router
from puridentityserver.interfaces.api.discovery import discovery_router
from puridentityserver.interfaces.api.federation import federation_router
from puridentityserver.interfaces.api.introspect import introspect_router
from puridentityserver.interfaces.api.jwks import jwk_set_router
from puridentityserver.interfaces.api.logout import logout_router
from puridentityserver.interfaces.api.openid20_provider import openid20_provider_router
from puridentityserver.interfaces.api.par import par_router
from puridentityserver.interfaces.api.protected_resource import protected_resource_router
from puridentityserver.interfaces.api.registration import registration_router
from puridentityserver.interfaces.api.revocation import revocation_router
from puridentityserver.interfaces.api.same_origin import SameOriginFormGuardMiddleware
from puridentityserver.interfaces.api.session_management import session_management_router
from puridentityserver.interfaces.api.token import token_router
from puridentityserver.interfaces.api.userinfo import userinfo_router
from puridentityserver.interfaces.repositories.readers import ClientReader

_PACKAGE_VERSION = "0.1.0"


def _primary_algorithm(settings: Settings) -> JWTAlgorithm:
    """Algorithme asymétrique de signature principal, ou RS256 sinon.

    La famille HS* signe l'``id_token`` avec le secret partagé du client :
    elle ne fournit jamais la clé de serveur signant l'access_token et le
    reste des jetons — premier algorithme asymétrique configuré.
    """
    for algorithm in settings.jwks_signing_algorithms:
        if algorithm not in SYMMETRIC_ALGORITHMS:
            return algorithm
    return JWTAlgorithm.RS256


def _discovery_config(
    settings: Settings, token_endpoint_auth_methods: tuple[str, ...]
) -> DiscoveryConfig:
    """Manifeste ``/.well-known/openid-configuration`` (OpenID Connect Discovery 1.0).

    Les champs ``client_registration_types_supported`` et
    ``federation_registration_endpoint`` ne sont renseignés que si le support
    OpenID Federation est activé (§12.1.2).
    """
    return DiscoveryConfig(
        issuer=settings.issuer,
        base_url=settings.base_url,
        registration_enabled=settings.registration_enabled,
        par_enabled=settings.par_enabled,
        par_required=settings.par_required,
        ciba_enabled=settings.ciba_enabled,
        signing_algorithms=settings.jwks_algorithms,
        encryption_algorithms=settings.jwks_encryption_algorithms,
        encryption_methods=settings.jwks_encryption_methods,
        token_endpoint_auth_methods=token_endpoint_auth_methods,
        client_registration_types_supported=(
            ("automatic", "explicit") if settings.federation_enabled else ()
        ),
        federation_registration_endpoint=(
            f"{(settings.base_url or settings.issuer).rstrip('/')}/federation/register"
            if settings.federation_enabled
            else ""
        ),
    )


def _federation_usecase(
    settings: Settings,
    *,
    key_manager: DefaultKeyManager,
    discovery_usecase: DiscoveryUseCase,
    client_reader: ClientReader,
) -> FederationUseCase | None:
    """Cas d'usage ``Federation`` (OpenID Federation 1.1 §12), ou ``None`` si inactif.

    ``key_manager`` est le ``DefaultKeyManager`` dédié aux ``entity_statement``
    (``KeyUse.FEDERATION``) ; le fetcher accepte les cibles loopback si la
    liaison ``host`` est locale ou si ``federation_allow_local_targets``
    l'autorise explicitement.
    """
    if not settings.federation_enabled:
        return None
    algorithm = JWTAlgorithm(settings.federation_signing_alg)
    return FederationUseCase(
        config=FederationConfig(
            entity_identifier=(settings.federation_entity_identifier or settings.issuer).rstrip(
                "/"
            ),
            trust_anchors=settings.federation_trust_anchors,
            statement_ttl_seconds=settings.federation_statement_ttl_seconds,
            algorithm=algorithm,
            registration_types=("automatic", "explicit"),
        ),
        token_manager=PyJWTFederationTokenManager(key_manager, algorithm),
        key_provider=KeyManagerFederationKeyProvider(key_manager),
        fetcher=HTTPFederationEntityFetcher(
            allow_local_targets=loopback_bind(settings.host)
            or settings.federation_allow_local_targets
        ),
        metadata_provider=DiscoveryFederationMetadataProvider(
            discovery_usecase, (settings.base_url or settings.issuer)
        ),
        subordinate_source=ClientRegistrySubordinateSource(client_reader),
    )


def _mount_authorization_routers(
    app: FastAPI,
    *,
    authorize_usecase: AuthorizeUseCase,
    par_usecase: PushedAuthorizationUseCase,
    client_reader: ClientReader,
    consent_usecase: ConsentUseCase,
    request_object_resolver: RequestObjectResolver,
    par_enabled: bool,
    par_required: bool,
    require_login: bool,
    base_url: str,
    jarm_signer: JarmSigner | None = None,
    issuer: str = "",
) -> None:
    """Monte ``/authorize`` (+ ``/par`` + ``/consent`` selon la configuration).

    ``issuer`` (identifiant d'émetteur publié par discovery) est réfléchi en
    ``iss`` dans les erreurs ``response_mode=form_post`` (RFC 9207 §2).
    """
    app.include_router(
        authorize_router(
            authorize_usecase,
            par_usecase=par_usecase if par_enabled else None,
            client_repository=client_reader,
            consent_usecase=consent_usecase,
            request_object_resolver=request_object_resolver,
            par_required=par_required,
            require_login=require_login,
            base_url=base_url,
            jarm_signer=jarm_signer,
            issuer=issuer,
        )
    )
    app.include_router(
        consent_router(
            consent_usecase,
            authorize_usecase,
            client_reader,
            par_usecase=par_usecase if par_enabled else None,
            jarm_signer=jarm_signer,
            issuer=issuer,
        )
    )
    if par_enabled:
        app.include_router(par_router(par_usecase))


class ProtocolDependencies:
    """Conteneur des dépendances du serveur protocole (repos, managers, usecases).

    Construit la chaîne d'injection du protocole à partir des
    ``Settings`` et des ``Stores`` partagés (construits localement en
    déploiement séparé, fournis par le serveur ``full`` sinon) ; expose le
    cycle de vie (seed + libération) et les réglages par client (durée de
    session, politique de mots de passe).
    """

    def __init__(self, settings: Settings, stores: Stores) -> None:
        """Construit les manifestes, lecteurs et usecases pour ``settings``."""
        self.settings = settings
        self.stores = stores

        self.key_manager = DefaultKeyManager(stores.key_pair)
        self.session_key_manager = DefaultKeyManager(stores.key_pair, use=KeyUse.SESSION)
        self.reset_key_manager = DefaultKeyManager(stores.key_pair, use=KeyUse.RESET)
        self.verify_key_manager = DefaultKeyManager(stores.key_pair, use=KeyUse.VERIFY)
        self.secret_key_manager = DefaultKeyManager(stores.key_pair, use=KeyUse.SECRET)
        configure_identity(
            session_key_manager=self.session_key_manager,
            reset_token_key_manager=self.reset_key_manager,
            verification_token_key_manager=self.verify_key_manager,
            cookie_lifetime_seconds=settings.identity_jwt_lifetime_seconds,
            session_rotation_days=settings.jwks_rotation_days,
            session_grace_period_days=settings.jwks_grace_period_days,
            password_policy=settings.password_policy,
        )
        self.config = _discovery_config(settings, self._token_endpoint_auth_methods())
        self.jwks_usecase = JWKSetUseCase(
            JWKSetConfig(
                key_size=settings.jwks_key_size,
                algorithms=settings.jwks_signing_algorithms,
                rotation_days=settings.jwks_rotation_days,
                grace_period_days=settings.jwks_grace_period_days,
                rotation_seconds=settings.jwks_rotation_seconds,
                rotation_algorithms=settings.jwks_rotation_signing_algorithms,
                retained_keys=settings.jwks_retained_keys,
            ),
            self.key_manager,
        )
        self.token_manager = PyJWTTokenManager(self.key_manager)
        self.secret_cipher = AsymmetricSecretCipher(self.secret_key_manager)
        self.id_token_encrypter = JWEIdTokenEncrypter()
        self.client_assertions = PyJWTClientAssertionVerifier(self.secret_cipher)
        self.client_certificate_headers = ClientCertificateHeaderNames(
            certificate=settings.client_certificate_header,
            subject_dn=settings.client_certificate_dn_header,
        )
        self.bearer_verifier = build_bearer_verifier(settings, self.token_manager)
        self.dpop_validator = PyJWTDpopProofValidator(stores.dpop_replay)
        self.signed_request_objects = PyJWTSignedRequestObjectVerifier(stores.dpop_replay)
        self.registration_authorizer = BearerClaimAuthorizer(
            self.bearer_verifier,
            ClaimRule(
                settings.registration_required_claim,
                frozenset(settings.registration_required_claim_values),
            ),
        )
        self.readers = build_readers_from_stores(
            client=stores.client,
            user=stores.user,
            identity_resource=stores.identity_resource,
            api_resource=stores.api_resource,
            # Enregistrement automatique (OpenID Federation 1.1 §12.1) : le
            # resolveur est résolu paresseusement, le cas d'usage de la
            # Fédération n'étant construit qu'après le discovery.
            federated_resolver=(
                TrustChainClientResolver(lambda: self.federation_usecase)
                if settings.federation_enabled
                else None
            ),
        )
        self.scope_registry = ScopeRegistry(
            self.readers.identity_resource,
            self.readers.api_resource,
            extra_scopes=(
                frozenset({Scope.OPENID20}) if settings.openid20_migration_enabled else frozenset()
            ),
        )
        self.openid20_migration = OpenID20MigrationUseCase(
            stores.openid20_identifier,
            enabled=settings.openid20_migration_enabled,
        )
        self.openid20_provider = OpenID20ProviderUseCase(
            self.key_manager,
            self.openid20_migration,
            issuer=settings.issuer,
            base_url=settings.base_url or settings.issuer,
            enabled=settings.openid20_migration_enabled,
            algorithm=_primary_algorithm(settings),
        )
        self.session_management = SessionManagementUseCase()
        self.claims_provider = UserStoreClaimsProvider(self.readers.user)
        self.identity_assurance = IdentityAssuranceUseCase(self.claims_provider, self.readers.user)
        self.discovery_usecase = DiscoveryUseCase(
            self.config,
            identity_resources=self.readers.identity_resource,
            api_resources=self.readers.api_resource,
            identity_assurance=self.identity_assurance,
        )

        self.federation_key_manager = DefaultKeyManager(stores.key_pair, use=KeyUse.FEDERATION)
        self.federation_usecase: FederationUseCase | None = _federation_usecase(
            settings,
            key_manager=self.federation_key_manager,
            discovery_usecase=self.discovery_usecase,
            client_reader=self.readers.client,
        )
        self.request_object_resolver = RequestObjectResolver(
            RequestObjectConfig(issuer=settings.issuer),
            HTTPRequestObjectFetcher(
                allow_local_targets=loopback_bind(settings.host)
                or settings.request_uri_allow_local_targets
            ),
            clients=self.readers.client,
            signed=self.signed_request_objects,
        )

        self.jarm_signer = JarmSigner(
            PyJarmEnvelopeSigner(self.key_manager, settings.issuer),
            self.readers.client,
        )
        self.authorize_usecase = AuthorizeUseCase(
            AuthorizeConfig(
                code_ttl_seconds=settings.authorization_code_ttl_seconds,
                access_token_ttl_seconds=settings.access_token_ttl_seconds,
                signing_algorithm=_primary_algorithm(settings),
                issuer=settings.issuer,
                secret_cipher=self.secret_cipher,
                id_token_encrypter=self.id_token_encrypter,
                subject_seed=settings.subject_pairwise_seed,
            ),
            self.readers.client,
            stores.code,
            self.token_manager,
            self.scope_registry,
            session_management=self.session_management,
            claims_provider=self.claims_provider,
            identity_resources=self.readers.identity_resource,
            jarm_signer=self.jarm_signer,
            openid20_migration=self.openid20_migration,
            identity_assurance=self.identity_assurance,
        )
        self.token_usecase = TokenUseCase(
            TokenConfig(
                issuer=settings.issuer,
                signing_algorithm=_primary_algorithm(settings),
                access_token_ttl_seconds=settings.access_token_ttl_seconds,
                refresh_token_ttl_seconds=settings.refresh_token_ttl_seconds,
                token_endpoint=f"{settings.base_url or settings.issuer}".rstrip("/") + "/token",
                secret_cipher=self.secret_cipher,
                id_token_encrypter=self.id_token_encrypter,
                subject_seed=settings.subject_pairwise_seed,
            ),
            self.readers.client,
            stores.code,
            self.token_manager,
            stores.refresh,
            stores.device,
            stores.backchannel,
            self.scope_registry,
            self.client_assertions,
            TokenDependencies(
                claims_provider=self.claims_provider,
                revoked_tokens=stores.revoked,
                dpop=DpopGrantGuard(self.dpop_validator),
                openid20_migration=self.openid20_migration,
                identity_assurance=self.identity_assurance,
            ),
        )
        self.device_usecase = DeviceAuthorizationUseCase(
            DeviceConfig(
                issuer=settings.issuer,
                base_url=settings.base_url,
                ttl_seconds=settings.device_code_ttl_seconds,
                interval_seconds=settings.device_code_interval_seconds,
            ),
            self.readers.client,
            stores.device,
            self.scope_registry,
        )
        protocol_base_url = (settings.base_url or settings.issuer).rstrip("/")
        self.backchannel_authorize_usecase = BackchannelAuthenticationUseCase(
            BackchannelAuthenticationConfig(
                issuer=settings.issuer,
                base_url=settings.base_url,
                ttl_seconds=settings.ciba_ttl_seconds,
                min_ttl_seconds=settings.ciba_min_ttl_seconds,
                interval_seconds=settings.ciba_interval_seconds,
                token_endpoint=f"{protocol_base_url}/token",
                bc_authorize_endpoint=f"{protocol_base_url}/bc-authorize",
                binding_message_max_length=settings.ciba_binding_message_max_length,
            ),
            self.readers.client,
            self.readers.user,
            stores.backchannel,
            self.scope_registry,
            client_assertions=self.client_assertions,
            token_manager=self.token_manager,
            request_objects=self.signed_request_objects,
        )
        self.ciba_approval_usecase = CibaApprovalUseCase(
            stores.backchannel, ping_notifier=HTTPCibaPingNotifier()
        )
        self.userinfo_usecase = UserInfoUseCase(
            UserInfoConfig(issuer=settings.issuer, subject_seed=settings.subject_pairwise_seed),
            self.token_manager,
            self.claims_provider,
            stores.revoked,
            self.readers.identity_resource,
            dpop=self.dpop_validator,
            clients=self.readers.client,
            identity_assurance=self.identity_assurance,
        )
        self.protected_resource_usecase: ProtectedResourceUseCase | None = None
        if settings.protected_resource_enabled:
            self.protected_resource_usecase = ProtectedResourceUseCase(
                ProtectedResourceConfig(issuer=settings.issuer),
                self.token_manager,
                stores.revoked,
                dpop=self.dpop_validator,
            )
        self.introspect_usecase = IntrospectUseCase(
            IntrospectConfig(issuer=settings.issuer),
            self.readers.client,
            self.token_manager,
            stores.revoked,
        )
        self.revocation_usecase = RevocationUseCase(
            RevocationConfig(issuer=settings.issuer),
            self.readers.client,
            self.token_manager,
            stores.revoked,
        )
        self.logout_usecase = LogoutUseCase(
            LogoutConfig(issuer=settings.issuer, subject_seed=settings.subject_pairwise_seed),
            self.readers.client,
            self.token_manager,
            HTTPBackchannelNotifier(),
        )
        self.registration_usecase = RegistrationUseCase(
            RegistrationConfig(
                issuer=settings.issuer,
                base_url=settings.base_url,
                requires_initial_access_token=settings.registration_requires_initial_access_token,
                initial_access_token_hashes=settings.registration_initial_access_token_hashes,
                initial_access_token_mode=settings.registration_initial_access_token_mode,
                subject_seed=settings.subject_pairwise_seed,
            ),
            stores.client,
            self.scope_registry,
            self.registration_authorizer,
            self.secret_cipher,
            sector_fetcher=HTTPRequestObjectFetcher(
                allow_local_targets=loopback_bind(settings.host)
                or settings.request_uri_allow_local_targets,
                content_type="application/json",
            ),
        )
        self.par_usecase = PushedAuthorizationUseCase(
            PushedAuthorizationConfig(
                ttl_seconds=settings.par_ttl_seconds,
                par_endpoint=(f"{settings.base_url or settings.issuer}".rstrip("/") + "/par"),
                issuer=settings.issuer,
                token_endpoint=(f"{settings.base_url or settings.issuer}".rstrip("/") + "/token"),
            ),
            self.readers.client,
            stores.pushed,
            self.scope_registry,
            dpop=self.dpop_validator,
            client_assertions=self.client_assertions,
            request_object_resolver=self.request_object_resolver,
        )
        self.consent_usecase = ConsentUseCase(stores.consent)

    @staticmethod
    def _token_endpoint_auth_methods() -> tuple[str, ...]:
        """Méthodes d'auth du token endpoint publiées au discovery.

        La clé de scellement des secrets HMAC (``KeyUse.SECRET``) étant
        générée automatiquement, ``client_secret_jwt`` est toujours annoncé.
        """
        return tuple(method.value for method in TokenEndpointAuthMethod)

    async def resolve_session_lifetime(self, client_id: str) -> int | None:
        """Retourne la durée de session cookie configurée pour le client, si présente."""
        client = await self.readers.client.find_by_id(client_id)
        return client.session_lifetime_seconds if client is not None else None

    async def resolve_password_policy(self, client_id: str) -> PasswordPolicy:
        """Politique de mots de passe effective : surcharge du client, sinon défaut.

        La table partielle ``password_policy`` du client (``clients_seed``)
        écrase les seules clés qu'elle renseigne sur la politique serveur
        (``[settings.password_policy]``) ; client inconnu → défaut pur.
        """
        client = await self.readers.client.find_by_id(client_id)
        if client is None:
            return self.settings.password_policy
        return client.password_policy.apply(self.settings.password_policy)

    @asynccontextmanager
    async def lifespan(self, _app: FastAPI) -> AsyncGenerator[None, None]:
        """Prépare les stockages (resources + protocole) puis libère à l'arrêt."""
        await initialise_resources(self.stores, self.settings)
        await self._start_protocol()
        try:
            yield
        finally:
            await close_resources(self.stores)
            await close_protocol_stores(self.stores)

    async def _start_protocol(self) -> None:
        """Alimente clients + user store et génère les clés (protocole/full)."""
        identity_users = await seed_users(self.settings.identity_seed_users)
        await initialise_protocol_stores(self.stores, self.settings)
        if self.federation_usecase is not None:
            # Fédération : une clé de signature dédiée aux entity statements
            # (distincte des clés `sig` du JWKS OIDC, OpenID Federation 1.1
            # §2.1) doit exister avant la publication du statement.
            await self.federation_key_manager.ensure_active_key(
                2048, JWTAlgorithm(self.settings.federation_signing_alg)
            )
        await self.stores.user.save_all(
            [
                UserClaims(subject=subject, claims=claims)
                for subject, claims in self.settings.users_seed.items()
                if subject not in identity_users  # profils d'identité → pont sous UUID ci-dessous
            ]
        )
        for subject, user in identity_users.items():
            profile = self.settings.users_seed.get(subject)
            if profile is not None:
                await self.stores.user.save(UserClaims(subject=str(user.id), claims=profile))
        await self.jwks_usecase.initialise()
        for manager in (
            self.session_key_manager,
            self.reset_key_manager,
            self.verify_key_manager,
        ):
            await manager.ensure_active_key(2048, JWTAlgorithm.RS256)
        await self._initialise_seal_key()

    async def _initialise_seal_key(self) -> None:
        """Prépare la clé de scellement des secrets HMAC (``KeyUse.SECRET``).

        Un seed PEM configuré est enregistré si aucune clé de scellement
        n'existe encore (déterminisme des serveurs en mémoire) puis la
        clé active est générée / tourne suivant ``jwks_rotation_days``.
        """
        if self.settings.client_secret_seal_key_pem:
            existing = await self.secret_key_manager.get_active_keys()
            if not existing:
                seed = load_seal_key_pair(self.settings.client_secret_seal_key_pem)
                await self.stores.key_pair.save(seed)
        await self.secret_cipher.rotate_if_stale(
            self.settings.jwks_key_size, self.settings.jwks_rotation_days
        )

    def mount(self, app: FastAPI) -> None:
        """Monte les endpoints de protocole OIDC/OAuth sur ``app``."""
        app.include_router(discovery_router(self.discovery_usecase))
        app.include_router(jwk_set_router(self.jwks_usecase))
        if self.federation_usecase is not None:
            # Fédération (OpenID Federation 1.1) : l'entity configuration de
            # l'OP. Les routes ne sont montées que si le support est activé —
            # sans lui, aucun chemin n'est exposé.
            app.include_router(federation_router(self.federation_usecase))
        app.include_router(login_router(self.resolve_session_lifetime))
        app.include_router(
            signup_router(
                self.resolve_session_lifetime,
                resolve_password_policy=self.resolve_password_policy,
                default_password_policy=self.settings.password_policy,
            )
        )
        app.include_router(auth_router)
        app.include_router(register_router, prefix="/auth")
        if self.settings.openid20_migration_enabled:
            # Rôle OpenID 2.0 de l'OP (spec de migration) : les routes ne
            # sont montées que si le support est activé — sans lui, aucun
            # chemin n'est exposé.
            app.include_router(
                openid20_provider_router(self.openid20_provider, issuer=self.settings.issuer)
            )
        _mount_authorization_routers(
            app,
            authorize_usecase=self.authorize_usecase,
            par_usecase=self.par_usecase,
            client_reader=self.readers.client,
            consent_usecase=self.consent_usecase,
            request_object_resolver=self.request_object_resolver,
            par_enabled=self.settings.par_enabled,
            par_required=self.settings.par_required,
            require_login=self.settings.require_login,
            base_url=self.settings.base_url or self.settings.issuer,
            jarm_signer=self.jarm_signer,
            issuer=self.settings.issuer,
        )
        app.include_router(token_router(self.token_usecase, self.client_certificate_headers))
        app.include_router(device_authorization_router(self.device_usecase))
        app.include_router(device_page_router(self.device_usecase))
        if self.settings.ciba_enabled:
            app.include_router(
                backchannel_authorization_router(
                    self.backchannel_authorize_usecase, self.client_certificate_headers
                )
            )
        if self.settings.ciba_approval_enabled:
            app.include_router(ciba_approval_router(self.ciba_approval_usecase))
        app.include_router(
            userinfo_router(
                self.userinfo_usecase,
                self.client_certificate_headers,
                trust_proxy_headers=self.settings.trust_proxy_headers,
            )
        )
        if self.protected_resource_usecase is not None:
            app.include_router(
                protected_resource_router(
                    self.protected_resource_usecase,
                    self.client_certificate_headers,
                    trust_proxy_headers=self.settings.trust_proxy_headers,
                )
            )
        app.include_router(introspect_router(self.introspect_usecase))
        app.include_router(revocation_router(self.revocation_usecase))
        app.include_router(logout_router(self.logout_usecase))
        app.include_router(session_management_router(self.session_management, self.readers.client))
        if self.settings.registration_enabled:
            app.include_router(registration_router(self.registration_usecase))


def create_app(settings: Settings | None = None) -> FastAPI:
    """Assemble l'application FastAPI du serveur protocole."""
    settings = settings if settings is not None else Settings()
    deps = ProtocolDependencies(settings, build_stores(settings))
    app = FastAPI(
        title="PurIdentityServer — protocole",
        version=_PACKAGE_VERSION,
        description="Serveur OpenID Connect conforme aux specs OIDC Core 1.0 (protocole).",
        lifespan=deps.lifespan,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        swagger_ui_oauth2_redirect_url=settings.swagger_ui_oauth2_redirect_url,
        swagger_ui_init_oauth=(
            settings.swagger_ui_init_oauth if settings.swagger_ui_oauth2_enabled else None
        ),
    )
    app.add_middleware(DynamicCORSMiddleware, client_repository=deps.readers.client)
    app.add_middleware(
        SameOriginFormGuardMiddleware,
        trust_proxy_headers=settings.trust_proxy_headers,
    )
    deps.mount(app)
    return app


app = create_app()
