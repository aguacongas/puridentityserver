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
from puridentityserver.application.claim_authorizer import BearerClaimAuthorizer, ClaimRule
from puridentityserver.application.consent import ConsentUseCase
from puridentityserver.application.device_authorize import (
    DeviceAuthorizationUseCase,
    DeviceConfig,
)
from puridentityserver.application.discovery import DiscoveryConfig, DiscoveryUseCase
from puridentityserver.application.introspect import IntrospectConfig, IntrospectUseCase
from puridentityserver.application.jwks import JWKSetConfig, JWKSetUseCase
from puridentityserver.application.logout import LogoutConfig, LogoutUseCase
from puridentityserver.application.par import PushedAuthorizationConfig, PushedAuthorizationUseCase
from puridentityserver.application.registration import RegistrationConfig, RegistrationUseCase
from puridentityserver.application.revocation import RevocationConfig, RevocationUseCase
from puridentityserver.application.scope_registry import ScopeRegistry
from puridentityserver.application.token import TokenConfig, TokenUseCase
from puridentityserver.application.userinfo import UserInfoConfig, UserInfoUseCase
from puridentityserver.domain.authorization import TokenEndpointAuthMethod
from puridentityserver.domain.jwks import SYMMETRIC_ALGORITHMS, JWTAlgorithm, KeyUse
from puridentityserver.domain.userinfo import UserClaims
from puridentityserver.identity.config import (
    auth_router,
    configure_identity,
    login_router,
    register_router,
    seed_users,
)
from puridentityserver.infrastructure.backchannel import HTTPBackchannelNotifier
from puridentityserver.infrastructure.bearer import build_bearer_verifier
from puridentityserver.infrastructure.claims import UserStoreClaimsProvider
from puridentityserver.infrastructure.client_assertions import PyJWTClientAssertionVerifier
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
from puridentityserver.infrastructure.secrets import AsymmetricSecretCipher, load_seal_key_pair
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.interfaces.api.authorize import authorize_router
from puridentityserver.interfaces.api.consent import consent_router
from puridentityserver.interfaces.api.cors import DynamicCORSMiddleware
from puridentityserver.interfaces.api.device_authorize import device_authorization_router
from puridentityserver.interfaces.api.device_page import device_page_router
from puridentityserver.interfaces.api.discovery import discovery_router
from puridentityserver.interfaces.api.introspect import introspect_router
from puridentityserver.interfaces.api.jwks import jwk_set_router
from puridentityserver.interfaces.api.logout import logout_router
from puridentityserver.interfaces.api.par import par_router
from puridentityserver.interfaces.api.registration import registration_router
from puridentityserver.interfaces.api.revocation import revocation_router
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


def _mount_authorization_routers(
    app: FastAPI,
    *,
    authorize_usecase: AuthorizeUseCase,
    par_usecase: PushedAuthorizationUseCase,
    client_reader: ClientReader,
    consent_usecase: ConsentUseCase,
    par_enabled: bool,
) -> None:
    """Monte ``/authorize`` (+ ``/par`` + ``/consent`` selon la configuration)."""
    app.include_router(
        authorize_router(
            authorize_usecase,
            par_usecase=par_usecase if par_enabled else None,
            client_repository=client_reader,
            consent_usecase=consent_usecase,
        )
    )
    app.include_router(consent_router(consent_usecase, authorize_usecase, client_reader))
    if par_enabled:
        app.include_router(par_router(par_usecase))


class ProtocolDependencies:
    """Conteneur des dépendances du serveur protocole (repos, managers, usecases).

    Construit la chaîne d'injection du protocole à partir des
    ``Settings`` et des ``Stores`` partagés (construits localement en
    déploiement séparé, fournis par le serveur ``full`` sinon) ; expose le
    cycle de vie (seed + libération) et la durée de session par client.
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
        )
        self.config = DiscoveryConfig(
            issuer=settings.issuer,
            base_url=settings.base_url,
            registration_enabled=settings.registration_enabled,
            par_enabled=settings.par_enabled,
            signing_algorithms=settings.jwks_algorithms,
            encryption_algorithms=settings.jwks_encryption_algorithms,
            encryption_methods=settings.jwks_encryption_methods,
            token_endpoint_auth_methods=self._token_endpoint_auth_methods(),
        )
        self.jwks_usecase = JWKSetUseCase(
            JWKSetConfig(
                key_size=settings.jwks_key_size,
                algorithms=settings.jwks_signing_algorithms,
                rotation_days=settings.jwks_rotation_days,
                grace_period_days=settings.jwks_grace_period_days,
            ),
            self.key_manager,
        )
        self.token_manager = PyJWTTokenManager(self.key_manager)
        self.secret_cipher = AsymmetricSecretCipher(self.secret_key_manager)
        self.id_token_encrypter = JWEIdTokenEncrypter()
        self.client_assertions = PyJWTClientAssertionVerifier(self.secret_cipher)
        self.bearer_verifier = build_bearer_verifier(settings, self.token_manager)
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
        )
        self.scope_registry = ScopeRegistry(
            self.readers.identity_resource, self.readers.api_resource
        )

        self.authorize_usecase = AuthorizeUseCase(
            AuthorizeConfig(
                code_ttl_seconds=settings.authorization_code_ttl_seconds,
                access_token_ttl_seconds=settings.access_token_ttl_seconds,
                signing_algorithm=_primary_algorithm(settings),
                issuer=settings.issuer,
                secret_cipher=self.secret_cipher,
                id_token_encrypter=self.id_token_encrypter,
            ),
            self.readers.client,
            stores.code,
            self.token_manager,
            self.scope_registry,
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
            ),
            self.readers.client,
            stores.code,
            self.token_manager,
            stores.refresh,
            stores.device,
            self.scope_registry,
            self.client_assertions,
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
        self.userinfo_usecase = UserInfoUseCase(
            UserInfoConfig(issuer=settings.issuer),
            self.token_manager,
            UserStoreClaimsProvider(self.readers.user),
            stores.revoked,
            self.readers.identity_resource,
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
            LogoutConfig(issuer=settings.issuer),
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
            ),
            stores.client,
            self.scope_registry,
            self.registration_authorizer,
            self.secret_cipher,
        )
        self.par_usecase = PushedAuthorizationUseCase(
            PushedAuthorizationConfig(ttl_seconds=settings.par_ttl_seconds),
            self.readers.client,
            stores.pushed,
            self.scope_registry,
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
        app.include_router(
            discovery_router(
                DiscoveryUseCase(
                    self.config,
                    identity_resources=self.readers.identity_resource,
                    api_resources=self.readers.api_resource,
                )
            )
        )
        app.include_router(jwk_set_router(self.jwks_usecase))
        app.include_router(login_router(self.resolve_session_lifetime))
        app.include_router(auth_router)
        app.include_router(register_router, prefix="/auth")
        _mount_authorization_routers(
            app,
            authorize_usecase=self.authorize_usecase,
            par_usecase=self.par_usecase,
            client_reader=self.readers.client,
            consent_usecase=self.consent_usecase,
            par_enabled=self.settings.par_enabled,
        )
        app.include_router(token_router(self.token_usecase))
        app.include_router(device_authorization_router(self.device_usecase))
        app.include_router(device_page_router(self.device_usecase))
        app.include_router(userinfo_router(self.userinfo_usecase))
        app.include_router(introspect_router(self.introspect_usecase))
        app.include_router(revocation_router(self.revocation_usecase))
        app.include_router(logout_router(self.logout_usecase))
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
    )
    app.add_middleware(DynamicCORSMiddleware, client_repository=deps.readers.client)
    deps.mount(app)
    return app


app = create_app()
