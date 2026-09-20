"""Composition root — câblage de l'application FastAPI et injection des dépendances."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from puridentityserver.application.authorize import AuthorizeConfig, AuthorizeUseCase
from puridentityserver.application.consent import ConsentUseCase
from puridentityserver.application.device_authorize import (
    DeviceAuthorizationUseCase,
    DeviceConfig,
)
from puridentityserver.application.discovery import DiscoveryConfig, DiscoveryUseCase
from puridentityserver.application.identity_resource import IdentityResourceUseCase
from puridentityserver.application.introspect import IntrospectConfig, IntrospectUseCase
from puridentityserver.application.jwks import JWKSetConfig, JWKSetUseCase
from puridentityserver.application.logout import LogoutConfig, LogoutUseCase
from puridentityserver.application.par import PushedAuthorizationConfig, PushedAuthorizationUseCase
from puridentityserver.application.registration import RegistrationConfig, RegistrationUseCase
from puridentityserver.application.revocation import RevocationConfig, RevocationUseCase
from puridentityserver.application.token import TokenConfig, TokenUseCase
from puridentityserver.application.userinfo import UserInfoConfig, UserInfoUseCase
from puridentityserver.domain.jwks import JWTAlgorithm, KeyUse
from puridentityserver.domain.userinfo import UserClaims
from puridentityserver.identity.config import (
    apply_schema,
    auth_router,
    configure_identity,
    login_router,
    register_router,
    seed_users,
)
from puridentityserver.infrastructure.claims import UserStoreClaimsProvider
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.factory import (
    build_authorization_code_repository,
    build_client_repository,
    build_consent_repository,
    build_device_authorization_repository,
    build_identity_resource_repository,
    build_key_pair_repository,
    build_pushed_authorization_repository,
    build_refresh_token_repository,
    build_revoked_token_repository,
    build_user_repository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.interfaces.api.authorize import authorize_router
from puridentityserver.interfaces.api.consent import consent_router
from puridentityserver.interfaces.api.cors import DynamicCORSMiddleware
from puridentityserver.interfaces.api.device_authorize import device_authorization_router
from puridentityserver.interfaces.api.device_page import device_page_router
from puridentityserver.interfaces.api.discovery import discovery_router
from puridentityserver.interfaces.api.identity_resources import identity_resources_router
from puridentityserver.interfaces.api.introspect import introspect_router
from puridentityserver.interfaces.api.jwks import jwk_set_router
from puridentityserver.interfaces.api.logout import logout_router
from puridentityserver.interfaces.api.par import par_router
from puridentityserver.interfaces.api.registration import registration_router
from puridentityserver.interfaces.api.revocation import revocation_router
from puridentityserver.interfaces.api.token import token_router
from puridentityserver.interfaces.api.userinfo import userinfo_router
from puridentityserver.interfaces.repositories.client_repository import ClientRepository
from puridentityserver.interfaces.repositories.key_pair_repository import KeyPairRepository

_PACKAGE_VERSION = "0.1.0"


def _mount_authorization_routers(
    app: FastAPI,
    *,
    authorize_usecase: AuthorizeUseCase,
    par_usecase: PushedAuthorizationUseCase,
    client_repository: ClientRepository,
    consent_usecase: ConsentUseCase,
    par_enabled: bool,
) -> None:
    """Monte ``/authorize`` (+ ``/par`` + ``/consent`` selon la configuration)."""
    app.include_router(
        authorize_router(
            authorize_usecase,
            par_usecase=par_usecase if par_enabled else None,
            client_repository=client_repository,
            consent_usecase=consent_usecase,
        )
    )
    app.include_router(consent_router(consent_usecase, authorize_usecase, client_repository))
    if par_enabled:
        app.include_router(par_router(par_usecase))


def _primary_algorithm(settings: Settings) -> JWTAlgorithm:
    """Algorithme de signature principal, ou RS256 si aucun n'est configuré."""
    algorithms = settings.jwks_signing_algorithms
    return algorithms[0] if algorithms else JWTAlgorithm.RS256


class _Dependencies:
    """Registre des dépendances du serveur (repos, managers, usecases).

    La composition root construit toute la chaîne d'injection à partir des
    ``Settings`` ; l'instance expose aussi le hook de durée de session et le
    cycle de vie (seed + libération des stockages) consommés par FastAPI.
    """

    def __init__(self, settings: Settings) -> None:
        """Construit les manifestes, repositories et usecases pour ``settings``."""
        self.settings = settings

        key_repository = build_key_pair_repository(settings)
        self.key_repository: KeyPairRepository = key_repository
        self.key_manager = DefaultKeyManager(key_repository)
        self.session_key_manager = DefaultKeyManager(key_repository, use=KeyUse.SESSION)
        self.reset_key_manager = DefaultKeyManager(key_repository, use=KeyUse.RESET)
        self.verify_key_manager = DefaultKeyManager(key_repository, use=KeyUse.VERIFY)

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

        self.client_repository = build_client_repository(settings)
        self.code_repository = build_authorization_code_repository(settings)
        self.user_repository = build_user_repository(settings)
        self.revoked_token_repository = build_revoked_token_repository(settings)
        self.refresh_token_repository = build_refresh_token_repository(settings)
        self.device_code_repository = build_device_authorization_repository(settings)
        self.pushed_code_repository = build_pushed_authorization_repository(settings)
        self.consent_repository = build_consent_repository(settings)
        self.identity_resource_repository = build_identity_resource_repository(settings)

        self.authorize_usecase = AuthorizeUseCase(
            AuthorizeConfig(
                code_ttl_seconds=settings.authorization_code_ttl_seconds,
                access_token_ttl_seconds=settings.access_token_ttl_seconds,
                signing_algorithm=_primary_algorithm(settings),
                issuer=settings.issuer,
            ),
            self.client_repository,
            self.code_repository,
            self.token_manager,
        )
        self.token_usecase = TokenUseCase(
            TokenConfig(
                issuer=settings.issuer,
                signing_algorithm=_primary_algorithm(settings),
                access_token_ttl_seconds=settings.access_token_ttl_seconds,
                refresh_token_ttl_seconds=settings.refresh_token_ttl_seconds,
            ),
            self.client_repository,
            self.code_repository,
            self.token_manager,
            self.refresh_token_repository,
            self.device_code_repository,
        )
        self.device_usecase = DeviceAuthorizationUseCase(
            DeviceConfig(
                issuer=settings.issuer,
                base_url=settings.base_url,
                ttl_seconds=settings.device_code_ttl_seconds,
                interval_seconds=settings.device_code_interval_seconds,
            ),
            self.client_repository,
            self.device_code_repository,
        )
        self.userinfo_usecase = UserInfoUseCase(
            UserInfoConfig(issuer=settings.issuer),
            self.token_manager,
            UserStoreClaimsProvider(self.user_repository),
            self.revoked_token_repository,
            self.identity_resource_repository,
        )
        self.introspect_usecase = IntrospectUseCase(
            IntrospectConfig(issuer=settings.issuer),
            self.client_repository,
            self.token_manager,
            self.revoked_token_repository,
        )
        self.revocation_usecase = RevocationUseCase(
            RevocationConfig(issuer=settings.issuer),
            self.client_repository,
            self.token_manager,
            self.revoked_token_repository,
        )
        self.logout_usecase = LogoutUseCase(
            LogoutConfig(issuer=settings.issuer),
            self.client_repository,
            self.token_manager,
        )
        self.registration_usecase = RegistrationUseCase(
            RegistrationConfig(
                issuer=settings.issuer,
                base_url=settings.base_url,
                requires_initial_access_token=settings.registration_requires_initial_access_token,
                initial_access_token_hashes=settings.registration_initial_access_token_hashes,
            ),
            self.client_repository,
        )
        self.par_usecase = PushedAuthorizationUseCase(
            PushedAuthorizationConfig(ttl_seconds=settings.par_ttl_seconds),
            self.client_repository,
            self.pushed_code_repository,
        )
        self.consent_usecase = ConsentUseCase(self.consent_repository)

    async def resolve_session_lifetime(self, client_id: str) -> int | None:
        """Retourne la durée de session cookie configurée pour le client, si présente."""
        client = await self.client_repository.find_by_id(client_id)
        return client.session_lifetime_seconds if client is not None else None

    @asynccontextmanager
    async def lifespan(self, _app: FastAPI) -> AsyncGenerator[None, None]:
        """Prépare les stockages, alimente le registre clients + user store puis génère les clés."""
        await apply_schema()
        identity_users = await seed_users(self.settings.identity_seed_users)
        await self.key_repository.initialise()
        await self.client_repository.initialise()
        await self.code_repository.initialise()
        await self.user_repository.initialise()
        await self.revoked_token_repository.initialise()
        await self.refresh_token_repository.initialise()
        await self.device_code_repository.initialise()
        await self.pushed_code_repository.initialise()
        await self.consent_repository.initialise()
        await self.identity_resource_repository.initialise()
        for client in self.settings.seed_clients:
            await self.client_repository.save(client)
        for resource in self.settings.seed_identity_resources:
            await self.identity_resource_repository.save(resource)
        await self.user_repository.save_all(
            [
                UserClaims(subject=subject, claims=claims)
                for subject, claims in self.settings.users_seed.items()
                if subject not in identity_users  # profils d'identité → pont sous UUID ci-dessous
            ]
        )
        # Pont identité ⊕ user store : chaque compte configuré (UUID FastAPI
        # Users, `Settings.identity_seed_users`) récupère le profil seed
        # correspondant afin que /userinfo renvoie ses claims après un login
        # navigateur réel.
        for subject, user in identity_users.items():
            profile = self.settings.users_seed.get(subject)
            if profile is not None:
                await self.user_repository.save(UserClaims(subject=str(user.id), claims=profile))
        await self.jwks_usecase.initialise()
        for manager in (
            self.session_key_manager,
            self.reset_key_manager,
            self.verify_key_manager,
        ):
            await manager.ensure_active_key(2048, JWTAlgorithm.RS256)
        try:
            yield
        finally:
            await self.key_repository.close()
            await self.client_repository.close()
            await self.code_repository.close()
            await self.user_repository.close()
            await self.revoked_token_repository.close()
            await self.refresh_token_repository.close()
            await self.device_code_repository.close()
            await self.pushed_code_repository.close()
            await self.consent_repository.close()
            await self.identity_resource_repository.close()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Assemble l'application FastAPI autour du registre de dépendances fourni."""
    settings = settings if settings is not None else Settings()
    deps = _Dependencies(settings)

    app = FastAPI(
        title="PurIdentityServer",
        version=_PACKAGE_VERSION,
        description="Serveur OpenID Connect conforme aux specs OIDC Core 1.0.",
        lifespan=deps.lifespan,
    )
    app.add_middleware(DynamicCORSMiddleware, client_repository=deps.client_repository)
    app.include_router(
        discovery_router(
            DiscoveryUseCase(deps.config, identity_resources=deps.identity_resource_repository)
        )
    )
    app.include_router(
        identity_resources_router(IdentityResourceUseCase(deps.identity_resource_repository))
    )
    app.include_router(jwk_set_router(deps.jwks_usecase))
    app.include_router(login_router(deps.resolve_session_lifetime))
    app.include_router(auth_router)
    app.include_router(register_router, prefix="/auth")
    _mount_authorization_routers(
        app,
        authorize_usecase=deps.authorize_usecase,
        par_usecase=deps.par_usecase,
        client_repository=deps.client_repository,
        consent_usecase=deps.consent_usecase,
        par_enabled=settings.par_enabled,
    )
    app.include_router(token_router(deps.token_usecase))
    app.include_router(device_authorization_router(deps.device_usecase))
    app.include_router(device_page_router(deps.device_usecase))
    app.include_router(userinfo_router(deps.userinfo_usecase))
    app.include_router(introspect_router(deps.introspect_usecase))
    app.include_router(revocation_router(deps.revocation_usecase))
    app.include_router(logout_router(deps.logout_usecase))
    if settings.registration_enabled:
        app.include_router(registration_router(deps.registration_usecase))
    return app


app = create_app()
