"""Composition root — câblage de l'application FastAPI et injection des dépendances."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from puridentityserver.application.authorize import AuthorizeConfig, AuthorizeUseCase
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
    build_device_authorization_repository,
    build_key_pair_repository,
    build_pushed_authorization_repository,
    build_refresh_token_repository,
    build_revoked_token_repository,
    build_user_repository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.interfaces.api.authorize import authorize_router
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
from puridentityserver.interfaces.repositories.client_repository import ClientRepository

_PACKAGE_VERSION = "0.1.0"


def _mount_authorization_routers(
    app: FastAPI,
    *,
    authorize_usecase: AuthorizeUseCase,
    par_usecase: PushedAuthorizationUseCase,
    client_repository: ClientRepository,
    par_enabled: bool,
) -> None:
    """Monte ``/authorize`` (+ ``/par`` quand la Pushed Authorization Request est activée)."""
    app.include_router(
        authorize_router(
            authorize_usecase,
            par_usecase=par_usecase if par_enabled else None,
            client_repository=client_repository,
        )
    )
    if par_enabled:
        app.include_router(par_router(par_usecase))


def create_app(settings: Settings | None = None) -> FastAPI:
    """Assemble l'application FastAPI ; câble les usecases avec les réglages fournis."""
    settings = settings if settings is not None else Settings()

    key_repository = build_key_pair_repository(settings)
    key_manager = DefaultKeyManager(key_repository)
    session_key_manager = DefaultKeyManager(key_repository, use=KeyUse.SESSION)
    reset_key_manager = DefaultKeyManager(key_repository, use=KeyUse.RESET)
    verify_key_manager = DefaultKeyManager(key_repository, use=KeyUse.VERIFY)

    configure_identity(
        session_key_manager=session_key_manager,
        reset_token_key_manager=reset_key_manager,
        verification_token_key_manager=verify_key_manager,
        cookie_lifetime_seconds=settings.identity_jwt_lifetime_seconds,
        session_rotation_days=settings.jwks_rotation_days,
        session_grace_period_days=settings.jwks_grace_period_days,
    )
    config = DiscoveryConfig(
        issuer=settings.issuer,
        base_url=settings.base_url,
        registration_enabled=settings.registration_enabled,
        par_enabled=settings.par_enabled,
        signing_algorithms=settings.jwks_algorithms,
    )

    jwks_config = JWKSetConfig(
        key_size=settings.jwks_key_size,
        algorithms=settings.jwks_signing_algorithms,
        rotation_days=settings.jwks_rotation_days,
        grace_period_days=settings.jwks_grace_period_days,
    )
    jwks_usecase = JWKSetUseCase(jwks_config, key_manager)
    token_manager = PyJWTTokenManager(key_manager)

    client_repository = build_client_repository(settings)
    code_repository = build_authorization_code_repository(settings)
    user_repository = build_user_repository(settings)
    revoked_token_repository = build_revoked_token_repository(settings)
    refresh_token_repository = build_refresh_token_repository(settings)
    device_code_repository = build_device_authorization_repository(settings)
    pushed_code_repository = build_pushed_authorization_repository(settings)

    authorize_usecase = AuthorizeUseCase(
        AuthorizeConfig(
            code_ttl_seconds=settings.authorization_code_ttl_seconds,
            access_token_ttl_seconds=settings.access_token_ttl_seconds,
            signing_algorithm=settings.jwks_signing_algorithms[0]
            if settings.jwks_signing_algorithms
            else JWTAlgorithm.RS256,
            issuer=settings.issuer,
        ),
        client_repository,
        code_repository,
        token_manager,
    )
    token_usecase = TokenUseCase(
        TokenConfig(
            issuer=settings.issuer,
            signing_algorithm=settings.jwks_signing_algorithms[0]
            if settings.jwks_signing_algorithms
            else JWTAlgorithm.RS256,
            access_token_ttl_seconds=settings.access_token_ttl_seconds,
            refresh_token_ttl_seconds=settings.refresh_token_ttl_seconds,
        ),
        client_repository,
        code_repository,
        token_manager,
        refresh_token_repository,
        device_code_repository,
    )
    device_usecase = DeviceAuthorizationUseCase(
        DeviceConfig(
            issuer=settings.issuer,
            base_url=settings.base_url,
            ttl_seconds=settings.device_code_ttl_seconds,
            interval_seconds=settings.device_code_interval_seconds,
        ),
        client_repository,
        device_code_repository,
    )
    userinfo_usecase = UserInfoUseCase(
        UserInfoConfig(issuer=settings.issuer),
        token_manager,
        UserStoreClaimsProvider(user_repository),
        revoked_token_repository,
    )
    introspect_usecase = IntrospectUseCase(
        IntrospectConfig(issuer=settings.issuer),
        client_repository,
        token_manager,
        revoked_token_repository,
    )
    revocation_usecase = RevocationUseCase(
        RevocationConfig(issuer=settings.issuer),
        client_repository,
        token_manager,
        revoked_token_repository,
    )
    logout_usecase = LogoutUseCase(
        LogoutConfig(issuer=settings.issuer),
        client_repository,
        token_manager,
    )
    registration_usecase = RegistrationUseCase(
        RegistrationConfig(
            issuer=settings.issuer,
            base_url=settings.base_url,
            requires_initial_access_token=settings.registration_requires_initial_access_token,
            initial_access_token_hashes=settings.registration_initial_access_token_hashes,
        ),
        client_repository,
    )
    par_usecase = PushedAuthorizationUseCase(
        PushedAuthorizationConfig(ttl_seconds=settings.par_ttl_seconds),
        client_repository,
        pushed_code_repository,
    )

    async def _resolve_session_lifetime(client_id: str) -> int | None:
        """Retourne la durée de session cookie configurée pour le client, si présente."""
        client = await client_repository.find_by_id(client_id)
        return client.session_lifetime_seconds if client is not None else None

    @asynccontextmanager
    async def _lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
        """Prépare les stockages, alimente le registre clients + user store puis génère les clés."""
        await apply_schema()
        identity_users = await seed_users(settings.identity_seed_users)
        await key_repository.initialise()
        await client_repository.initialise()
        await code_repository.initialise()
        await user_repository.initialise()
        await revoked_token_repository.initialise()
        await refresh_token_repository.initialise()
        await device_code_repository.initialise()
        await pushed_code_repository.initialise()
        for client in settings.seed_clients:
            await client_repository.save(client)
        await user_repository.save_all(
            [
                UserClaims(subject=subject, claims=claims)
                for subject, claims in settings.users_seed.items()
                if subject not in identity_users  # profils d'identité → pont sous UUID ci-dessous
            ]
        )
        # Pont identité ⊕ user store : chaque compte configuré (UUID FastAPI
        # Users, `Settings.identity_seed_users`) récupère le profil seed
        # correspondant afin que /userinfo renvoie ses claims après un login
        # navigateur réel.
        for subject, user in identity_users.items():
            profile = settings.users_seed.get(subject)
            if profile is not None:
                await user_repository.save(UserClaims(subject=str(user.id), claims=profile))
        await jwks_usecase.initialise()
        for manager in (
            session_key_manager,
            reset_key_manager,
            verify_key_manager,
        ):
            await manager.ensure_active_key(2048, JWTAlgorithm.RS256)
        try:
            yield
        finally:
            await key_repository.close()
            await client_repository.close()
            await code_repository.close()
            await user_repository.close()
            await revoked_token_repository.close()
            await refresh_token_repository.close()
            await device_code_repository.close()
            await pushed_code_repository.close()

    app = FastAPI(
        title="PurIdentityServer",
        version=_PACKAGE_VERSION,
        description="Serveur OpenID Connect conforme aux specs OIDC Core 1.0.",
        lifespan=_lifespan,
    )
    app.include_router(discovery_router(DiscoveryUseCase(config)))
    app.include_router(jwk_set_router(jwks_usecase))
    app.include_router(login_router(_resolve_session_lifetime))
    app.include_router(auth_router)
    app.include_router(register_router, prefix="/auth")
    _mount_authorization_routers(
        app,
        authorize_usecase=authorize_usecase,
        par_usecase=par_usecase,
        client_repository=client_repository,
        par_enabled=settings.par_enabled,
    )
    app.include_router(token_router(token_usecase))
    app.include_router(device_authorization_router(device_usecase))
    app.include_router(device_page_router(device_usecase))
    app.include_router(userinfo_router(userinfo_usecase))
    app.include_router(introspect_router(introspect_usecase))
    app.include_router(revocation_router(revocation_usecase))
    app.include_router(logout_router(logout_usecase))
    if settings.registration_enabled:
        app.include_router(registration_router(registration_usecase))
    return app


app = create_app()
