"""Composition root — câblage de l'application FastAPI et injection des dépendances."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from thepuroidc.application.authorize import AuthorizeConfig, AuthorizeUseCase
from thepuroidc.application.discovery import DiscoveryConfig, DiscoveryUseCase
from thepuroidc.application.jwks import JWKSetConfig, JWKSetUseCase
from thepuroidc.application.token import TokenConfig, TokenUseCase
from thepuroidc.application.userinfo import UserInfoConfig, UserInfoUseCase
from thepuroidc.domain.jwks import JWTAlgorithm, KeyUse
from thepuroidc.domain.userinfo import UserClaims
from thepuroidc.identity.config import (
    apply_schema,
    auth_router,
    configure_identity,
    login_router,
    register_router,
    seed_users,
)
from thepuroidc.infrastructure.claims import UserStoreClaimsProvider
from thepuroidc.infrastructure.jwks import DefaultKeyManager
from thepuroidc.infrastructure.persistence.factory import (
    build_authorization_code_repository,
    build_client_repository,
    build_key_pair_repository,
    build_user_repository,
)
from thepuroidc.infrastructure.settings import Settings
from thepuroidc.infrastructure.tokens import PyJWTTokenManager
from thepuroidc.interfaces.api.authorize import authorize_router
from thepuroidc.interfaces.api.discovery import discovery_router
from thepuroidc.interfaces.api.jwks import jwk_set_router
from thepuroidc.interfaces.api.token import token_router
from thepuroidc.interfaces.api.userinfo import userinfo_router

_PACKAGE_VERSION = "0.1.0"


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

    authorize_usecase = AuthorizeUseCase(
        AuthorizeConfig(
            code_ttl_seconds=settings.authorization_code_ttl_seconds,
            signing_algorithm=settings.jwks_signing_algorithms[0].value
            if settings.jwks_signing_algorithms
            else "RS256",
        ),
        client_repository,
        code_repository,
    )
    token_usecase = TokenUseCase(
        TokenConfig(
            issuer=settings.issuer,
            signing_algorithm=settings.jwks_signing_algorithms[0]
            if settings.jwks_signing_algorithms
            else JWTAlgorithm.RS256,
            access_token_ttl_seconds=settings.access_token_ttl_seconds,
        ),
        client_repository,
        code_repository,
        token_manager,
    )
    userinfo_usecase = UserInfoUseCase(
        UserInfoConfig(issuer=settings.issuer),
        token_manager,
        UserStoreClaimsProvider(user_repository),
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

    app = FastAPI(
        title="ThePurOidc",
        version=_PACKAGE_VERSION,
        description="Serveur OpenID Connect conforme aux specs OIDC Core 1.0.",
        lifespan=_lifespan,
    )
    app.include_router(discovery_router(DiscoveryUseCase(config)))
    app.include_router(jwk_set_router(jwks_usecase))
    app.include_router(login_router(_resolve_session_lifetime))
    app.include_router(auth_router)
    app.include_router(register_router)
    app.include_router(authorize_router(authorize_usecase))
    app.include_router(token_router(token_usecase))
    app.include_router(userinfo_router(userinfo_usecase))
    return app


app = create_app()
