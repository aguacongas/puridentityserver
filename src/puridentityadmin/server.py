"""Composition root du serveur administration — gestion des resources.

Assemble l'application FastAPI du serveur **administration** : les
endpoints CRUD des IdentityResources et des ApiResources, protégés par
un JWT portant le claim administrateur configuré. Ce serveur écrit dans
les stores des resources (partagés avec le protocole en déploiement
``full``, ou un magasin commun en déploiement séparé) ; il n'expose
**aucun** endpoint OIDC/OAuth.

Déployé seul (``puridentityadmin.server:app``), il construit ses propres
stores depuis la configuration ; le serveur ``full`` le compose
par-dessus des stores partagés (``puridentityfull.server``).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from puridentityserver.application.api_resource import ApiResourceUseCase
from puridentityserver.application.claim_authorizer import BearerClaimAuthorizer, ClaimRule
from puridentityserver.application.identity_resource import IdentityResourceUseCase
from puridentityserver.infrastructure.bearer import build_bearer_verifier
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.stores import (
    Stores,
    build_stores,
    close_resources,
    initialise_resources,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.infrastructure.tokens import PyJWTTokenManager
from puridentityserver.interfaces.api.api_resources import api_resources_router
from puridentityserver.interfaces.api.cors import DynamicCORSMiddleware
from puridentityserver.interfaces.api.identity_resources import identity_resources_router

_PACKAGE_VERSION = "0.1.0"


class AdminDependencies:
    """Conteneur des dépendances du serveur administration.

    Construit l'autorisation Bearer (local si l'issuer de gestion est
    celui du serveur, JWKS distant sinon) et les usecases CRUD des
    resources à partir des ``Settings`` et des ``Stores`` partagés.
    """

    def __init__(self, settings: Settings, stores: Stores) -> None:
        """Construit le vérificateur, l'autoriseur et les usecases CRUD."""
        self.settings = settings
        self.stores = stores
        self.token_manager = PyJWTTokenManager(DefaultKeyManager(stores.key_pair))
        self.bearer_verifier = build_bearer_verifier(settings, self.token_manager)
        self.admin_authorizer = (
            BearerClaimAuthorizer(
                self.bearer_verifier,
                ClaimRule(
                    settings.admin_required_claim,
                    frozenset(settings.admin_required_claim_values),
                ),
            )
            if settings.admin_protected
            else None
        )
        self.identity_resources_usecase = IdentityResourceUseCase(stores.identity_resource)
        self.api_resources_usecase = ApiResourceUseCase(stores.api_resource)

    @asynccontextmanager
    async def lifespan(self, _app: FastAPI) -> AsyncGenerator[None, None]:
        """Prépare les stores des resources puis les libère à l'arrêt."""
        await initialise_resources(self.stores, self.settings)
        try:
            yield
        finally:
            await close_resources(self.stores)

    def mount(self, app: FastAPI) -> None:
        """Monte les endpoints de gestion des resources sur ``app``."""
        app.include_router(
            identity_resources_router(
                self.identity_resources_usecase,
                authorizer=self.admin_authorizer,
            )
        )
        app.include_router(
            api_resources_router(self.api_resources_usecase, authorizer=self.admin_authorizer)
        )


def create_app(settings: Settings | None = None) -> FastAPI:
    """Assemble l'application FastAPI du serveur administration."""
    settings = settings if settings is not None else Settings()
    deps = AdminDependencies(settings, build_stores(settings))
    app = FastAPI(
        title="PurIdentityServer — administration",
        version=_PACKAGE_VERSION,
        description="Gestion des IdentityResources et ApiResources de PurIdentityServer.",
        lifespan=deps.lifespan,
    )
    app.add_middleware(DynamicCORSMiddleware, client_repository=deps.stores.client)
    deps.mount(app)
    return app


app = create_app()
