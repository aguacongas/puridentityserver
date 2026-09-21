"""Composition root du serveur ``full`` — protocole ⊕ administration.

Assemble en un seul process les serveurs **protocole** et
**administration** par-dessus **les mêmes instances de stockage**
(``Stores`` construit une seule fois) : un déploiement mémoire seule ou
mono-serveur où les écritures de l'administration (IdentityResources,
ApiResources, Dynamic Client Registration) sont immédiatement visibles
du protocole, et réciproquement.

Chaque sous-serveur reste une brique autonome (``ProtocolDependencies``
/ ``AdminDependencies``) : le code n'est pas dupliqué, on compose les
deux compositions roots.
"""

from __future__ import annotations

from fastapi import FastAPI

from puridentityadmin.server import AdminDependencies
from puridentityprotocol.server import ProtocolDependencies
from puridentityserver.infrastructure.persistence.stores import build_stores
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.interfaces.api.cors import DynamicCORSMiddleware

_PACKAGE_VERSION = "0.1.0"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Assemble l'application FastAPI complète (protocole + administration).

    Les stores sont construits une seule fois et partagés entre les deux
    sous-serveurs ; le cycle de vie complet (resources + protocole) est
    porté par le serveur protocole.
    """
    settings = settings if settings is not None else Settings()
    stores = build_stores(settings)
    protocol = ProtocolDependencies(settings, stores)
    admin = AdminDependencies(settings, stores)

    app = FastAPI(
        title="PurIdentityServer",
        version=_PACKAGE_VERSION,
        description="Serveur OpenID Connect conforme aux specs OIDC Core 1.0, "
        "avec administration intégrée.",
        lifespan=protocol.lifespan,
    )
    app.add_middleware(DynamicCORSMiddleware, client_repository=protocol.readers.client)
    protocol.mount(app)
    admin.mount(app)
    return app


app = create_app()
