"""Façade de composition — sélection du serveur selon le rôle configuré.

Point d'entrée historiquement référencé (`uv run uvicorn
puridentityserver.server:app`) : il délègue la composition au serveur
correspondant au ``role`` configuré.

- ``role = "protocol"``  → ``puridentityprotocol.server`` (OIDC/OAuth,
  accès en lecture seule aux resources administrées) ;
- ``role = "admin"``     → ``puridentityadmin.server`` (CRUD des
  IdentityResources/ApiResources, sans aucun endpoint OIDC/OAuth) ;
- ``role = "full"``      → ``puridentityfull.server`` (protocole ⊕
  administration par-dessus les mêmes stores).

Chaque sous-serveur reste déployable indépendamment via son propre point
d'entrée, sans ce module.
"""

from __future__ import annotations

from fastapi import FastAPI

from puridentityserver.infrastructure.settings import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    """Assemble le serveur sélectionné par ``settings.role`` (défaut ``full``)."""
    settings = settings if settings is not None else Settings()
    if settings.role == "admin":
        from puridentityadmin.server import create_app as _create_admin_app

        return _create_admin_app(settings)
    if settings.role == "protocol":
        from puridentityprotocol.server import create_app as _create_protocol_app

        return _create_protocol_app(settings)
    from puridentityfull.server import create_app as _create_full_app

    return _create_full_app(settings)


app = create_app()
