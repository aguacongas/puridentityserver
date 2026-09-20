"""Route FastAPI d'exposition des métadonnées OpenID Connect Discovery."""

from fastapi import APIRouter

from puridentityserver.application.discovery import DiscoveryUseCase
from puridentityserver.interfaces.schemas.discovery import DiscoveryDocument


def discovery_router(usecase: DiscoveryUseCase) -> APIRouter:
    """Construit le routeur FastAPI exposant les métadonnées de discovery."""
    router = APIRouter(tags=["discovery"])

    @router.get("/.well-known/openid-configuration", summary="OpenID Connect Discovery")
    async def openid_configuration() -> DiscoveryDocument:
        doc = await usecase.execute()
        return DiscoveryDocument(**doc)

    return router
