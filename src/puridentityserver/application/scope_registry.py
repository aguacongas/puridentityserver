"""Registre applicatif des scopes connus et résolution des audiences.

Regroupe les scopes acceptés par le serveur : les IdentityResources
(scopes identité OIDC) et les scopes déclarés par les ``ApiResource``
(scopes d'API). Tout scope demandé hors registre est refusé
(``invalid_scope``) ; l'``aud`` d'un access token porte le nom des
resources protégées dont des scopes ont été accordés (sinon l'identifiant
du client émetteur, audience historique des tokens du serveur).
"""

from __future__ import annotations

from puridentityserver.domain.identity_resource import DEFAULT_IDENTITY_RESOURCES
from puridentityserver.interfaces.repositories.api_resource_repository import (
    ApiResourceRepository,
)
from puridentityserver.interfaces.repositories.identity_resource_repository import (
    IdentityResourceRepository,
)


class ScopeRegistry:
    """Vérifie l'enregistrement des scopes et calcule les audiences API."""

    def __init__(
        self,
        identity_resources: IdentityResourceRepository | None = None,
        api_resources: ApiResourceRepository | None = None,
    ) -> None:
        """Injection des registres de resources (identité et API)."""
        self._identity_resources = identity_resources
        self._api_resources = api_resources

    async def unknown_scopes(self, scopes: frozenset[str]) -> tuple[str, ...]:
        """Scopes demandés jamais enregistrés (identité ⊕ API), triés."""
        known = await self.known_scope_names()
        return tuple(sorted(name for name in scopes if name not in known))

    async def known_scope_names(self) -> frozenset[str]:
        """Noms de tous les scopes acceptés (défauts identité + registres)."""
        names = {resource.name for resource in DEFAULT_IDENTITY_RESOURCES}
        if self._identity_resources is not None:
            identity_stored = await self._identity_resources.find_all()
            names.update(resource.name for resource in identity_stored)
        if self._api_resources is not None:
            api_stored = await self._api_resources.find_all()
            for resource in api_stored:
                names.update(resource.scopes)
        return frozenset(names)

    async def audiences_for(self, client_id: str, scopes: frozenset[str]) -> str | list[str]:
        """Audience d'un access token : resources dont des scopes sont accordés.

        Retourne le nom unique (``str``) quand une seule resource est
        concernée, la liste triée des noms dans le cas contraire, et
        ``client_id`` quand aucun scope d'API n'est accordé (comportement
        historique du serveur).
        """
        if self._api_resources is None:
            return client_id
        stored = await self._api_resources.find_all()
        audiences = [resource.name for resource in stored if resource.scopes & set(scopes)]
        if not audiences:
            return client_id
        audiences = sorted(audiences)
        return audiences[0] if len(audiences) == 1 else audiences
