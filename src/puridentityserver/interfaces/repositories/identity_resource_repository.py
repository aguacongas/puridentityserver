"""Port de persistance des IdentityResources (scopes identité OIDC §5.4)."""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.identity_resource import IdentityResource


class IdentityResourceRepository(Protocol):
    """Contrat de stockage des IdentityResources.

    Le port définit les opérations nécessaires au cycle de vie des
    resources (création, lecture pour le discovery et le filtrage
    ``/userinfo``, mise à jour, suppression) ainsi que son cycle de vie
    propre (initialisation du schéma, libération des ressources). Les
    implémentations concrètes (mémoire, SQL, Redis, MongoDB…) sont
    fournies en infrastructure et choisies à la composition root selon la
    configuration du serveur.
    """

    async def save(self, resource: IdentityResource) -> None:
        """Enregistre la resource (insertion ou mise à jour par ``name``)."""
        ...

    async def find_by_name(self, name: str) -> IdentityResource | None:
        """Retourne la resource identifiée par ``name``, ou ``None``."""
        ...

    async def find_all(self) -> list[IdentityResource]:
        """Retourne toutes les resources enregistrées."""
        ...

    async def delete(self, name: str) -> None:
        """Supprime la resource identifiée par ``name`` (idempotent)."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (crée le schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du repository (connexions, moteur…)."""
        ...
