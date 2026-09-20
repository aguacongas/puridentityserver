"""Cas d'utilisation : gestion (CRUD) des IdentityResources (scopes identité).

Les IdentityResources déclarent les scopes identité du serveur et les
claims qu'ils exposent. Elles alimentent ``scopes_supported`` /
``claims_supported`` du discovery et le filtrage des claims de
``/userinfo`` selon le scope accordé au jeton (OIDC Core 1.0 §5.4).

Ce usecase expose la gestion du registre (liste, création, lecture, mise
à jour, suppression), cohérente avec les seeds ``clients_seed`` /
``identity_resources_seed`` de la configuration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from puridentityserver.domain.identity_resource import IdentityResource
from puridentityserver.interfaces.repositories.identity_resource_repository import (
    IdentityResourceRepository,
)

_MAX_NAME_LENGTH = 128
_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass(frozen=True, slots=True)
class IdentityResourceRequest:
    """Description d'une IdentityResource reçue de l'API de gestion."""

    name: str
    display_name: str = ""
    user_claims: frozenset[str] = frozenset()
    show_in_discovery_document: bool = True


@dataclass(frozen=True, slots=True)
class IdentityResourceData:
    """Réponse de gestion : une IdentityResource normalisée."""

    name: str
    display_name: str = ""
    user_claims: list[str] = field(default_factory=list)
    show_in_discovery_document: bool = True


@dataclass(frozen=True, slots=True)
class IdentityResourceError:
    """Rejet d'une demande de gestion (message + statut HTTP)."""

    error: str
    error_description: str = ""
    status_code: int = 400


class IdentityResourceUseCase:
    """Crée, liste, lit, met à jour et supprime les IdentityResources."""

    def __init__(self, repository: IdentityResourceRepository) -> None:
        """Injection du repository de persistance des resources."""
        self._repository = repository

    async def list(self) -> list[IdentityResourceData]:
        """Retourne la liste ordonnée des IdentityResources enregistrées."""
        resources = await self._repository.find_all()
        return [_to_data(resource) for resource in resources]

    async def create(
        self, request: IdentityResourceRequest
    ) -> IdentityResourceData | IdentityResourceError:
        """Crée une nouvelle IdentityResource (ou retourne une erreur)."""
        resource = _parse_request(request)
        if isinstance(resource, IdentityResourceError):
            return resource
        if await self._repository.find_by_name(resource.name) is not None:
            return IdentityResourceError(
                "invalid_identity_resource",
                f"Une IdentityResource nommée «{resource.name}» existe déjà",
                409,
            )
        await self._repository.save(resource)
        return _to_data(resource)

    async def read(self, name: str) -> IdentityResourceData | IdentityResourceError:
        """Lit la IdentityResource identifiée par ``name``, ou une 404."""
        resource = await self._repository.find_by_name(name)
        if resource is None:
            return IdentityResourceError(
                "invalid_identity_resource", f"IdentityResource inconnue : {name}", 404
            )
        return _to_data(resource)

    async def update(
        self, name: str, request: IdentityResourceRequest
    ) -> IdentityResourceData | IdentityResourceError:
        """Remplace une IdentityResource existante (le nom reste stable)."""
        current = await self._repository.find_by_name(name)
        if current is None:
            return IdentityResourceError(
                "invalid_identity_resource", f"IdentityResource inconnue : {name}", 404
            )
        requested = _parse_request(request)
        if isinstance(requested, IdentityResourceError):
            return requested
        updated = IdentityResource(
            name=current.name,
            display_name=requested.display_name,
            user_claims=requested.user_claims,
            show_in_discovery_document=requested.show_in_discovery_document,
        )
        await self._repository.save(updated)
        return _to_data(updated)

    async def delete(self, name: str) -> IdentityResourceError | None:
        """Supprime l'IdentityResource identifiée par ``name`` (404 si inconnue)."""
        resource = await self._repository.find_by_name(name)
        if resource is None:
            return IdentityResourceError(
                "invalid_identity_resource", f"IdentityResource inconnue : {name}", 404
            )
        await self._repository.delete(name)
        return None


def _parse_request(request: IdentityResourceRequest) -> IdentityResource | IdentityResourceError:
    """Valide la demande et construit l'entité domaine."""
    name = request.name.strip()
    if not name:
        return IdentityResourceError(
            "invalid_identity_resource", "Le nom d'une IdentityResource est requis"
        )
    if len(name) > _MAX_NAME_LENGTH:
        return IdentityResourceError(
            "invalid_identity_resource",
            f"Le nom d'une IdentityResource est limité à {_MAX_NAME_LENGTH} caractères",
        )
    if _NAME_PATTERN.fullmatch(name) is None:
        return IdentityResourceError(
            "invalid_identity_resource",
            "Le nom d'une IdentityResource ne peut contenir que des caractères "
            "alphanumériques, des points, tirets et undescores",
        )
    claims = frozenset(claim.strip() for claim in request.user_claims if claim.strip())
    return IdentityResource(
        name=name,
        display_name=request.display_name.strip(),
        user_claims=claims,
        show_in_discovery_document=request.show_in_discovery_document,
    )


def _to_data(resource: IdentityResource) -> IdentityResourceData:
    """Normalise une entité domaine en réponse de gestion."""
    return IdentityResourceData(
        name=resource.name,
        display_name=resource.display_name,
        user_claims=sorted(resource.user_claims),
        show_in_discovery_document=resource.show_in_discovery_document,
    )
