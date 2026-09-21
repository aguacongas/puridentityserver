"""Cas d'utilisation : gestion (CRUD) des ApiResources (ressources protégées).

Les ApiResources déclarent les audiences API du serveur et leurs scopes
d'API. Ces scopes alimentent ``scopes_supported`` du discovery, sont
acceptés aux endpoints d'émission uniquement s'ils sont enregistrés, et
l'``aud`` d'un access token porte le nom des resources dont des scopes
ont été accordés.

Ce usecase expose la gestion du registre (liste, création, lecture, mise
à jour, suppression), cohérente avec le seed ``api_resources_seed`` de la
configuration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from puridentityserver.domain.api_resource import ApiResource
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.interfaces.repositories.api_resource_repository import (
    ApiResourceRepository,
)

_MAX_NAME_LENGTH = 128
_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass(frozen=True, slots=True)
class ApiResourceRequest:
    """Description d'une ApiResource reçue de l'API de gestion."""

    name: str
    display_name: str = ""
    scopes: frozenset[str] = frozenset()
    allowed_access_token_signing_algos: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class ApiResourceData:
    """Réponse de gestion : une ApiResource normalisée."""

    name: str
    display_name: str = ""
    scopes: list[str] = field(default_factory=list)
    allowed_access_token_signing_algos: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ApiResourceError:
    """Rejet d'une demande de gestion (message + statut HTTP)."""

    error: str
    error_description: str = ""
    status_code: int = 400


class ApiResourceUseCase:
    """Crée, liste, lit, met à jour et supprime les ApiResources."""

    def __init__(self, repository: ApiResourceRepository) -> None:
        """Injection du repository de persistance des resources."""
        self._repository = repository

    async def list(self) -> list[ApiResourceData]:
        """Retourne la liste ordonnée des ApiResources enregistrées."""
        resources = await self._repository.find_all()
        return [_to_data(resource) for resource in resources]

    async def create(self, request: ApiResourceRequest) -> ApiResourceData | ApiResourceError:
        """Crée une nouvelle ApiResource (ou retourne une erreur)."""
        resource = _parse_request(request)
        if isinstance(resource, ApiResourceError):
            return resource
        if await self._repository.find_by_name(resource.name) is not None:
            return ApiResourceError(
                "invalid_api_resource", f"Une ApiResource nommée «{resource.name}» existe déjà", 409
            )
        await self._repository.save(resource)
        return _to_data(resource)

    async def read(self, name: str) -> ApiResourceData | ApiResourceError:
        """Lit la ApiResource identifiée par ``name``, ou une 404."""
        resource = await self._repository.find_by_name(name)
        if resource is None:
            return ApiResourceError("invalid_api_resource", f"ApiResource inconnue : {name}", 404)
        return _to_data(resource)

    async def update(
        self, name: str, request: ApiResourceRequest
    ) -> ApiResourceData | ApiResourceError:
        """Remplace une ApiResource existante (le nom reste stable)."""
        current = await self._repository.find_by_name(name)
        if current is None:
            return ApiResourceError("invalid_api_resource", f"ApiResource inconnue : {name}", 404)
        requested = _parse_request(request)
        if isinstance(requested, ApiResourceError):
            return requested
        updated = ApiResource(
            name=current.name,
            display_name=requested.display_name,
            scopes=requested.scopes,
            allowed_access_token_signing_algos=requested.allowed_access_token_signing_algos,
        )
        await self._repository.save(updated)
        return _to_data(updated)

    async def delete(self, name: str) -> ApiResourceError | None:
        """Supprime la ApiResource identifiée par ``name`` (404 si inconnue)."""
        resource = await self._repository.find_by_name(name)
        if resource is None:
            return ApiResourceError("invalid_api_resource", f"ApiResource inconnue : {name}", 404)
        await self._repository.delete(name)
        return None


def _parse_request(request: ApiResourceRequest) -> ApiResource | ApiResourceError:
    """Valide la demande et construit l'entité domaine."""
    name = request.name.strip()
    if not name:
        return ApiResourceError("invalid_api_resource", "Le nom d'une ApiResource est requis")
    if len(name) > _MAX_NAME_LENGTH:
        return ApiResourceError(
            "invalid_api_resource",
            f"Le nom d'une ApiResource est limité à {_MAX_NAME_LENGTH} caractères",
        )
    if _NAME_PATTERN.fullmatch(name) is None:
        return ApiResourceError(
            "invalid_api_resource",
            "Le nom d'une ApiResource ne peut contenir que des caractères "
            "alphanumériques, des points, tirets et undescores",
        )
    scopes = frozenset(scope.strip() for scope in request.scopes if scope.strip())
    invalid_scopes = [scope for scope in scopes if _NAME_PATTERN.fullmatch(scope) is None]
    if invalid_scopes:
        return ApiResourceError(
            "invalid_api_resource",
            f"Scope(s) d'API invalide(s) : {', '.join(sorted(invalid_scopes))}. "
            "Caractères alphanumériques, points, tirets et undescores uniquement",
            400,
        )
    algos = tuple(sorted(request.allowed_access_token_signing_algos))
    unknown = [
        name
        for name in algos
        if name not in JWTAlgorithm.__members__ and name not in JWTAlgorithm._value2member_map_
    ]
    if unknown:
        return ApiResourceError(
            "invalid_api_resource",
            f"Algorithme(s) de signature non supportés : {', '.join(unknown)}",
            400,
        )
    return ApiResource(
        name=name,
        display_name=request.display_name.strip(),
        scopes=scopes,
        allowed_access_token_signing_algos=algos,
    )


def _to_data(resource: ApiResource) -> ApiResourceData:
    """Normalise une entité domaine en réponse de gestion."""
    return ApiResourceData(
        name=resource.name,
        display_name=resource.display_name,
        scopes=sorted(resource.scopes),
        allowed_access_token_signing_algos=sorted(resource.allowed_access_token_signing_algos),
    )
