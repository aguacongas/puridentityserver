"""Adapters de lecture seule sur les repositories de persistance.

Le serveur protocole accède aux resources administrées (clients,
utilisateurs, IdentityResources, ApiResources) via les ports de lecture
seule de ``interfaces.repositories.readers``. Ces adapters enveloppent
l'implémentation concrète du stockage (mémoire ou SQL) et ne délèguent
que des opérations de lecture : aucune méthode d'écriture n'est exposée.

``Readers`` regroupe les quatre lecteurs construits depuis un ``Stores``
partagé : le serveur ``full`` injecte les mêmes instances de stockage à
l'administration et au protocole, les lectures sont donc cohérentes.
"""

from __future__ import annotations

from dataclasses import dataclass

from puridentityserver.domain.api_resource import ApiResource
from puridentityserver.domain.authorization import Client
from puridentityserver.domain.identity_resource import IdentityResource
from puridentityserver.domain.userinfo import UserClaims
from puridentityserver.interfaces.repositories.api_resource_repository import (
    ApiResourceRepository,
)
from puridentityserver.interfaces.repositories.client_repository import ClientRepository
from puridentityserver.interfaces.repositories.identity_resource_repository import (
    IdentityResourceRepository,
)
from puridentityserver.interfaces.repositories.readers import (
    ApiResourceReader,
    ClientReader,
    IdentityResourceReader,
    UserReader,
)
from puridentityserver.interfaces.repositories.user_repository import UserRepository


class ClientReaderAdapter:
    """Lecteur des clients du registre — délègue au repository parent."""

    def __init__(self, repository: ClientRepository) -> None:
        """Enveloppe le repository read-write (atomique avec l'administration)."""
        self._repository = repository

    async def find_by_id(self, client_id: str) -> Client | None:
        """Retourne le client identifié par ``client_id``, ou ``None``."""
        return await self._repository.find_by_id(client_id)

    async def find_all(self) -> list[Client]:
        """Retourne tous les clients enregistrés."""
        return await self._repository.find_all()

    async def is_cors_origin_allowed(self, origin: str) -> bool:
        """Indique si l'``origin`` est autorisée en CORS par un client actif."""
        return await self._repository.is_cors_origin_allowed(origin)


class UserReaderAdapter:
    """Lecteur des profils utilisateurs — délègue au repository parent."""

    def __init__(self, repository: UserRepository) -> None:
        """Enveloppe le repository read-write du user store."""
        self._repository = repository

    async def find_by_subject(self, subject: str) -> UserClaims | None:
        """Retourne le profil identifié par ``subject``, ou ``None``."""
        return await self._repository.find_by_subject(subject)

    async def find_all(self) -> list[UserClaims]:
        """Retourne tous les profils enregistrés."""
        return await self._repository.find_all()


class IdentityResourceReaderAdapter:
    """Lecteur des IdentityResources — délègue au repository parent."""

    def __init__(self, repository: IdentityResourceRepository) -> None:
        """Enveloppe le repository read-write des resources identité."""
        self._repository = repository

    async def find_by_name(self, name: str) -> IdentityResource | None:
        """Retourne la resource identifiée par ``name``, ou ``None``."""
        return await self._repository.find_by_name(name)

    async def find_all(self) -> list[IdentityResource]:
        """Retourne toutes les resources enregistrées."""
        return await self._repository.find_all()


class ApiResourceReaderAdapter:
    """Lecteur des ApiResources — délègue au repository parent."""

    def __init__(self, repository: ApiResourceRepository) -> None:
        """Enveloppe le repository read-write des resources d'API."""
        self._repository = repository

    async def find_by_name(self, name: str) -> ApiResource | None:
        """Retourne la resource identifiée par ``name``, ou ``None``."""
        return await self._repository.find_by_name(name)

    async def find_all(self) -> list[ApiResource]:
        """Retourne toutes les resources enregistrées."""
        return await self._repository.find_all()


@dataclass(frozen=True, slots=True)
class Readers:
    """Regroupe les quatre lecteurs du protocole pour un ``Stores`` partagé."""

    client: ClientReader
    user: UserReader
    identity_resource: IdentityResourceReader
    api_resource: ApiResourceReader


def build_readers_from_stores(
    *,
    client: ClientRepository,
    user: UserRepository,
    identity_resource: IdentityResourceRepository,
    api_resource: ApiResourceRepository,
) -> Readers:
    """Construit les lecteurs protocole sur des instances de stockage partagées."""
    return Readers(
        client=ClientReaderAdapter(client),
        user=UserReaderAdapter(user),
        identity_resource=IdentityResourceReaderAdapter(identity_resource),
        api_resource=ApiResourceReaderAdapter(api_resource),
    )
