"""Lecteur de clients avec repli sur la résolution fédérée (OpenID Federation 1.1).

Le registre des clients reste la source de vérité ; lorsqu'un ``client_id``
inconnu correspond à une **Entity Identifier**, l'OP tente de résoudre le RP
dans une fédération (spec §12.1) et déduit son client de l'entity statement.
"""

from __future__ import annotations

from puridentityserver.domain.authorization import Client
from puridentityserver.interfaces.domain.federation import FederatedClientResolver
from puridentityserver.interfaces.repositories.readers import ClientReader


class FederatedClientReader:
    """Lecteur de clients : registre d'abord, résolution fédérée ensuite.

    Sans résolveur (Fédération désactivée), le comportement est celui d'un
    lecteur simple sur le registre.
    """

    def __init__(
        self, clients: ClientReader, resolver: FederatedClientResolver | None = None
    ) -> None:
        """Injection du registre des clients et du résolveur fédéré."""
        self._clients = clients
        self._resolver = resolver

    async def find_by_id(self, client_id: str) -> Client | None:
        """Retourne le client enregistré, ou le client fédéré dérivé."""
        client = await self._clients.find_by_id(client_id)
        if client is not None:
            return client
        if self._resolver is None:
            return None
        return await self._resolver.resolve(client_id)

    async def find_all(self) -> list[Client]:
        """Retourne tous les clients enregistrés.

        Les clients fédérés éphémères ne sont pas persistés : ils sont
        résolus à la demande.
        """
        return await self._clients.find_all()

    async def is_cors_origin_allowed(self, origin: str) -> bool:
        """Indique si l'origine est autorisée en CORS par un client actif."""
        return await self._clients.is_cors_origin_allowed(origin)
