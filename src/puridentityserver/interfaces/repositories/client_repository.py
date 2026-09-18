"""Port de persistance des clients OAuth/OIDC (RFC 6749 §2)."""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.authorization import Client


class ClientRepository(Protocol):
    """Contrat de stockage des clients.

    Le port définit les opérations nécessaires au cycle de vie des
    clients (enregistrement, lecture pour authentification) ainsi que son
    cycle de vie propre (initialisation du schéma, libération des
    ressources). Les implémentations concrètes (mémoire, SQL, Redis,
    MongoDB…) sont fournies en infrastructure et choisies à la
    composition root selon la configuration du serveur.
    """

    async def save(self, client: Client) -> None:
        """Enregistre le client (insertion ou mise à jour par ``client_id``)."""
        ...

    async def find_by_id(self, client_id: str) -> Client | None:
        """Retourne le client identifié par ``client_id``, ou ``None``."""
        ...

    async def find_all(self) -> list[Client]:
        """Retourne tous les clients enregistrés."""
        ...

    async def delete(self, client_id: str) -> None:
        """Supprime le client identifié par ``client_id`` (idempotent)."""
        ...

    async def is_cors_origin_allowed(self, origin: str) -> bool:
        """Indique si l'``origin`` est autorisée en CORS par un client actif.

        Les origines autorisées sont déduites des ``redirect_uris`` des
        clients et complétées par leurs ``web_origins`` (OAuth 2.0 for
        Browser-Based Apps) : un client enregistré dynamiquement (RFC 7591)
        est donc couvert sans reconfiguration du serveur.
        """
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (crée le schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du repository (connexions, moteur…)."""
        ...
