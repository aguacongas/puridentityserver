"""Port de persistance des demandes d'authentification backchannel (CIBA).

L'``auth_req_id`` opque n'est jamais stocké en clair : seule son empreinte
SHA-256 (``auth_req_id_hash``) est persistée. Le hint est résolu à l'acceptation
de la demande (``subject``) ; la décision de l'utilisateur met à jour le statut,
puis le client consomme le résultat sur ``/token`` (grant CIBA) — le poll réussi
supprime la session (``delete``).
"""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.authorization import BackchannelAuthenticationRequest


class BackchannelAuthenticationRepository(Protocol):
    """Contrat de stockage des demandes CIBA.

    Les implémentations concrètes (mémoire, SQL…) sont choisies à la
    composition root selon la configuration.
    """

    async def save(self, request: BackchannelAuthenticationRequest) -> None:
        """Persiste la demande (insertion ou mise à jour)."""
        ...

    async def find_by_auth_req_id_hash(
        self, auth_req_id_hash: str
    ) -> BackchannelAuthenticationRequest | None:
        """Retourne la demande identifiée par l'empreinte de l'``auth_req_id``."""
        ...

    async def approve(self, auth_req_id_hash: str) -> None:
        """Marque la demande comme autorisée par l'utilisateur."""
        ...

    async def deny(self, auth_req_id_hash: str) -> None:
        """Marque la demande comme refusée par l'utilisateur."""
        ...

    async def delete(self, auth_req_id_hash: str) -> None:
        """Supprime la demande (consommée par le poll réussi ou expirée)."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (crée le schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du repository (connexions, moteur…)."""
        ...
