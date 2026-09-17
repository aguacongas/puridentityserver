"""Port de persistance des paires de clés de signature (RFC 7517)."""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.jwks import KeyPair


class KeyPairRepository(Protocol):
    """Contrat de stockage des paires de clés.

    Le port définit les opérations nécessaires au cycle de vie des clés
    (génération, rotation, exposition) ainsi que son cycle de vie propre
    (initialisation du schéma, libération des ressources). Les
    implémentations concrètes (mémoire, SQL, Redis, MongoDB…) sont
    fournies en infrastructure et choisies à la composition root selon
    la configuration du serveur.
    """

    async def save(self, key_pair: KeyPair) -> None:
        """Persiste la paire de clés (insertion ou mise à jour, idempotent)."""
        ...

    async def find_all(self) -> list[KeyPair]:
        """Retourne toutes les paires de clés persistées, sans condition."""
        ...

    async def update(self, key_pair: KeyPair) -> None:
        """Met à jour une paire de clés existante (par ``kid``)."""
        ...

    async def delete(self, kid: str) -> None:
        """Supprime définitivement la paire de clés identifiée par ``kid``."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (crée le schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du repository (connexions, moteur…)."""
        ...
