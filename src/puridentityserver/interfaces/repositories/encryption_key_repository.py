"""Port de persistance de la clé de chiffrement de l'émetteur OID4VCI."""

from __future__ import annotations

from typing import Protocol


class EncryptionKeyRepository(Protocol):
    """Contrat de stockage de la clé privée de chiffrement de l'émetteur.

    La clé EC P-256 sert au chiffrement des credential requests et des
    credential responses OID4VCI (ECDH-ES, issue #304). Elle doit être
    unique et partagée entre les instances du serveur (load balancing) :
    une rotation en cours de run casserait le déchiffrement des requêtes
    déjà engagées. Le provisionnement est « à la première usage » :
    ``save_if_absent`` n'insère que si aucune clé n'existe, la contrainte
    d'unicité du stockage tranchant les courses entre instances.
    """

    async def load(self) -> str | None:
        """Retourne le PEM PKCS#8 de la clé privée persistée, ou ``None``."""
        ...

    async def save_if_absent(self, private_key_pem: str) -> None:
        """Persiste le PEM seulement si aucune clé n'est déjà stockée."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (création de la table ou du magasin)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du stockage."""
        ...
