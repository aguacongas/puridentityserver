"""Port de persistance des sessions du Device Authorization Grant (RFC 8628).

Le ``device_code`` opque n'est jamais stocké en clair : seule son empreinte
SHA-256 (``device_code_hash``) est persistée. Le ``user_code`` court est
recherché en clair par la page de vérification. Une fois l'utilisateur
connecté et l'appareil autorisé/refusé, la décision met à jour la session ;
le poll réussi sur ``/token`` la consomme (``delete``).
"""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.authorization import DeviceAuthorization


class DeviceAuthorizationRepository(Protocol):
    """Contrat de stockage des sessions de l'appareil.

    Les implémentations concrètes (mémoire, SQL…) sont choisies à la
    composition root selon la configuration.
    """

    async def save(self, session: DeviceAuthorization) -> None:
        """Persiste la session (insertion ou mise à jour)."""
        ...

    async def find_by_device_code_hash(self, device_code_hash: str) -> DeviceAuthorization | None:
        """Retourne la session identifiée par l'empreinte du ``device_code``."""
        ...

    async def find_by_user_code(self, user_code: str) -> DeviceAuthorization | None:
        """Retourne la session identifiée par le ``user_code`` saisi (normalisé)."""
        ...

    async def approve(self, device_code_hash: str, subject: str) -> None:
        """Marque la session comme autorisée et fixe le ``subject``."""
        ...

    async def deny(self, device_code_hash: str) -> None:
        """Marque la session comme refusée par l'utilisateur."""
        ...

    async def delete(self, device_code_hash: str) -> None:
        """Supprime la session (consommée par le poll réussi ou expirée)."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (crée le schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du repository (connexions, moteur…)."""
        ...
