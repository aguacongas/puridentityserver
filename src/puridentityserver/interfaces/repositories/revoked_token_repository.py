"""Port de persistance du denylist de jetons révoqués (RFC 7009)."""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.revocation import RevokedToken


class RevokedTokenRepository(Protocol):
    """Contrat de stockage des jetons révoqués.

    Ne manipule que l'empreinte SHA-256 d'un jeton (jamais le jeton en
    clair). Les entrées expirées doivent être purgées régulièrement
    (``purge_expired``) pour borner la taille du denylist.
    """

    async def save(self, revoked: RevokedToken) -> None:
        """Enregistre une révocation (insertion ou mise à jour par ``token_hash``)."""
        ...

    async def is_revoked(self, token_hash: str) -> bool:
        """Indique si l'empreinte ``token_hash`` figure au denylist."""
        ...

    async def purge_expired(self) -> int:
        """Supprime les entrées dont l'expiration est dépassée ; retourne le compte."""
        ...

    async def initialise(self) -> None:
        """Prépare le stockage (crée le schéma si nécessaire)."""
        ...

    async def close(self) -> None:
        """Libère les ressources du repository (connexions, moteur…)."""
        ...
