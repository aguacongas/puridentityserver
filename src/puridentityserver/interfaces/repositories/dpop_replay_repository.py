"""Port de persistance des preuves DPoP déjà présentées (RFC 9449 §11).

Le store anti-replay mémorise l'empreinte SHA-256 de chaque ``jti``
accepté pour refuser tout rejeu de preuve dans la fenêtre encore
validante de l'``iat``.
"""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.dpop import DPoPReplay


class DpopReplayRepository(Protocol):
    """Contrat de stockage des ``jti`` de preuves DPoP.

    Ne manipule que l'empreinte SHA-256 d'un ``jti`` (jamais le ``jti``
    en clair). Les entrées expirées doivent être purgées régulièrement
    (``purge_expired``) pour borner la taille du store.
    """

    async def save(self, replay: DPoPReplay) -> None:
        """Enregistre un ``jti`` présenté (insertion par ``jti_hash``)."""
        ...

    async def is_used(self, jti_hash: str) -> bool:
        """Indique si l'empreinte ``jti_hash`` a déjà été présentée."""
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
