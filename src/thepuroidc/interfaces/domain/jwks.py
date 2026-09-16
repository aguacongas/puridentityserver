"""Ports du périmètre JWKS (RFC 7517) — abstractions dont dépend la couche application."""

from __future__ import annotations

from typing import Protocol

from thepuroidc.domain.jwks import JWTAlgorithm, KeyPair


class KeyManager(Protocol):
    """Interface de gestion des paires de clés de signature.

    L'infrastructure fournit l'implémentation concrète (cryptography),
    par défaut ``DefaultKeyManager``.
    """

    async def generate_key_pair(self, key_size: int, algorithm: JWTAlgorithm) -> KeyPair:
        """Génère une nouvelle paire de clés et l'ajoute au magasin."""
        ...

    async def get_active_keys(self) -> list[KeyPair]:
        """Retourne les clés encore actives (non expirées)."""
        ...

    async def get_key_by_kid(self, kid: str) -> KeyPair | None:
        """Retourne la clé identifiée par ``kid`` (quel que soit son état).

        Nécessaire à la validation des tokens signés avec une clé inactive
        mais encore dans sa période de grâce (rotations successives).
        """
        ...

    async def mark_expired_keys(self, rotation_days: int, grace_period_days: int) -> int:
        """Passe les clés périmées en inactives, supprime celles hors grace period.

        Retourne le nombre de clés supprimées.
        """
        ...

    async def ensure_active_key(self, key_size: int, algorithm: JWTAlgorithm) -> None:
        """S'assure qu'au moins une clé active de l'algorithme existe."""
        ...
