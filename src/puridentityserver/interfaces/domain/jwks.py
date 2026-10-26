"""Ports du périmètre JWKS (RFC 7517) — abstractions dont dépend la couche application."""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.jwks import JWTAlgorithm, KeyPair


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

    async def rotate_key(self, key_size: int, algorithm: JWTAlgorithm) -> KeyPair:
        """Remplace la clé active de l'algorithme par une nouvelle paire.

        L'ancienne clé est *retirée* (inactive) mais conservée au magasin :
        elle reste publiée au JWKS pendant la période de rétention et
        continue de valider les jetons qu'elle a signés (OIDC Core 1.0 §10.1).
        La nouvelle paire est générée **avant** le retrait pour qu'une clé
        active existe en permanence.
        """
        ...

    async def get_retained_keys(self, limit: int) -> list[KeyPair]:
        """Clés retirées encore conservées, de la plus récente à la plus ancienne.

        ``limit`` borne le nombre de clés renvoyées (0 = aucune).
        """
        ...

    async def get_retired_keys(self) -> list[KeyPair]:
        """Toutes les clés retirées (inactives) de la famille, plus récentes d'abord.

        Permet aux callers de retenir au moins une clé par algorithme, plutôt
        qu'``N`` globalement (OIDC Core 1.0 §10.1).
        """
        ...

    async def prune_inactive_keys(self, keep: int) -> int:
        """Supprime les clés retirées au-delà des ``keep`` plus récentes.

        Retourne le nombre de clés supprimées : la rotation ne doit pas
        faire croître indéfiniment le magasin de clés.
        """
        ...

    async def ensure_active_key(self, key_size: int, algorithm: JWTAlgorithm) -> None:
        """S'assure qu'au moins une clé active de l'algorithme existe."""
        ...
