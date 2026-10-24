"""Cas d'utilisation : gestion du JSON Web Key Set (JWKS)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from puridentityserver.domain.jwks import (
    ALL_SIGNING_ALGORITHMS,
    SYMMETRIC_ALGORITHMS,
    JWTAlgorithm,
    KeyPair,
)
from puridentityserver.interfaces.domain.jwks import KeyManager


def _managed_algorithms(algorithms: tuple[JWTAlgorithm, ...]) -> tuple[JWTAlgorithm, ...]:
    """Ne conserve que les algorithmes générant une paire de clés (asymétriques).

    La famille HS* signe l'``id_token`` avec le secret partagé du client :
    aucune clé de serveur à générer ni à publier au JWKS.
    """
    return tuple(algorithm for algorithm in algorithms if algorithm not in SYMMETRIC_ALGORITHMS)


def _age_seconds(created_at: datetime, now: datetime) -> float:
    """Âge d'une clé en secondes (les horodatages naïfs sont lus en UTC).

    Les magasins relationnels (SQLite) ne conservent pas le fuseau : la
    lecture peut renvoyer un horodatage naïf, que l'on interprets en UTC.
    """
    reference = (
        created_at if created_at.tzinfo is not None else created_at.replace(tzinfo=timezone.utc)
    )
    return (now - reference).total_seconds()


@dataclass(frozen=True, slots=True)
class JWKSetConfig:
    """Paramètres de gestion des clés JWKS.

    ``rotation_days`` / ``grace_period_days`` pilotent la rotation
    **journalière** (une clé plus vieille que ``rotation_days`` est retirée,
    puis supprimée au-delà de la période de grâce). ``rotation_seconds``
    ajoute une rotation **proactive** : au-delà de cet âge (en secondes), la
    clé de signature est remplacée à la prochaine publication du JWKS ; ``0``
    (défaut) la désactive. ``rotation_algorithms`` restreint la rotation
    proactive à certains algorithmes (vide = tous). ``retained_keys`` borne
    le nombre de clés retirées encore publiées au JWKS (OIDC Core 1.0 §10.1).
    """

    key_size: int = 4096
    algorithms: tuple[JWTAlgorithm, ...] = ALL_SIGNING_ALGORITHMS
    rotation_days: int = 90
    grace_period_days: int = 7
    rotation_seconds: float = 0.0
    rotation_algorithms: tuple[JWTAlgorithm, ...] = ()
    retained_keys: int = 1


class JWKSetUseCase:
    """Gère le cycle de vie des clés et l'exposition du JWKS.

    S'appuie sur un ``KeyManager`` injecté pour la génération et le
    stockage des clés (Clean Architecture — pas de dépendance directe
    vers ``cryptography``). Chaque algorithme configuré possède ses
    propres clés, publiées en parallèle dans le JWKS.
    """

    def __init__(
        self,
        config: JWKSetConfig,
        key_manager: KeyManager,
        *,
        encryption_key_manager: KeyManager | None = None,
    ) -> None:
        """Injection de la configuration et du gestionnaire de clés.

        ``encryption_key_manager`` gère la famille ``KeyUse.ENC`` — la clé
        RSA de déchiffrement des request objects (OIDC Core 1.0 §10.1,
        issue #204), publiée au JWKS aux côtés des clés de signature.
        Sans injection, le JWKS ne porte que les clés de signature.
        """
        self._config = config
        self._key_manager = key_manager
        self._encryption_keys = encryption_key_manager

    async def initialise(self) -> None:
        """Génère une clé initiale par algorithme si le magasin est vide.

        Les algorithmes symétriques (HS*) ne produisent aucune clé. La
        famille ``enc`` — une clé RSA de déchiffrement des request objects
        (OIDC Core 1.0 §10.1, issue #204) — reçoit sa clé initiale ici ;
        elle n'est ni pivotée ni purgée avec les clés de signature, aucun
        jeton longue durée n'en dépendant.
        """
        for algorithm in _managed_algorithms(self._config.algorithms):
            await self._key_manager.ensure_active_key(self._config.key_size, algorithm)
        if self._encryption_keys is not None:
            await self._encryption_keys.ensure_active_key(self._config.key_size, JWTAlgorithm.RS256)

    async def get_active_keys(self) -> list[KeyPair]:
        """Retourne les clés actives prêtes à être exposées dans le JWKS."""
        await self._mark_expired_keys()
        return await self._key_manager.get_active_keys()

    async def get_published_keys(self) -> list[KeyPair]:
        """Retourne les clés publiées au JWKS : actives et retirées retenues.

        OIDC Core 1.0 §10.1 : le JWK Set SHOULD conserver les clés de
        signature récemment retirées pour une transition en douceur — un
        jeton signé juste avant la rotation reste donc vérifiable.
        """
        await self._mark_expired_keys()
        await self._rotate_signing_keys()
        await self._key_manager.prune_inactive_keys(self._config.retained_keys)
        keys = await self._key_manager.get_active_keys()
        keys.extend(await self._key_manager.get_retained_keys(self._config.retained_keys))
        keys.extend(await self._encryption_keys_to_publish())
        return keys

    async def rotate_signing_keys(self) -> list[KeyPair]:
        """Fait pivoter à la demande les clés de signature gérées.

        Rotation **ponctuelle** (endpoint d'administration) : chaque
        algorithme géré reçoit une nouvelle paire, l'ancienne est retirée
        (inactive) mais reste publiée au JWKS pendant la rétention
        (OIDC Core 1.0 §10.1) et continue de valider les jetons qu'elle a
        signés. L'OP publie les nouvelles clés à la publication suivante
        du JWKS — le magasin de clés est partagé entre l'OP et le serveur
        d'administration.
        """
        return [
            await self._key_manager.rotate_key(self._config.key_size, algorithm)
            for algorithm in _managed_algorithms(self._config.algorithms)
        ]

    async def _encryption_keys_to_publish(self) -> list[KeyPair]:
        """Clés ``enc`` publiées aux côtés des clés de signature (issue #204).

        Leur cycle de vie est distinct de la rotation journalière : sans
        clé active, la publication régénère celle-ci comme pour les
        familles ``session``/``reset``/``verify`` au démarrage.
        """
        if self._encryption_keys is None:
            return []
        active = await self._encryption_keys.get_active_keys()
        if not active:
            await self._encryption_keys.ensure_active_key(self._config.key_size, JWTAlgorithm.RS256)
            active = await self._encryption_keys.get_active_keys()
        return active

    async def _mark_expired_keys(self) -> None:
        """Applique la politique de rotation journalière (retrait puis purge)."""
        removed = await self._key_manager.mark_expired_keys(
            self._config.rotation_days, self._config.grace_period_days
        )
        if removed > 0:
            for algorithm in _managed_algorithms(self._config.algorithms):
                active = [
                    key
                    for key in await self._key_manager.get_active_keys()
                    if key.algorithm is algorithm
                ]
                if not active:
                    await self._key_manager.ensure_active_key(self._config.key_size, algorithm)

    async def _rotate_signing_keys(self) -> None:
        """Fait pivoter les clés de signature trop anciennes.

        La rotation est **paresseuse** : elle est déclenchée par la
        publication du JWKS (et non par une tâche de fond), seule interaction
        possible avec l'OP entre deux relevés du module de certification
        ``oidcc-server-rotate-keys``. La clé retirée reste publiée pendant
        la rétention (OIDC Core 1.0 §10.1).
        """
        if self._config.rotation_seconds <= 0:
            return
        now = datetime.now(timezone.utc)
        for algorithm in self._rotation_algorithms():
            active = [
                key
                for key in await self._key_manager.get_active_keys()
                if key.algorithm is algorithm
            ]
            if not active:
                await self._key_manager.ensure_active_key(self._config.key_size, algorithm)
                continue
            current = max(active, key=lambda key: key.created_at)
            if _age_seconds(current.created_at, now) < self._config.rotation_seconds:
                continue
            await self._key_manager.rotate_key(self._config.key_size, algorithm)

    def _rotation_algorithms(self) -> tuple[JWTAlgorithm, ...]:
        """Algorithmes concernés par la rotation proactive (vide = tous)."""
        if self._config.rotation_algorithms:
            return self._config.rotation_algorithms
        return _managed_algorithms(self._config.algorithms)
