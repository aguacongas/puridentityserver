"""Gestionnaire de clés de signature — implémentation concrète de ``KeyManager``."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Protocol, cast

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from puridentityserver.domain.jwks import (
    SYMMETRIC_ALGORITHMS,
    JWTAlgorithm,
    KeyPair,
    KeyUse,
)
from puridentityserver.interfaces.repositories.key_pair_repository import KeyPairRepository

_RSA_ALGORITHMS = (
    JWTAlgorithm.RS256,
    JWTAlgorithm.RS384,
    JWTAlgorithm.RS512,
    JWTAlgorithm.PS256,
    JWTAlgorithm.PS384,
    JWTAlgorithm.PS512,
)

_EC_CURVES: dict[JWTAlgorithm, ec.EllipticCurve] = {
    JWTAlgorithm.ES256: ec.SECP256R1(),
    JWTAlgorithm.ES384: ec.SECP384R1(),
    JWTAlgorithm.ES512: ec.SECP521R1(),
}


class _PEMPrivateKey(Protocol):
    """Interface de sérialisation minimale d'une clé privée (toutes familles)."""

    def private_bytes(
        self,
        encoding: Encoding,
        fmt: PrivateFormat,
        encryption_algorithm: NoEncryption,
    ) -> bytes: ...

    def public_key(self) -> _PEMPublicKey: ...


class _PEMPublicKey(Protocol):
    """Interface de sérialisation minimale d'une clé publique (toutes familles)."""

    def public_bytes(
        self,
        encoding: Encoding,
        fmt: PublicFormat,
    ) -> bytes: ...


class DefaultKeyManager:
    """Génère et stocke des paires de clés de signature via un repository.

    Supporte les familles RSA (RS*, PS*) et EC (ES*) : le type de clé
    générée dépend de l'algorithme demandé. Le repository injecté fournit
    la persistance (mémoire pour les tests, SQL/Redis/Mongo en production).
    Un gestionnaire est scopé sur un usage précis (``KeyUse.SIG`` pour les
    tokens OIDC, ``KeyUse.SESSION`` pour les cookies) et ne manipule que
    les clés de sa famille — les usages partagent le même repository mais
    restent isolés.
    """

    def __init__(self, repository: KeyPairRepository, use: KeyUse = KeyUse.SIG) -> None:
        """Injection du repository de persistance + usage des clés gérées."""
        self._repository = repository
        self._use = use

    async def _keys(self) -> list[KeyPair]:
        """Retourne les clés du repository appartenant à la famille gérée."""
        return [key for key in await self._repository.find_all() if key.use is self._use]

    async def generate_key_pair(self, key_size: int, algorithm: JWTAlgorithm) -> KeyPair:
        """Génère une paire de clés pour l'algorithme et la persiste."""
        generated = _generate_key_pair(key_size, algorithm)
        key_pair = KeyPair(
            algorithm=generated.algorithm,
            use=self._use,
            kid=generated.kid,
            private_key_pem=generated.private_key_pem,
            public_key_pem=generated.public_key_pem,
            created_at=generated.created_at,
            is_active=generated.is_active,
        )
        await self._repository.save(key_pair)
        return key_pair

    async def get_active_keys(self) -> list[KeyPair]:
        """Retourne les clés marquées actives, parmi la famille gérée."""
        return [k for k in await self._keys() if k.is_active]

    async def get_key_by_kid(self, kid: str) -> KeyPair | None:
        """Retourne la clé de la famille gérée identifiée par ``kid``."""
        for key in await self._keys():
            if key.kid == kid:
                return key
        return None

    async def mark_expired_keys(self, rotation_days: int, grace_period_days: int) -> int:
        """Marque les clés expirées, supprime celles dépassant la grace period.

        Retourne le nombre de clés supprimées.
        """
        now = datetime.now(timezone.utc)
        rotation_deadline = now - timedelta(days=rotation_days)
        grace_deadline = now - timedelta(days=rotation_days + grace_period_days)
        removed = 0
        for key in await self._keys():
            if key.created_at <= grace_deadline:
                await self._repository.delete(key.kid)
                removed += 1
            elif key.created_at <= rotation_deadline and key.is_active:
                await self._repository.update(replace(key, is_active=False))
        return removed

    async def ensure_active_key(self, key_size: int, algorithm: JWTAlgorithm) -> None:
        """Génère une clé de l'algorithme si aucune clé active n'est disponible."""
        active = [k for k in await self.get_active_keys() if k.algorithm is algorithm]
        if not active:
            await self.generate_key_pair(key_size, algorithm)


def _generate_key_pair(key_size: int, algorithm: JWTAlgorithm) -> KeyPair:
    """Génère une paire de clés PEM adaptée à l'algorithme demandé.

    Ne gère que les algorithmes **asymétriques** (RS*/PS*/ES*) : la
    famille symétrique HS* ne possède pas de paire de clés — elle signe
    l'``id_token`` avec le secret partagé du client, jamais avec une clé
    de serveur.
    """
    if algorithm in SYMMETRIC_ALGORITHMS:
        raise ValueError(
            f"{algorithm.value} est un algorithme symétrique (HMAC) : aucune clé à générer"
        )
    if algorithm in _RSA_ALGORITHMS:
        pk: _PEMPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    else:
        pk = cast(_PEMPrivateKey, ec.generate_private_key(_EC_CURVES[algorithm]))

    private_pem = pk.private_bytes(
        cast(Encoding, Encoding.PEM),
        cast(PrivateFormat, PrivateFormat.PKCS8),
        NoEncryption(),
    ).decode("ascii")
    public_pem = (
        pk.public_key()
        .public_bytes(
            cast(Encoding, Encoding.PEM),
            cast(PublicFormat, PublicFormat.SubjectPublicKeyInfo),
        )
        .decode("ascii")
    )

    return KeyPair(
        algorithm=algorithm,
        private_key_pem=private_pem,
        public_key_pem=public_pem,
    )
