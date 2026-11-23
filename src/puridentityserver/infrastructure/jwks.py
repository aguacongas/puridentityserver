"""Gestionnaire de clés de signature — implémentation concrète de ``KeyManager``."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Protocol, cast

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from puridentityserver.domain.jwks import (
    SYMMETRIC_ALGORITHMS,
    JWTAlgorithm,
    KeyPair,
    KeyUse,
)
from puridentityserver.interfaces.domain.jwks import KeyManager
from puridentityserver.interfaces.repositories.key_pair_repository import (
    KeyPairConflictError,
    KeyPairRepository,
)

_RSA_ALGORITHMS = (
    JWTAlgorithm.RS256,
    JWTAlgorithm.RS384,
    JWTAlgorithm.RS512,
    JWTAlgorithm.PS256,
    JWTAlgorithm.PS384,
    JWTAlgorithm.PS512,
)

#: Familles dotées d'un **slot de famille** : la paire portant ``(use, slot)``
#: est la clé *courante*, toutes les autres sont en drain. L'unicité de ce
#: couple dans le store (les ``NULL`` étant distincts) arbitre le
#: provisionnement concurrent de deux instances au premier démarrage :
#: l'instance perdante adopte la clé retenue au lieu d'en créer une seconde
#: (issue #310). Les familles ``SIG`` et ``SECRET`` en sont exclues : la
#: première génère avant de désactiver l'ancienne (OIDC Core 1.0 s10.1, une
#: clé active doit exister en permanence), la seconde doit garder ses
#: anciennes clés *actives* pour déchiffrer les secrets déjà scellés.
_FAMILY_SLOTS: dict[KeyUse, str] = {KeyUse.CREDENTIAL: "oid4vci"}

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

    async def generate_key_pair(
        self, key_size: int, algorithm: JWTAlgorithm, *, replace_kid: str | None = None
    ) -> KeyPair:
        """Génère une paire de clés pour l'algorithme et la persiste.

        Pour une famille à slot (``_FAMILY_SLOTS``), la nouvelle paire
        devient la clé courante : l'occupant ``replace_kid`` est libéré
        d'abord. Si une autre instance a pris ou remplacé le slot entre la
        lecture du caller et l'écriture, sa clé est **adoptée** et la paire
        générée est abandonnée — deux instances qui démarrent en même temps
        convergent vers une seule clé courante, sans écraser ni dupliquer
        (issue #310).

        Args:
            key_size: taille de la paire demandée (ignorée pour les courbes EC).
            algorithm: algorithme de la paire à générer.
            replace_kid: ``kid`` de la clé courante à remplacer, tel que lu
                par le caller ; ``None`` provisionne une famille vide.

        Returns:
            La paire persistée, ou la clé courante adoptée en cas de course.
        """
        slot = _FAMILY_SLOTS.get(self._use)
        keys = await self._keys() if slot is not None else []
        if slot is not None:
            holder = next((key for key in keys if key.slot == slot), None)
            if holder is not None and holder.kid != replace_kid:
                return holder  # la course est tranchée : la clé du store fait foi
            if holder is not None:
                await self._repository.update(replace(holder, slot=None))
        generated = _generate_key_pair(key_size, algorithm)
        candidate = KeyPair(
            algorithm=generated.algorithm,
            use=self._use,
            kid=generated.kid,
            private_key_pem=generated.private_key_pem,
            public_key_pem=generated.public_key_pem,
            created_at=generated.created_at,
            is_active=generated.is_active,
            slot=slot,
        )
        try:
            await self._repository.save(candidate)
        except KeyPairConflictError:
            if slot is None:
                raise
            winner = next((key for key in await self._keys() if key.slot == slot), None)
            if winner is None:
                raise
            return winner
        return candidate

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

    async def rotate_key(self, key_size: int, algorithm: JWTAlgorithm) -> KeyPair:
        """Remplace la clé active de l'algorithme par une nouvelle paire.

        La nouvelle paire est générée **avant** le retrait de l'ancienne :
        une clé active existe donc en permanence, et l'ancienne reste au
        magasin (inactive) pour la rétention publiée au JWKS.
        """
        current = [key for key in await self.get_active_keys() if key.algorithm is algorithm]
        generated = await self.generate_key_pair(key_size, algorithm)
        for key in current:
            await self._repository.update(replace(key, is_active=False))
        return generated

    async def get_retained_keys(self, limit: int) -> list[KeyPair]:
        """Clés retirées conservées, de la plus récente à la plus ancienne."""
        if limit <= 0:
            return []
        return (await self.get_retired_keys())[:limit]

    async def prune_inactive_keys(self, keep: int) -> int:
        """Supprime les clés retirées au-delà des ``keep`` plus récentes."""
        retired = await self.get_retired_keys()
        removed = 0
        for key in retired[max(keep, 0) :]:
            await self._repository.delete(key.kid)
            removed += 1
        return removed

    async def get_retired_keys(self) -> list[KeyPair]:
        """Toutes les clés retirées (inactives) de la famille, plus récentes d'abord.

        Exposé pour les callers qui doivent retenir une clé par algorithme
        (et non globalement) lors de la publication du JWKS (OIDC Core 1.0
        §10.1 — publication des clés récemment retirées pour la vérification
        des jetons émis avant la rotation).
        """
        return sorted(
            (key for key in await self._keys() if not key.is_active),
            key=lambda key: (key.created_at, key.kid),
            reverse=True,
        )

    async def ensure_active_key(self, key_size: int, algorithm: JWTAlgorithm) -> None:
        """Génère une clé de l'algorithme si aucune clé active n'est disponible."""
        active = [k for k in await self.get_active_keys() if k.algorithm is algorithm]
        if not active:
            await self.generate_key_pair(key_size, algorithm)


async def first_active_key(key_manager: KeyManager, algorithm: JWTAlgorithm) -> KeyPair:
    """Première clé active de l'algorithme, en génère une si aucune n'existe.

    Partagée par l'émission des jetons (``PyJWTTokenManager``) et celle de
    l'enveloppe JARM (``PyJarmEnvelopeSigner``) : même dérive de clé, même
    ``kid`` opposé au JWKS.
    """
    for key in await key_manager.get_active_keys():
        if key.algorithm is algorithm:
            return key
    await key_manager.ensure_active_key(4096, algorithm)
    for key in await key_manager.get_active_keys():
        if key.algorithm is algorithm:
            return key
    raise RuntimeError(f"Aucune clé active disponible pour l'algorithme {algorithm.value}")


async def rotate_if_stale(
    key_manager: KeyManager, key_size: int, algorithm: JWTAlgorithm, rotation_days: int
) -> bool:
    """Génère une clé si la famille est vide ou si la plus récente est périmée.

    Facteur commun de la rotation « à la première usage » du store
    ``key_pair`` : quand ``rotation_days`` jours se sont écoulés depuis
    ``created_at`` de la clé la plus récente de la famille gérée (ou quand
    la famille est vide), une nouvelle paire est générée. L'ancienne clé
    reste dans le store (drain), jamais supprimée automatiquement —
    conforme à ``AsymmetricSecretCipher.rotate_if_stale``, qui délègue à
    cette fonction. Le ``kid`` de la clé périmée est transmis au
    gestionnaire : pour une famille à slot, si une autre instance a déjà
    tourné entre la lecture et l'écriture, sa clé est adoptée (issue #310).

    Returns:
        ``True`` si la famille a reçu une clé courante — générée ici, ou
        adoptée après course.
    """
    keys = await key_manager.get_active_keys()
    if not keys:
        await key_manager.generate_key_pair(key_size, algorithm)
        return True
    newest = max(keys, key=lambda key: key.created_at)
    deadline = datetime.now(timezone.utc) - timedelta(days=rotation_days)
    if newest.created_at <= deadline:
        await key_manager.generate_key_pair(key_size, algorithm, replace_kid=newest.kid)
        return True
    return False


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
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption(),
    ).decode("ascii")
    public_pem = (
        pk.public_key()
        .public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )

    return KeyPair(
        algorithm=algorithm,
        private_key_pem=private_pem,
        public_key_pem=public_pem,
    )


def pem_key_kid(public_key_pem: str) -> str:
    """Identifiant stable et autodérivé d'une clé (SHA-256 de sa clé publique).

    Partagé par le seed de scellement (``KeyUse.SECRET``) et le seed de
    chiffrement OID4VCI (``KeyUse.CREDENTIAL``) : le ``kid`` dérive de la
    clé publique, il est donc identique d'un redémarrage à l'autre — le
    store retrouve la même ligne au lieu d'en créer une seconde.
    """
    digest = hashlib.sha256(public_key_pem.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest[:9]).rstrip(b"=").decode("ascii")


def load_credential_key_pair(private_key_pem: str) -> KeyPair:
    """Construit la ``KeyPair`` de chiffrement OID4VCI issue d'un PEM.

    Sert de **seed** (mondes déterministes / serveurs en mémoire, cf.
    ``client_secret_seal_key_pem``, issue #310) : la composition root
    l'enregistre dans le store ``key_pair`` si la famille
    ``KeyUse.CREDENTIAL`` est vide, avant la rotation au démarrage. Le
    ``kid`` dérive de la clé publique, la seed est donc stable d'un
    redémarrage à l'autre. ``ValueError`` si le PEM n'est pas une clé
    EC P-256 : la famille chiffre en ECDH-ES sur cette courbe seule.
    """
    private = load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(
        private.curve, ec.SECP256R1
    ):
        raise ValueError("seed de chiffrement OID4VCI : cle EC P-256 attendue")
    public_pem = (
        private.public_key()
        .public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return KeyPair(
        algorithm=JWTAlgorithm.ES256,
        use=KeyUse.CREDENTIAL,
        kid=pem_key_kid(public_pem),
        private_key_pem=private_key_pem,
        public_key_pem=public_pem,
    )
