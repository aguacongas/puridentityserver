"""Chiffrement au repos des secrets clients (RSA-OAEP, clé de scellement rotative).

``AsymmetricSecretCipher`` chiffre le secret client avec la clé publique
**la plus récente** de la famille ``KeyUse.SECRET`` et le déchiffre avec
n'importe quelle clé encore en vie : la rotation est **automatique**,
portée par le store ``key_pair`` existant et son ``DefaultKeyManager``
(mêmes mécanismes que les clés de signature/cookies) — aucune clé à
configurer à la main.

Chaque jeton chiffré porte le préfixe ``<kid>:`` (``kid`` dérivé de la
clé publique, stable et sans table de correspondance) : l'identification
de la clé source est immédiate, sans hypothèse sur l'ordre du store. Les
jetons *historiques* sans préfixe (ancien format Fernet migré à la
volée) restent déchiffrables par repli sur toutes les clés.

Contrairement aux clés de signature, les clés de scellement ne sont
**jamais purgées** par la rotation : un secret est chiffré à vie dans le
registre, il reste lisible tant que sa clé existe. La rotation génère une
nouvelle clé quand la plus récente dépasse ``jwks_rotation_days`` et
l'ancienne est retirée **manuellement** une fois le drain terminé
(chaque client ``client_secret_jwt`` ré-scellé au prochain ``PUT``).

Le chiffrement asymétrique (RSA-OAEP / SHA-256 via ``cryptography``)
garantit confidentialité et intégrité du matériau : seul le serveur, qui
détient les clés privées dans le store ``key_pair``, le déchiffre.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import cast

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from puridentityserver.domain.jwks import JWTAlgorithm, KeyPair, KeyUse
from puridentityserver.interfaces.domain.jwks import KeyManager

_SEAL_ALGORITHM = JWTAlgorithm.RS256
_SEAL_DEFAULT_KEY_SIZE = 2048

_PREFIX = ":"
_MISSING_KEY_ERROR = "aucune clé de scellement (KeyUse.SECRET) dans le store key_pair"
_OAEP = OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _key_kid(public_key_pem: str) -> str:
    """Identifiant stable et autodérivé d'une clé (SHA-256 de sa clé publique)."""
    digest = hashlib.sha256(public_key_pem.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest[:9]).rstrip(b"=").decode("ascii")


def _load_public(public_key_pem: str) -> RSAPublicKey:
    """Charge la clé publique RSA en mémoire depuis son PEM."""
    key = load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(key, RSAPublicKey):
        raise ValueError(f"clé de scellement non RSA : {type(key).__name__}")
    return key


def _load_private(private_key_pem: str) -> RSAPrivateKey:
    """Charge la clé privée RSA en mémoire depuis son PEM."""
    key = load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    if not isinstance(key, RSAPrivateKey):
        raise ValueError(f"clé de scellement non RSA : {type(key).__name__}")
    return key


def load_seal_key_pair(private_key_pem: str) -> KeyPair:
    """Construit la ``KeyPair`` de scellement associée à la clé privée ``pem``.

    Sert de **seed** (mondes déterministes / serveurs en mémoire) : la clé
    fournie est enregistrée dans le store ``key_pair`` au démarrage si
    aucune clé de scellement n'existe encore. Le ``kid`` dérive de la clé
    publique : le seed est stable d'un redémarrage à l'autre.
    """
    private = _load_private(private_key_pem)
    public_pem = (
        private.public_key()
        .public_bytes(
            cast(Encoding, Encoding.PEM),
            cast(PublicFormat, PublicFormat.SubjectPublicKeyInfo),
        )
        .decode("ascii")
    )
    return KeyPair(
        algorithm=_SEAL_ALGORITHM,
        use=KeyUse.SECRET,
        kid=_key_kid(public_pem),
        private_key_pem=private_key_pem,
        public_key_pem=public_pem,
    )


class AsymmetricSecretCipher:
    """Chiffre/déchiffre les secrets clients avec la clé de scellement du store.

    La famille est scopée sur ``KeyUse.SECRET`` par le ``KeyManager``
    injecté : ``encrypt`` utilise toujours la clé la plus récente,
    ``decrypt`` résout la clé du jeton par son ``kid`` puis replie sur
    toutes les clés encore présentes (y compris jetons sans préfixe).
    """

    def __init__(self, key_manager: KeyManager) -> None:
        """Injection du gestionnaire de clés de la famille de scellement."""
        self._key_manager = key_manager

    async def _seal_keys(self) -> list[KeyPair]:
        """Clés de scellement actives, de la plus ancienne à la plus récente."""
        keys = sorted(
            await self._key_manager.get_active_keys(), key=lambda key: (key.created_at, key.kid)
        )
        if not keys:
            raise ValueError(_MISSING_KEY_ERROR)
        return keys

    async def encrypt(self, value: str) -> str:
        """Chiffre ``value`` avec la clé la plus récente et préfixe son ``kid``."""
        keys = await self._seal_keys()
        newest = keys[-1]
        public = _load_public(newest.public_key_pem)
        ciphertext = public.encrypt(value.encode("utf-8"), _OAEP)
        encoded = base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode("ascii")
        return f"{newest.kid}{_PREFIX}{encoded}"

    async def decrypt(self, token: str) -> str:
        """Déchiffre ``token`` : clé résolue par ``kid``, sinon repli sur tout le trousseau."""
        keys = await self._seal_keys()
        kid, separator, body = token.partition(_PREFIX)
        if separator:
            key = next((candidate for candidate in reversed(keys) if candidate.kid == kid), None)
            if key is not None:
                plaintext = _try_decrypt(_load_private(key.private_key_pem), body)
                if plaintext is not None:
                    return plaintext
        candidates = (body,) if separator else (token,)
        for candidate in candidates:
            for key in reversed(keys):
                plaintext = _try_decrypt(_load_private(key.private_key_pem), candidate)
                if plaintext is not None:
                    return plaintext
        raise ValueError("secret client indéchiffrable (clé de scellement retirée du store ?)")

    async def is_current(self, token: str) -> bool:
        """Indique si ``token`` est chiffré avec la clé la plus récente."""
        kid, separator, _body = token.partition(_PREFIX)
        keys = await self._seal_keys()
        return bool(separator) and kid == keys[-1].kid

    async def reencrypt(self, token: str) -> str:
        """Rechiffre ``token`` sous la clé la plus récente (identité s'il y est déjà)."""
        if await self.is_current(token):
            return token
        return await self.encrypt(await self.decrypt(token))

    async def rotate_if_stale(
        self, key_size: int = _SEAL_DEFAULT_KEY_SIZE, rotation_days: int = 90
    ) -> bool:
        """Génère une clé de scellement si la plus récente dépasse ``rotation_days``.

        L'ancienne clé reste dans le store (drain) : jamais supprimée
        automatiquement, contrairement aux clés de signature. Retourne
        ``True`` si une nouvelle clé a été générée.
        """
        keys = await self._key_manager.get_active_keys()
        if not keys:
            await self._key_manager.generate_key_pair(key_size, _SEAL_ALGORITHM)
            return True
        newest = max(keys, key=lambda key: key.created_at)
        deadline = datetime.now(timezone.utc) - timedelta(days=rotation_days)
        if newest.created_at <= deadline:
            await self._key_manager.generate_key_pair(key_size, _SEAL_ALGORITHM)
            return True
        return False


def _try_decrypt(private: RSAPrivateKey, body: str) -> str | None:
    """Tente un déchiffrement OAEP : ``None`` si l'intégrité est rejetée."""
    try:
        decoded = base64.urlsafe_b64decode(body + "===")
    except (ValueError, TypeError):
        return None
    try:
        return private.decrypt(decoded, _OAEP).decode("utf-8")
    except (ValueError, TypeError):
        return None
