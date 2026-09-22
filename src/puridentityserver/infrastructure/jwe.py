"""Chiffrement JWE compact d'``id_token`` sur les primitives ``cryptography`` (RFC 7516).

Implémente le format compact (RFC 7516 §7.1) :

``<header>.<encrypted_key>.<iv>.<ciphertext>.<tag>``

- gestion de la clé (RFC 7518 §4) : ``RSA-OAEP`` / ``RSA-OAEP-256``
  (clé publique RSA enregistrée dans le ``jwks`` du client),
  ``A128KW`` / ``A256KW`` (RFC 3394, clé d'enveloppe dérivée par
  HKDF-SHA256 du secret partagé du client) et ``dir`` (la clé dérivée
  sert directement de clé de contenu) ;
- chiffrement du contenu (RFC 7518 §5) : ``A*CBC-HS*`` (AES-CBC +
  HMAC sur la moitié gauche/droite de la CEK, RFC 7518 §5.2) et
  ``A*GCM`` (AES-GCM, IV 96 bits, tag 128 bits).

Le wrapper (encodage base64url, AAD, AL, concaténation) suit le RFC ;
les opérations cryptographiques elles-mêmes passent exclusivement par
``cryptography``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
from hmac import compare_digest
from typing import cast

from cryptography.hazmat.primitives import hashes, hmac, keywrap
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    RSAPublicNumbers,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7

from puridentityserver.domain.authorization import Client
from puridentityserver.domain.jwe import (
    ASYMMETRIC_ENCRYPTION_ALGORITHMS,
    DEFAULT_ENCRYPTION_METHOD,
    GCM_ENCRYPTION_METHODS,
    JWEEncryptionMethod,
    JWEKeyManagementAlgorithm,
)
from puridentityserver.domain.key_validation import _MIN_RSA_MODULUS_BITS
from puridentityserver.interfaces.domain.tokens import JWEUnavailableError

# Vecteurs d'initialisation : 16 octets pour AES-CBC, 96 bits pour AES-GCM
# (RFC 7518 §5.2.2.1 et §5.3.1.1) ; tag GCM de 128 bits (RFC 7518 §5.3).
_CBC_IV_SIZE = 16
_GCM_IV_SIZE = 12
_GCM_TAG_SIZE = 16

# Tailles des clés d'enveloppe AES-KW (RFC 3394 §2.2.3) : 16 octets
# (A128KW) et 32 octets (A256KW).
_KW_KEK_SIZE = {
    JWEKeyManagementAlgorithm.A128KW: 16,
    JWEKeyManagementAlgorithm.A256KW: 32,
}

# Info HKDF de dérivation des clés d'enveloppe / de contenu depuis le
# secret partagé du client (déterministe : le client rejoue la dérivation).
_HKDF_INFO = b"puridentityserver:id-token-encryption"


def b64u(data: bytes) -> str:
    """Encode des octets en base64url sans padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    """Décode du base64url sans padding (padding rétabli pour l'API stdlib)."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def derive_content_key(shared_secret: str, size: int) -> bytes:
    """Dérive une clé de ``size`` octets depuis le secret partagé (HKDF-SHA256).

    Déterministe sur le ``client_secret`` : le destinataire (le client),
    qui connaît son propre secret, rejoue la dérivation pour déchiffrer —
    conformément aux familles symétriques de l'OIDC (id_token chiffré via
    clé préalablement partagée).
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=size,
        salt=None,
        info=_HKDF_INFO,
    ).derive(shared_secret.encode("utf-8"))


def rsa_public_key_from_jwks(keys: tuple[dict[str, object], ...]) -> RSAPublicKey:
    """Retourne la première clé publique RSA (``kty``/``n``/``e``) d'un JWKS.

    Résout ``n``/``e`` (base64url big-endian, RFC 7517 §4.3) vers la
    ``RSAPublicKey`` ``cryptography`` ; lève ``JWEUnavailableError`` si le
    client n'enregistre aucune clé RSA — matériel exigé par ``RSA-OAEP``.
    """
    for key in keys:
        if str(key.get("kty", "")).upper() != "RSA":
            continue
        modulus = key.get("n")
        exponent = key.get("e")
        if not isinstance(modulus, str) or not isinstance(exponent, str):
            continue
        try:
            n = int.from_bytes(b64u_decode(modulus), "big")
            e = int.from_bytes(b64u_decode(exponent), "big")
        except ValueError:
            continue
        if n <= 0 or e <= 0 or n.bit_length() < _MIN_RSA_MODULUS_BITS:
            continue
        return RSAPublicNumbers(e, n).public_key()
    raise JWEUnavailableError("aucune clé publique RSA dans le jwks du client")


def encrypt_compact(
    *,
    algorithm: JWEKeyManagementAlgorithm,
    method: JWEEncryptionMethod,
    plaintext: bytes,
    shared_kek: bytes = b"",
    rsa_public_key: RSAPublicKey | None = None,
) -> str:
    """Chiffre ``plaintext`` en JWE compact (RFC 7516 §7.1).

    ``shared_kek`` fournit la clé d'enveloppe (A*KW) ou la clé de contenu
    (``dir``) ; ``rsa_public_key`` la clé publique ``RSA-OAEP``. La CEK
    des familles asymétriques et AES-KW est aléatoire (``os.urandom``).
    """
    header = {
        "alg": algorithm.value,
        "enc": method.value,
    }
    aad = _protected_b64(header)

    cek, encrypted_key = _encrypt_key(
        algorithm, method, shared_kek=shared_kek, rsa_public_key=rsa_public_key
    )
    iv, ciphertext, tag = _encrypt_content(method, cek, aad.encode("ascii"), plaintext)

    return ".".join(
        (
            aad,
            b64u(encrypted_key),
            b64u(iv),
            b64u(ciphertext),
            b64u(tag),
        )
    )


def decrypt_compact(
    token: str,
    *,
    algorithm: JWEKeyManagementAlgorithm,
    method: JWEEncryptionMethod,
    shared_kek: bytes = b"",
    rsa_private_key: RSAPrivateKey | None = None,
) -> bytes:
    """Déchiffre un JWE compact (RFC 7516 §7.2) et vérifie son intégrité.

    ``shared_kek``/``rsa_private_key`` inversent la gestion de la clé de
    ``encrypt_compact`` ; la violation d'intégrité (tag CBC-HMAC ou GCM)
    lève ``ValueError``.
    """
    protected, encrypted_key, iv, ciphertext, tag = _split_compact(token)

    cek = _decrypt_key(
        algorithm,
        b64u_decode(encrypted_key),
        shared_kek=shared_kek,
        rsa_private_key=rsa_private_key,
    )
    return _decrypt_content(
        method,
        cek,
        protected.encode("ascii"),
        b64u_decode(iv),
        b64u_decode(ciphertext),
        b64u_decode(tag),
    )


class JWEIdTokenEncrypter:
    """Chiffre un ``id_token`` JWS en JWE compact pour un client destinataire.

    L'algorithme et la méthode viennent de la configuration du client
    (``id_token_encrypted_response_alg`` / ``_enc``, OIDC Core 1.0
    §3.1.3.6) ; la clé publique RSA des familles asymétriques est lue dans
    le ``jwks`` enregistré du client, les clés symétriques sont dérivées
    du ``shared_secret`` injecté par le cas d'utilisation.
    """

    async def encrypt_id_token(
        self,
        *,
        id_token: str,
        client: Client,
        shared_secret: str = "",
    ) -> str:
        """Chiffre l'``id_token`` en JWE compact ; ``cty: JWT`` (imbrication)."""
        algorithm = _algorithm(client.id_token_encrypted_response_alg)
        method = _method(
            client.id_token_encrypted_response_enc,
            default=DEFAULT_ENCRYPTION_METHOD,
        )
        # Chiffrement coûteux (OAEP/AES) : exécuté hors de l'event loop, comme
        # la résolution des clés d'assertion (client_assertions.py).
        return await asyncio.to_thread(
            _seal_id_token, id_token, client.jwks, algorithm, method, shared_secret
        )


def _seal_id_token(
    id_token: str,
    jwks: tuple[dict[str, object], ...],
    algorithm: JWEKeyManagementAlgorithm,
    method: JWEEncryptionMethod,
    shared_secret: str,
) -> str:
    """Construit puis scelle l'``id_token`` (familles asymétrique et symétrique)."""
    aad = _protected_b64({"alg": algorithm.value, "enc": method.value, "cty": "JWT"})

    if algorithm in ASYMMETRIC_ENCRYPTION_ALGORITHMS:
        cek = os.urandom(method.cek_size)
        encrypted_key = rsa_public_key_from_jwks(jwks).encrypt(cek, _oaep(algorithm))
    else:
        if not shared_secret:
            raise JWEUnavailableError(
                "un algorithme symétrique d'id_token exige le secret partagé du client"
            )
        shared_kek = derive_content_key(shared_secret, _kek_size(algorithm, method))
        if algorithm is JWEKeyManagementAlgorithm.DIRECT:
            cek = shared_kek
            encrypted_key = b""
        else:
            cek = os.urandom(method.cek_size)
            encrypted_key = keywrap.aes_key_wrap(shared_kek, cek)

    iv, ciphertext, tag = _encrypt_content(
        method, cek, aad.encode("ascii"), id_token.encode("utf-8")
    )
    return ".".join(
        (
            aad,
            b64u(encrypted_key),
            b64u(iv),
            b64u(ciphertext),
            b64u(tag),
        )
    )


def _protected_b64(header: dict[str, str]) -> str:
    """Encode l'en-tête protégé du JWE en base64url (RFC 7516 §4)."""
    return b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _algorithm(configured: str) -> JWEKeyManagementAlgorithm:
    """Résout l'algorithme de gestion de clé configuré du client."""
    if not configured:
        raise JWEUnavailableError("aucun algorithme de chiffrement d'id_token configuré")
    algorithm = cast(
        JWEKeyManagementAlgorithm | None,
        JWEKeyManagementAlgorithm._value2member_map_.get(configured),
    )
    if algorithm is None:
        raise JWEUnavailableError(
            f"algorithme de chiffrement d'id_token non supporté : {configured}"
        )
    return algorithm


def _method(configured: str, *, default: JWEEncryptionMethod) -> JWEEncryptionMethod:
    """Résout la méthode de chiffrement du contenu (``default`` si absente)."""
    if not configured:
        return default
    method = cast(
        JWEEncryptionMethod | None,
        JWEEncryptionMethod._value2member_map_.get(configured),
    )
    if method is None:
        raise JWEUnavailableError(f"méthode de chiffrement d'id_token non supportée : {configured}")
    return method


def _kek_size(algorithm: JWEKeyManagementAlgorithm, method: JWEEncryptionMethod) -> int:
    """Taille de la clé dérivée depuis le secret partagé (dépend du ``alg``)."""
    if algorithm is JWEKeyManagementAlgorithm.DIRECT:
        return method.cek_size
    return _KW_KEK_SIZE[algorithm]


def _encrypt_key(
    algorithm: JWEKeyManagementAlgorithm,
    method: JWEEncryptionMethod,
    *,
    shared_kek: bytes,
    rsa_public_key: RSAPublicKey | None,
) -> tuple[bytes, bytes]:
    """Génère la CEK et la chiffre selon la famille de gestion de clé."""
    if algorithm in ASYMMETRIC_ENCRYPTION_ALGORITHMS:
        if rsa_public_key is None:
            raise ValueError(f"{algorithm.value} exige une clé publique RSA")
        cek = os.urandom(method.cek_size)
        return cek, rsa_public_key.encrypt(cek, _oaep(algorithm))
    if algorithm is JWEKeyManagementAlgorithm.DIRECT:
        if len(shared_kek) != method.cek_size:
            raise ValueError(
                f"dir exige une clé de contenu de {method.cek_size} octets (reçu {len(shared_kek)})"
            )
        return shared_kek, b""
    if len(shared_kek) != _KW_KEK_SIZE[algorithm]:
        raise ValueError(
            f"{algorithm.value} exige une clé d'enveloppe de {_KW_KEK_SIZE[algorithm]} octets"
        )
    cek = os.urandom(method.cek_size)
    return cek, keywrap.aes_key_wrap(shared_kek, cek)


def _decrypt_key(
    algorithm: JWEKeyManagementAlgorithm,
    encrypted_key: bytes,
    *,
    shared_kek: bytes,
    rsa_private_key: RSAPrivateKey | None,
) -> bytes:
    """Récupère la CEK depuis la forme chiffrée (inverse de ``_encrypt_key``)."""
    if algorithm in ASYMMETRIC_ENCRYPTION_ALGORITHMS:
        if rsa_private_key is None:
            raise ValueError(f"{algorithm.value} exige une clé privée RSA")
        return rsa_private_key.decrypt(encrypted_key, _oaep(algorithm))
    if algorithm is JWEKeyManagementAlgorithm.DIRECT:
        if encrypted_key:
            raise ValueError("dir porte une encrypted_key non vide")
        return shared_kek
    if len(shared_kek) != _KW_KEK_SIZE[algorithm]:
        raise ValueError(
            f"{algorithm.value} exige une clé d'enveloppe de {_KW_KEK_SIZE[algorithm]} octets"
        )
    return keywrap.aes_key_unwrap(shared_kek, encrypted_key)


def _encrypt_content(
    method: JWEEncryptionMethod,
    cek: bytes,
    aad: bytes,
    plaintext: bytes,
) -> tuple[bytes, bytes, bytes]:
    """Chiffre le contenu et retourne ``(iv, ciphertext, tag)``."""
    if method in GCM_ENCRYPTION_METHODS:
        iv = os.urandom(_GCM_IV_SIZE)
        sealed = AESGCM(cek).encrypt(iv, plaintext, aad)
        return iv, sealed[:-_GCM_TAG_SIZE], sealed[-_GCM_TAG_SIZE:]
    mac_key, enc_key = cek[: method.cek_size // 2], cek[method.cek_size // 2 :]
    iv = os.urandom(_CBC_IV_SIZE)
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    tag = _cbc_hmac(mac_key, aad, iv, ciphertext, method)
    return iv, ciphertext, tag


def _cbc_hmac(
    mac_key: bytes,
    aad: bytes,
    iv: bytes,
    ciphertext: bytes,
    method: JWEEncryptionMethod,
) -> bytes:
    """Tag d'authentification CBC-HMAC : moitié gauche du HMAC (RFC 7518 §5.2.2.2)."""
    al = int.to_bytes(len(aad) * 8, 8, "big")
    signer = hmac.HMAC(mac_key, _hmac_hash(method))
    signer.update(aad + iv + ciphertext + al)
    digest = signer.finalize()
    return digest[: len(digest) // 2]


def _hmac_hash(method: JWEEncryptionMethod) -> hashes.HashAlgorithm:
    """Algorithme de hachage du HMAC lié à la méthode CBC-HMAC."""
    return {
        JWEEncryptionMethod.A128CBC_HS256: hashes.SHA256(),
        JWEEncryptionMethod.A192CBC_HS384: hashes.SHA384(),
        JWEEncryptionMethod.A256CBC_HS512: hashes.SHA512(),
    }[method]


def _oaep(algorithm: JWEKeyManagementAlgorithm) -> OAEP:
    """Schéma de remplissage OAEP de ``RSA-OAEP`` (SHA-1) ou ``RSA-OAEP-256``."""
    # RFC 7518 §4.3 : RSA-OAEP est défini avec SHA-1 (bandit S324)
    digest = (
        hashes.SHA1()  # ruff: ignore[suspicious-insecure-hash-usage]
        if algorithm is JWEKeyManagementAlgorithm.RSA_OAEP
        else hashes.SHA256()
    )
    return OAEP(mgf=padding.MGF1(algorithm=digest), algorithm=digest, label=None)


def _split_compact(token: str) -> tuple[str, str, str, str, str]:
    """Découpe un JWE compact en ses cinq segments (RFC 7516 §7.1)."""
    parts = token.split(".")
    if len(parts) != 5:
        raise ValueError("JWE compact invalide (5 segments attendus)")
    return cast(tuple[str, str, str, str, str], tuple(parts))


def _decrypt_content(
    method: JWEEncryptionMethod,
    cek: bytes,
    aad: bytes,
    iv: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    """Déchiffre le contenu et vérifie le tag (rejet d'intégrité → ``ValueError``)."""
    if method in GCM_ENCRYPTION_METHODS:
        return AESGCM(cek).decrypt(iv, ciphertext + tag, aad)
    mac_key, enc_key = cek[: method.cek_size // 2], cek[method.cek_size // 2 :]
    expected = _cbc_hmac(mac_key, aad, iv, ciphertext, method)
    if not compare_digest(tag, expected):
        raise ValueError("tag JWE invalide (authentification rejetée)")
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpadder.update(padded) + unpadder.finalize()
