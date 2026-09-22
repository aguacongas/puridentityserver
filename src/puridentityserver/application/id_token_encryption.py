"""Résolution du matériel de chiffrement d'``id_token`` par client (OIDC Core §3.1.3.6).

Partagé entre le token endpoint et l'endpoint d'autorisation (implicit/
hybrid) : un algorithme symétrique (``A128KW``/``A256KW``/``dir``) dérive
sa clé du secret partagé du client, conservé chiffré dans le registre —
les algorithmes ``RSA-OAEP``/``RSA-OAEP-256`` utilisent la clé publique
RSA du ``jwks`` enregistré par le client.
"""

from __future__ import annotations

from typing import cast

from puridentityserver.domain.authorization import Client
from puridentityserver.domain.jwe import (
    ASYMMETRIC_ENCRYPTION_ALGORITHMS,
    DEFAULT_ENCRYPTION_METHOD,
    JWEEncryptionMethod,
    JWEKeyManagementAlgorithm,
)
from puridentityserver.interfaces.domain.secrets import SecretCipher
from puridentityserver.interfaces.domain.tokens import IdTokenEncrypter, JWEUnavailableError


def should_encrypt_id_token(client: Client) -> bool:
    """Vrai si le client demande un ``id_token`` chiffré (``alg`` configuré)."""
    return bool(client.id_token_encrypted_response_alg)


async def resolve_id_token_encryption(
    client: Client,
    secret_cipher: SecretCipher | None,
) -> tuple[JWEKeyManagementAlgorithm, JWEEncryptionMethod, str] | None:
    """Retourne ``(algo, méthode, secret partagé)`` pour l'id_token du client.

    ``None`` signale un matériel manquant : un algorithme symétrique
    configuré sans secret récupérable (chiffreur indisponible ou chiffré
    absent) ou une méthode ``enc`` inconnue — l'émission échoue alors en
    ``invalid_client``. Une méthode ``enc`` absente retombe sur
    ``DEFAULT_ENCRYPTION_METHOD`` (OIDC Core 1.0 §3.1.3.6).
    """
    configured = client.id_token_encrypted_response_alg
    if not configured:
        return None
    algorithm = cast(
        JWEKeyManagementAlgorithm | None,
        JWEKeyManagementAlgorithm._value2member_map_.get(configured),
    )
    if algorithm is None:
        return None
    method = _resolve_method(client.id_token_encrypted_response_enc)
    if method is None:
        return None
    if algorithm in ASYMMETRIC_ENCRYPTION_ALGORITHMS:
        return algorithm, method, ""
    if secret_cipher is None or not client.client_secret_ciphertext:
        return None
    secret = await secret_cipher.decrypt(client.client_secret_ciphertext)
    return algorithm, method, secret


async def encrypt_id_token_for_client(
    *,
    id_token: str,
    client: Client,
    secret_cipher: SecretCipher | None,
    encrypter: IdTokenEncrypter | None,
) -> str:
    """Chiffre l'``id_token`` si le client le demande, sinon le retourne tel quel.

    Un client configuré mais sans matériel réalisable (chiffreur absent,
    secret non récupérable, clé RSA manquante) lève ``JWEUnavailableError`` :
    les cas d'utilisation la traduisent en erreur ``invalid_client``.
    """
    if not should_encrypt_id_token(client):
        return id_token
    if encrypter is None:
        raise JWEUnavailableError("aucun chiffreur d'id_token disponible")
    material = await resolve_id_token_encryption(client, secret_cipher)
    if material is None:
        raise JWEUnavailableError("matériel de chiffrement d'id_token indisponible")
    _algorithm, _method, shared_secret = material
    return await encrypter.encrypt_id_token(
        id_token=id_token,
        client=client,
        shared_secret=shared_secret,
    )


def _resolve_method(configured: str) -> JWEEncryptionMethod | None:
    """Résout la méthode ``enc`` (défaut si absente, ``None`` si inconnue)."""
    if not configured:
        return DEFAULT_ENCRYPTION_METHOD
    return cast(
        JWEEncryptionMethod | None,
        JWEEncryptionMethod._value2member_map_.get(configured),
    )
