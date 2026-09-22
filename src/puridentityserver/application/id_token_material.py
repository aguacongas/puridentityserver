"""Résolution du matériel de signature d'``id_token`` par client (OIDC Core §3.1.3.7).

Partagé entre le token endpoint et l'endpoint d'autorisation (implicit/
hybrid) : un algorithme syymétrique HS* signe l'``id_token`` avec le
secret partagé du client, conservé chiffré dans le registre ; les autres
algorithmes utilisent la clé de serveur correspondante (JWKS).
"""

from __future__ import annotations

from typing import cast

from puridentityserver.domain.authorization import Client
from puridentityserver.domain.jwks import SYMMETRIC_ALGORITHMS, JWTAlgorithm
from puridentityserver.interfaces.domain.secrets import SecretCipher


async def resolve_id_token_material(
    client: Client,
    default_algorithm: JWTAlgorithm,
    secret_cipher: SecretCipher | None,
) -> tuple[JWTAlgorithm, str] | None:
    """Retourne ``(algorithme, secret partagé)`` pour l'id_token du client.

    ``None`` signale un matériel manquant : un algorithme HS* configuré
    sans secret récupérable (chiffreur indisponible ou chiffré absent).
    """
    configured = client.id_token_signed_response_alg
    if not configured:
        return default_algorithm, ""
    algorithm = cast(JWTAlgorithm | None, JWTAlgorithm._value2member_map_.get(configured))
    if algorithm is None:
        return default_algorithm, ""
    if algorithm not in SYMMETRIC_ALGORITHMS:
        return algorithm, ""
    if secret_cipher is None or not client.client_secret_ciphertext:
        return None
    secret = await secret_cipher.decrypt(client.client_secret_ciphertext)
    return algorithm, secret
