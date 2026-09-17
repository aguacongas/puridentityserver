"""Authentification d'un client OAuth 2.0 (RFC 6749 §2.3).

Factorise la vérification du secret client (comparaison SHA-256 constante)
et l'authentification d'un client **confidentiel** au secret valide,
utilisée par les endpoints exigeant un appelant privilégié
(introspection RFC 7662, révocation RFC 7009).
"""

from __future__ import annotations

import hashlib
import hmac

from puridentityserver.domain.authorization import Client, ClientType
from puridentityserver.interfaces.repositories.client_repository import ClientRepository

CLIENT_UNKNOWN_ERROR = "Client inconnu ou désactivé"


def verify_client_secret(client: Client, secret: str) -> bool:
    """Vérifie l'empreinte SHA-256 du secret fourni (comparaison constante)."""
    computed = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return hmac.compare_digest(computed, client.client_secret_hash)


async def authenticate_confidential_client(
    client_repository: ClientRepository,
    client_id: str,
    client_secret: str,
) -> bool:
    """Authentifie ``client_id`` comme client confidentiel actif au secret valide."""
    client = await client_repository.find_by_id(client_id)
    if client is None or not client.is_active:
        return False
    if client.client_type is not ClientType.CONFIDENTIAL:
        return False
    return verify_client_secret(client, client_secret)
