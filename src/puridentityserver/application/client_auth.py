"""Authentification d'un client OAuth 2.0 (RFC 6749 §2.3).

Factorise la vérification du secret client (comparaison SHA-256 constante)
et l'authentification complète d'un client selon sa
``token_endpoint_auth_method`` (secret, assertion RFC 7523, certificat
RFC 8705 ou ``none``), partagée par les endpoints exigeant un appelant
authentifié : token, backchannel authentication (OIDC CIBA 1.0 §7.2)…
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence

from puridentityserver.domain.authorization import (
    Client,
    ClientCertificate,
    ClientType,
    TokenEndpointAuthMethod,
    der_certificate_hash,
)
from puridentityserver.interfaces.domain.client_assertions import (
    CLIENT_ASSERTION_TYPE_URN,
    ClientAssertionVerifier,
)
from puridentityserver.interfaces.repositories.readers import ClientReader

CLIENT_UNKNOWN_ERROR = "Client inconnu ou désactivé"
ASSERTION_INVALID_ERROR = "Assertion client invalide ou expirée"


def verify_client_secret(client: Client, secret: str) -> bool:
    """Vérifie l'empreinte SHA-256 du secret fourni (comparaison constante)."""
    computed = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return hmac.compare_digest(computed, client.client_secret_hash)


async def authenticate_confidential_client(
    client_repository: ClientReader,
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


async def authenticate_client(
    client: Client,
    *,
    client_secret: str = "",
    assertions: ClientAssertionVerifier | None = None,
    assertion_type: str = "",
    assertion: str = "",
    assertion_audience: str | Sequence[str] = "",
    tls_certificate: ClientCertificate | None = None,
) -> str | None:
    """Authentifie le client selon sa ``token_endpoint_auth_method`` (RFC 6749 §2.3).

    Retourne ``None`` si l'authentification réussit, sinon le détail du
    refus (le code ``invalid_client`` est porté par l'appelant).

    ``assertion_audience`` porte la ou les valeurs d'``aud`` admises pour
    la ``client_assertion`` : le token endpoint seul, ou — au backchannel
    authentication endpoint (CIBA §7.1) — l'issuer, le token endpoint et
    l'endpoint CIBA.
    """
    method = client.effective_auth_method
    if method in (
        TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        TokenEndpointAuthMethod.CLIENT_SECRET_POST,
    ):
        if not verify_client_secret(client, client_secret):
            return "Secret client invalide"
        return None
    if method in (
        TokenEndpointAuthMethod.CLIENT_SECRET_JWT,
        TokenEndpointAuthMethod.PRIVATE_KEY_JWT,
    ):
        return await _authenticate_assertion(
            client,
            assertions=assertions,
            assertion_type=assertion_type,
            assertion=assertion,
            audience=assertion_audience,
        )
    if method in (
        TokenEndpointAuthMethod.TLS_CLIENT_AUTH,
        TokenEndpointAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
    ):
        if not verify_tls_client_certificate(client, tls_certificate):
            return "Certificat client invalide"
        return None
    if method is TokenEndpointAuthMethod.NONE:
        return None
    return "Méthode d'authentification client inconnue"


async def _authenticate_assertion(
    client: Client,
    *,
    assertions: ClientAssertionVerifier | None,
    assertion_type: str,
    assertion: str,
    audience: str | Sequence[str],
) -> str | None:
    """Vérifie une ``client_assertion`` (RFC 7523 §2.2) ; ``None`` si absente/invalide."""
    if assertions is None:
        return ASSERTION_INVALID_ERROR
    if assertion_type and assertion_type != CLIENT_ASSERTION_TYPE_URN:
        return ASSERTION_INVALID_ERROR
    if not assertion:
        return ASSERTION_INVALID_ERROR
    claims = await assertions.verify(
        token=assertion,
        client=client,
        audience=audience,
        require_iss_eq_sub=True,
    )
    if claims is None:
        return ASSERTION_INVALID_ERROR
    return None


def verify_tls_client_certificate(client: Client, presented: ClientCertificate | None) -> bool:
    """Vérifie le certificat présenté contre le lien enregistré (RFC 8705)."""
    if presented is None:
        return False
    if (
        client.effective_auth_method is TokenEndpointAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH
        and not presented.is_self_signed
    ):
        return False
    if client.tls_client_certificate_hash:
        return (
            presented.der is not None
            and der_certificate_hash(presented.der) == client.tls_client_certificate_hash
        )
    if client.tls_client_auth_subject_dn:
        return bool(presented.subject_dn) and (
            presented.subject_dn == client.tls_client_auth_subject_dn
        )
    return False
