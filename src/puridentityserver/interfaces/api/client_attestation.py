"""Lecture des en-têtes d'attestation client (§6.1).

Chaque requête authentifiée par ``attest_jwt_client_auth`` porte
exactement un ``OAuth-Client-Attestation`` et un
``OAuth-Client-Attestation-PoP`` (§9-1) ; plusieurs occurrences d'un
même en-tête invalident la requête (``invalid_request``, rendu par
l'appelant, au même titre que l'en-tête ``DPoP`` dupliqué RFC 9449 §7.1).
"""

from __future__ import annotations

from starlette.datastructures import Headers

#: Noms des en-têtes d'attestation (§6.1, insensibles à la casse côté HTTP).
ATTESTATION_HEADER = "oauth-client-attestation"
ATTESTATION_POP_HEADER = "oauth-client-attestation-pop"


def extract_client_attestation(headers: Headers) -> tuple[str, str, str | None]:
    """Retourne ``(attestation, pop, erreur)`` de la requête entrante.

    Aucune occurrence rend ``("", "", None)`` : la présence des deux
    en-têtes est exigée par le dispatch d'authentification lui-même
    (un client non ``attest_jwt_client_auth`` n'est pas concerné).
    """
    attestations = headers.getlist(ATTESTATION_HEADER)
    pops = headers.getlist(ATTESTATION_POP_HEADER)
    if len(attestations) > 1 or len(pops) > 1:
        return (
            "",
            "",
            "La requête ne doit contenir qu'un en-tête OAuth-Client-Attestation "
            "et qu'un en-tête OAuth-Client-Attestation-PoP "
            "(draft-ietf-oauth-attestation-based-client-auth §9-1)",
        )
    return (
        attestations[0].strip() if attestations else "",
        pops[0].strip() if pops else "",
        None,
    )
