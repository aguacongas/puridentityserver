"""Contrôle de la liaison access token / certificat client mTLS (RFC 8705 §3.3).

Un access token émis avec ``cnf.x5t#S256`` (voir ``application/token.py``)
n'est accepté par un resource server de ce serveur que présenté avec le
certificat client dont l'empreinte base64url(SHA-256(DER)) correspond.
Le module est partagé par ``/userinfo`` et la ressource protégée.
"""

from __future__ import annotations

from puridentityserver.domain.authorization import ClientCertificate, der_certificate_hash


def certificate_binding_error(
    claims: dict[str, object], certificate: ClientCertificate | None
) -> str:
    """Retourne le message d'erreur de la liaison certificat, ou ``""``.

    ``""`` signifie que le jeton n'est pas lié à un certificat (claim
    ``cnf.x5t#S256`` absent) ou que le certificat présenté correspond au
    lien : la requête peut continuer. Un jeton lié présenté sans
    certificat — ou avec un certificat différent — est refusé.
    """
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict):
        return ""
    expected = cnf.get("x5t#S256")
    if not isinstance(expected, str) or not expected:
        return ""
    if certificate is None or certificate.der is None:
        return (
            "Access token lié au certificat client mTLS (RFC 8705 §3.3) : certificat non présenté"
        )
    if der_certificate_hash(certificate.der) != expected:
        return "Certificat client différent de celui liant l'access token (RFC 8705 §3.3)"
    return ""
