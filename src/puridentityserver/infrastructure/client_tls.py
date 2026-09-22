"""Extraction du certificat client présenté en mTLS (RFC 8705).

Le certificat est lu depuis deux sources complémentaires :

- le contexte TLS de l'appareil (``request.scope["ssl_object"]``, un
  ``ssl.SSLSocket``) quand uvicorn termine la TLS — typiquement un
  déploiement ``https`` direct ;
- les en-têtes posés par un proxy de terminaison TLS (nginx ``$ssl_client_cert``
  sous ``X-SSL-Client-Cert``, Envoy ``X-Forwarded-Client-Cert``) et le sujet
  ``$ssl_client_s_dn`` sous ``X-SSL-Client-S-DN`` — le déploiement web usuel.

Le résultat normalisé (``ClientCertificate``, domaine) permet ensuite au
token endpoint de comparer le certificat au lien enregistré pour le client.
"""

from __future__ import annotations

from ssl import SSLSocket
from typing import cast
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi import Request

from puridentityserver.domain.authorization import ClientCertificate


def extract_client_certificate(request: Request) -> ClientCertificate:
    """Extrait le certificat client de la requête (contexte TLS puis en-têtes)."""
    ssl_object = getattr(request, "scope", {}).get("ssl_object")
    if isinstance(ssl_object, SSLSocket):
        der = ssl_object.getpeercert(binary_form=True)
        if der:
            return _from_der(der)

    der = _der_from_headers(request)
    if der is not None:
        return _from_der(der)

    subject_dn = request.headers.get("X-SSL-Client-S-DN", "")
    if not subject_dn:
        subject_dn = request.headers.get("X-SSL-Client-SN", "")
    if subject_dn:
        return ClientCertificate(der=None, subject_dn=subject_dn)
    return ClientCertificate()


def _der_from_headers(request: Request) -> bytes | None:
    """Retourne la forme DER d'un certificat PEM reçu par en-tête de proxy."""
    pem = request.headers.get("X-SSL-Client-Cert", "")
    if not pem:
        xfcc = request.headers.get("X-Forwarded-Client-Cert", "")
        if xfcc:
            pem = unquote(xfcc)
    pem_user = _clean_pem(pem)
    if not pem_user:
        return None
    try:
        return x509.load_pem_x509_certificate(pem_user.encode("ascii")).public_bytes(
            cast(Encoding, Encoding.DER)
        )
    except ValueError:
        return None


def _clean_pem(pem: str) -> str:
    r"""Normalise un PEM reçu par en-tête (sauts de ligne échappés en ``\\n``)."""
    cleaned = pem.replace("\\n", "\n").replace("\\r", "\r")
    return cleaned.strip()


def _from_der(der: bytes) -> ClientCertificate:
    """Normalise un certificat DER : sujet one-line RFC 4514 et signature auto-référée."""
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return ClientCertificate(der=der)
    return ClientCertificate(
        der=der,
        subject_dn=cert.subject.rfc4514_string(),
        is_self_signed=cert.issuer == cert.subject,
    )
