"""Extraction du certificat client présenté en mTLS (RFC 8705).

Le certificat est lu depuis deux sources complémentaires :

- le contexte TLS de l'appareil (``request.scope["ssl_object"]``, un
  ``ssl.SSLSocket``) quand uvicorn termine la TLS — typiquement un
  déploiement ``https`` direct ;
- les en-têtes posés par un proxy de terminaison TLS (Cloudflare
  Transform Rules RFC 9440 ``cf.tls_client_auth.*``, nginx
  ``$ssl_client_cert``/``$ssl_client_s_dn``, Envoy, HAProxy…) — le
  déploiement web usuel.

Les noms de ces en-têtes sont **configurables** (``ClientCertificateHeaderNames``,
renseignés par ``Settings.client_certificate_header`` /
``client_certificate_dn_header``) pour s'adapter à n'importe quelle
plateforme de terminaison. Valeur du port PEM : elle est dé-URL encodée
si besoin (les proxies peuvent encoder les sauts de ligne en ``%0A``).

Le résultat normalisé (``ClientCertificate``, domaine) permet ensuite au
token endpoint de comparer le certificat au lien enregistré pour le client.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ssl import SSLSocket
from typing import cast
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi import Request

from puridentityserver.domain.authorization import ClientCertificate


@dataclass(frozen=True, slots=True)
class ClientCertificateHeaderNames:
    """Noms d'en-têtes HTTP portant le certificat client mTLS (proxy).

    ``certificate`` reçoit le PEM du certificat client (éventuellement
    URL-encodé) ; ``subject_dn`` reçoit le sujet RFC 4514 (repli quand le
    PEM n'est pas transmis, ex. ``tls_client_auth`` par sujet).
    """

    certificate: str = "X-SSL-Client-Cert"
    subject_dn: str = "X-SSL-Client-S-DN"


#: Noms d'en-têtes par défaut (nginx / déploiements existants).
DEFAULT_CLIENT_CERTIFICATE_HEADERS = ClientCertificateHeaderNames()


def extract_client_certificate(
    request: Request,
    header_names: ClientCertificateHeaderNames = DEFAULT_CLIENT_CERTIFICATE_HEADERS,
) -> ClientCertificate:
    """Extrait le certificat client de la requête (contexte TLS puis en-têtes)."""
    ssl_object = getattr(request, "scope", {}).get("ssl_object")
    if isinstance(ssl_object, SSLSocket):
        der = ssl_object.getpeercert(binary_form=True)
        if der:
            return _from_der(der)

    der = _der_from_headers(request, header_names)
    if der is not None:
        return _from_der(der)

    subject_dn = request.headers.get(header_names.subject_dn, "")
    if subject_dn:
        return ClientCertificate(der=None, subject_dn=_normalize_header_value(subject_dn))
    return ClientCertificate()


def _normalize_header_value(value: str) -> str:
    r"""Dé-URL-encode puis rétablit les séquences d'échappement d'un PEM.

    Les proxies de terminaison TLS encodent les caractères de contrôle du
    PEM différemment selon l'implémentation :

    - URL encoding (``%0A``) ;
    - séquences ``\n``/``\r``/``\t`` deux-caractères ;
    - escapes hex nginx ``\x0a``/``\x0d``/``\x09`` — le format de
      ``proxy_set_header`` quand la valeur provient d'une variable
      multi-lignes comme ``$ssl_client_cert`` (issue #209 : sans ce
      décodage, le PEM n'est jamais parsé, ``der`` reste ``None`` et le
      token endpoint rejette ``invalid_client`` « Certificat client mTLS
      requis » alors que le certificat est bien arrivé) ;
    - une barre inverse résiduelle devant un saut de ligne réel (pliage
      de ligne ``obs-fold`` RFC 9110 §5.2 reconstitué par le client).

    Les séquences hex à deux chiffres propres au sujet DN RFC 4514
    (``\2C``, ``\3D``…) ne sont pas touchées : seules les formes
    ``\x0a``/``\x0d``/``\x09`` (trois caractères après la barre inverse)
    sont reconnues.
    """
    decoded = unquote(value)
    for sequence, replacement in (
        ("\\x0a", "\n"),
        ("\\x0d", "\r"),
        ("\\x09", "\t"),
        ("\\n", "\n"),
        ("\\r", "\r"),
        ("\\t", "\t"),
    ):
        decoded = decoded.replace(sequence, replacement)
    # Barre inverse seule devant un saut de ligne/tabulation réels
    # (« \ » + newline) : rejetée, le PEM ne contient aucun antislash.
    return re.sub(r"\\[\r\n\t]", lambda m: m.group(0)[1:], decoded).strip()


def _der_from_headers(request: Request, header_names: ClientCertificateHeaderNames) -> bytes | None:
    """Retourne la forme DER d'un certificat PEM reçu par en-tête de proxy."""
    pem = _normalize_header_value(request.headers.get(header_names.certificate, ""))
    if not pem:
        return None
    try:
        return x509.load_pem_x509_certificate(pem.encode("ascii")).public_bytes(
            cast(Encoding, Encoding.DER)
        )
    except ValueError:
        return None


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
