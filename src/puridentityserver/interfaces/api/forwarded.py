"""Reconstruction de l'URL publique derrière un reverse proxy (RFC 9449 §4.3).

Un OP terminant le TLS derrière un proxy (Render, nginx du harness de
certification) voit ses requêtes avec l'URL interne du backend (ex.
``http://backend:8000/token``). La comparaison du claim ``htu`` d'une
preuve DPoP — construite par le client sur l'URL publique — exige donc
de reconstruire l'URL réellement appelée depuis les en-têtes
``X-Forwarded-*`` posés par le proxy.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from fastapi import Request


def public_url(request: Request, *, trust_proxy_headers: bool) -> str:
    """URL publique de la ressource requêtée, sans query ni fragment.

    Sans ``trust_proxy_headers``, retourne l'URL vue par le serveur (cas
    d'une connexion directe) : les en-têtes ``X-Forwarded-*`` sont
    forgeables et ne sont crus qu'en présence d'un proxy de confiance.
    Avec le drapeau, scheme et autorité sont repris de
    ``X-Forwarded-Proto``/``X-Forwarded-Host`` (repli sur les valeurs de
    la requête), ``X-Forwarded-Port`` complétant l'autorité dépourvue de
    port — conforme à la convention des reverse proxies (RFC 9110 §7.1).
    """
    url = str(request.url).partition("?")[0].partition("#")[0]
    if not trust_proxy_headers:
        return url
    parts = urlsplit(url)
    scheme = _first_value(request.headers.get("x-forwarded-proto", "")) or parts.scheme
    netloc = _first_value(request.headers.get("x-forwarded-host", "")) or parts.netloc
    port = _first_value(request.headers.get("x-forwarded-port", ""))
    if port:
        hostname = urlsplit(f"//{netloc}").hostname or ""
        netloc = f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"
    return urlunsplit((scheme, netloc, parts.path, "", ""))


def _first_value(header: str) -> str:
    """Première valeur d'un en-tête multi-valued (séparation par virgule)."""
    return header.split(",")[0].strip()
