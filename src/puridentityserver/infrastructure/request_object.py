"""Lecture d'un ``request_uri`` de request object (RFC 9101 §5.2).

Document JWT récupéré par la bibliothèque standard (``urllib``) exécutée hors
de la boucle d'événements (``asyncio.to_thread``, cf. ``infrastructure
backchannel``) : aucune dépendance réseau runtime n'est ajoutée. Le flux est
contrôlé avant et après l'appel réseau — destination anti-SSRF, aucun suivi de
redirection, délai et taille bornés, ``Content-Type: application/jwt`` exigé.

Les destinations privées ou loopback ne sont acceptées que si l'OP écoute
lui-même en local (``host`` loopback) : c'est le cas des tests, où le document
est hébergé par la suite sur la même machine, jamais d'une instance déployée
qui doit rester à l'abri d'une URL pointant vers son propre réseau.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import urllib.request
from email.message import Message
from typing import IO
from urllib.parse import urlsplit, urlunsplit

_MAX_DOCUMENT_BYTES = 64 * 1024
_REQUEST_TIMEOUT_SECONDS = 10
_ALLOWED_SCHEMES = frozenset(("http", "https"))
_CONTENT_TYPE = "application/jwt"


def loopback_bind(host: str) -> bool:
    """True si ``host`` est une adresse de liaison loopback (tests et dev).

    Les autres valeurs — dont ``0.0.0.0``, liaisons d'une instance déployée —
    ferment les destinations locales au fetch de ``request_uri``.
    """
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse les redirections : un ``request_uri`` doit viser le document."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> urllib.request.Request | None:
        """Annule toute redirection — ``urllib`` répond alors ``HTTPError``."""
        return None


class HTTPRequestObjectFetcher:
    """GET du document ``request_uri`` (implémentation du port ``RequestObjectFetcher``)."""

    def __init__(self, *, allow_local_targets: bool = False) -> None:
        """``allow_local_targets`` ouvre les destinations locales (tests, dev)."""
        self._allow_local_targets = allow_local_targets

    async def fetch(self, url: str) -> str | None:
        """Lit ``url`` et en retourne le corps ; ``None`` si refus ou échec."""
        target = _validated_url(url, self._allow_local_targets)
        if target is None:
            return None
        try:
            return await asyncio.to_thread(_read_document, target)
        except (OSError, ValueError):
            return None


def _validated_url(url: str, allow_local_targets: bool) -> str | None:
    """Retourne l'URL à appeler (fragment retiré) ou ``None`` si refusée."""
    parts = urlsplit(url)
    if parts.scheme not in _ALLOWED_SCHEMES or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if not allow_local_targets and not _public_host(parts.hostname):
        return None
    # Le fragment (empreinte du document, RFC 9101 §5.2) n'appartient pas à la
    # ressource : il ne doit pas partir dans la requête.
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def _public_host(hostname: str) -> bool:
    """True si toutes les adresses résolues de ``hostname`` sont publiques."""
    try:
        addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    return all(_is_public(str(address[4][0])) for address in addresses)


def _is_public(address: str) -> bool:
    """True si l'adresse n'appartient à aucune plage réservée (loopback, privée…)."""
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def _read_document(url: str) -> str:
    """GET ``url`` sans redirection et sans suivre les liens hors 200."""
    request = urllib.request.Request(  # NOSONAR(S310)
        url,
        headers={"Accept": _CONTENT_TYPE},
        method="GET",
    )
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
        if response.status != 200 or response.headers.get_content_type() != _CONTENT_TYPE:
            raise ValueError("réponse refusée : type ou statut inattendu")
        body = response.read(_MAX_DOCUMENT_BYTES + 1)
    if len(body) > _MAX_DOCUMENT_BYTES:
        raise ValueError("document request_uri trop volumineux")
    document: str = body.decode("utf-8")
    return document
