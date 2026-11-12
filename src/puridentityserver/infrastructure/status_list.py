"""Lecture de la status list référencée par un credential (OTSL, issue #224).

Le verifier OpenID4VP contrôle la révocation d'un credential SD-JWT VC qui
porte le claim ``status`` : il récupère le Status List Token publié à l'``uri``
de ``status.status_list`` (draft-ietf-oauth-status-list §8.1) puis lit le bit
de l'``index`` du credential. Le flux est contrôlé comme le fetch d'un
``request_uri`` : destination anti-SSRF, aucun suivi de redirection, délai et
taille bornés, ``Content-Type`` de la réponse exigé
(``application/statuslist+jwt``).

Les destinations privées ou loopback ne sont acceptées que si l'OP écoute
lui-même en local (``host`` loopback) ou si
``oid4vp_status_list_allow_local_targets`` l'ouvre explicitement : c'est le cas
du harness de certification, où la suite héberge la status list sur la même
machine. Un ``None`` est retourné sur tout refus ou échec : le use case rejette
alors la présentation (un verifier qui ne peut pas lire le statut n'accepte
pas le credential qui le référence).
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.request
from email.message import Message
from typing import IO
from urllib.parse import urlsplit, urlunsplit

#: Media type exigé du Status List Token (draft-ietf-oauth-status-list §5.1).
CONTENT_TYPE = "application/statuslist+jwt"

#: Délai maximal du GET de la status list, en secondes.
_TIMEOUT_SECONDS = 10

#: Taille maximale du corps lu (bitstring compressé : 64 Ko largement suffisant).
_MAX_TOKEN_BYTES = 65536

_ALLOWED_SCHEMES = frozenset({"https", "http"})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse les redirections : la cible validée est la seule à appeler."""

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


class StatusListFetcher:
    """GET d'un Status List Token servi par le status provider (OTSL §8.1).

    La classe est synchrone : l'appelant (use case ``OID4VPVerifierUseCase``,
    déjà exécuté hors boucle d'événements par la route ``vp_response``) gère
    lui-même son découplage avec l'async.
    """

    def __init__(self, *, allow_local_targets: bool = False) -> None:
        """``allow_local_targets`` ouvre les destinations locales (harness, tests)."""
        self._allow_local_targets = allow_local_targets

    def fetch(self, url: str) -> str | None:
        """Retourne le corps du token ; ``None`` si refus de destination ou échec."""
        target = _validated_url(url, self._allow_local_targets)
        if target is None:
            return None
        try:
            return _read_token(target)
        except (OSError, ValueError):
            return None


def _validated_url(url: str, allow_local_targets: bool) -> str | None:
    """Retourne l'URL à appeler ou ``None`` si schéma, identifiants ou hôte refusés."""
    parts = urlsplit(url)
    if parts.scheme not in _ALLOWED_SCHEMES or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if not allow_local_targets and not _public_host(parts.hostname):
        return None
    # La status list n'a pas de fragment document : rien à retirer, mais on
    # repart d'une URL canonique pour ne jamais la modifier autrement.
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


def _read_token(url: str) -> str:
    """GET ``url`` sans redirection, corps borné et ``Content-Type`` exigé.

    Raises:
        ValueError: si le statut, le type MIME ou la taille de la réponse
            sortent des bornes attendues, ou si le corps n'est pas ASCII.
    """
    request = urllib.request.Request(  # NOSONAR(S310)
        url,
        headers={"Accept": CONTENT_TYPE},
        method="GET",
    )
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(request, timeout=_TIMEOUT_SECONDS) as response:
        if response.status != 200 or response.headers.get_content_type() != CONTENT_TYPE:
            raise ValueError("réponse refusée : type ou statut inattendus")
        body = response.read(_MAX_TOKEN_BYTES + 1)
    if len(body) > _MAX_TOKEN_BYTES:
        raise ValueError("status list token trop volumineux")
    token: str = body.decode("ascii")
    return token
