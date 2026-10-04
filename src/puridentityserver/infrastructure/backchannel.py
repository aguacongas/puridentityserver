"""Client HTTP de notification back-channel (logout OIDC et CIBA).

Couvre OIDC Back-Channel Logout 1.0 §3 (POST form ``logout_token``) et
OIDC CIBA 1.0 §10.2 (POST JSON ``{"auth_req_id": ...}`` avec bearer).

Implémentation sur la bibliothèque standard (``urllib``) exécutée hors de
la boucle d'événements (``asyncio.to_thread``) pour ne pas bloquer les
requêtes concurrentes : aucune dépendance réseau runtime n'est ajoutée.
Les échecs (réseau, payloads refusés) sont tolérés — la notification est
best effort et ne conditionne jamais la terminaison de session (logout)
ni la décision déjà appliquée (CIBA).
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request
from email.message import Message
from typing import IO

_BACKCHANNEL_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
_REQUEST_TIMEOUT_SECONDS = 10


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse toute redirection : la requête notifiée doit viser l'URI exacte."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> urllib.request.Request | None:
        """Ne réécrit jamais la requête — l'erreur HTTP d'origine est retournée."""
        return None


class HTTPBackchannelNotifier:
    """POST form d'un ``logout_token`` vers une ``backchannel_logout_uri``."""

    async def notify(self, *, url: str, logout_token: str) -> None:
        """POST form ``logout_token`` vers ``url`` ; échecs silencieux."""
        payload = urllib.parse.urlencode({"logout_token": logout_token}).encode("utf-8")

        def _post() -> None:
            request = urllib.request.Request(  # NOSONAR(S310)
                url,
                data=payload,
                method="POST",
                headers=_BACKCHANNEL_FORM_HEADERS,
            )
            with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
                response.read()

        try:
            await asyncio.to_thread(_post)
        except OSError:
            return None


class HTTPCibaPingNotifier:
    """POST JSON ``{"auth_req_id": ...}`` vers un notification endpoint (CIBA §10.2).

    Un seul essai : aucune redirection suivie, aucun retry — un échec est
    toléré, le client conserve le mode poll pour récupérer le résultat.
    """

    async def notify_ping(
        self, *, url: str, client_notification_token: str, auth_req_id: str
    ) -> None:
        """Envoie la notification ``ping`` ; réseau et HTTP en échec ignorés."""
        payload = json.dumps({"auth_req_id": auth_req_id}, separators=(",", ":")).encode("utf-8")

        def _post() -> None:
            request = urllib.request.Request(  # NOSONAR(S310)
                url,
                data=payload,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {client_notification_token}",
                },
            )
            opener = urllib.request.build_opener(_NoRedirectHandler)
            with opener.open(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
                response.read()

        try:
            await asyncio.to_thread(_post)
        except OSError:
            return None
