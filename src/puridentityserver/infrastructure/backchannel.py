"""Client HTTP de notification back-channel (OIDC Back-Channel Logout 1.0 §3).

Implémentation sur la bibliothèque standard (``urllib``) exécutée hors de
la boucle d'événements (``asyncio.to_thread``) pour ne pas bloquer les
requêtes concurrentes : aucune dépendance réseau runtime n'est ajoutée.
Les échecs (réseau, payloads refusés) sont tolérés — la notification est
best effort et ne conditionne jamais la terminaison de session.
"""

from __future__ import annotations

import asyncio
import urllib.parse
import urllib.request

_BACKCHANNEL_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
_REQUEST_TIMEOUT_SECONDS = 10


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
