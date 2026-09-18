"""Middleware CORS dynamique — origines déduites des clients enregistrés.

Contrairement au ``CORSMiddleware`` de Starlette, figé à la construction
sur une liste statique d'origines, ce middleware interroge le registre des
clients à chaque requête : une origine est acceptée si elle est l'origine
d'une ``redirect_uri`` d'un client actif ou l'une de ses ``web_origins``
(OAuth 2.0 for Browser-Based Apps). Un client enregistré dynamiquement
(RFC 7591) est ainsi couvert immédiatement, sans reconfiguration ni
redémarrage du serveur.
"""

from __future__ import annotations

from starlette.datastructures import Headers
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from puridentityserver.interfaces.repositories.client_repository import ClientRepository

_ALLOW_METHODS = ("GET", "POST", "DELETE")
_ALLOW_HEADERS = ("Authorization", "Content-Type")
_EXPOSE_HEADERS = "Location, WWW-Authenticate"
_PREFLIGHT_MAX_AGE = "600"


class DynamicCORSMiddleware:
    """Autorise en CORS les origines déduites des clients actifs.

    Chaque requête portant un en-tête ``Origin`` est comparée aux origines
    des clients du registre (``redirect_uris`` + ``web_origins``). Les
    preludes (``OPTIONS`` avec ``Access-Control-Request-Method``) sont
    traités en 200 lorsque l'origine est autorisée, en 400 sinon ; les
    requêtes simples autorisées reçoivent les en-têtes
    ``Access-Control-*`` sur leur réponse.
    """

    def __init__(
        self,
        app: ASGIApp,
        client_repository: ClientRepository,
        *,
        allow_methods: tuple[str, ...] = _ALLOW_METHODS,
        allow_headers: tuple[str, ...] = _ALLOW_HEADERS,
    ) -> None:
        """Câble le middleware sur l'application et le registre clients."""
        self.app = app
        self._clients = client_repository
        self._allow_methods = allow_methods
        self._allow_headers = allow_headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """En-têtes CORS sur les réponses, preludes résolus avant le routage."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        origin = headers.get("origin")
        if origin is None:
            await self.app(scope, receive, send)
            return

        allowed = await self._clients.is_cors_origin_allowed(origin)
        is_preflight = (
            scope["method"] == "OPTIONS"
            and headers.get("access-control-request-method") is not None
        )
        if is_preflight:
            response = self._preflight_response(origin) if allowed else Response(status_code=400)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, _inject_cors(send, origin if allowed else None))

    def _preflight_response(self, origin: str) -> Response:
        """Réponse 200 de prelude pour une origine autorisée."""
        return Response(
            status_code=200,
            headers={
                "access-control-allow-origin": origin,
                "vary": "Origin",
                "access-control-allow-methods": ", ".join(self._allow_methods),
                "access-control-allow-headers": ", ".join(self._allow_headers),
                "access-control-max-age": _PREFLIGHT_MAX_AGE,
            },
        )


def _inject_cors(send: Send, origin: str | None) -> Send:
    """Enveloppe ``send`` pour ajouter les en-têtes CORS à la réponse émise."""

    async def send_with_cors(message: Message) -> None:
        if message["type"] == "http.response.start" and origin is not None:
            headers = list(message.get("headers", ()))
            headers.append((b"access-control-allow-origin", origin.encode("latin-1")))
            headers.append((b"vary", b"Origin"))
            headers.append((b"access-control-expose-headers", _EXPOSE_HEADERS.encode("latin-1")))
            message = {**message, "headers": headers}
        await send(message)

    return send_with_cors
