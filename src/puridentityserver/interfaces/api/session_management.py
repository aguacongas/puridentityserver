"""Routes FastAPI du Session Management OIDC 1.0 (suivi navigateur).

Expose deux endpoints (OIDC Session Management 1.0 §3.2-3.3) :

- ``GET /session_state`` — page ``check_session_iframe`` : le RP l'embarque
  en iframe cachée ; un script y écoute les ``postMessage``
  ``"<client_id> <session_state>"`` et interroge l'endpoint de statut en
  provenance du même serveur, puis répond ``unchanged`` / ``changed`` /
  ``error`` à l'émetteur (origines restreintes).
- ``GET /check_session`` — endpoint de statut de session : recalcule le
  ``session_state`` côté serveur (client, origin issue du ``postMessage``,
  ``sid`` du cookie HttpOnly) et indique si la session est toujours active.
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse

from puridentityserver.application.session_management import (
    SessionManagementUseCase,
    origin_of_url,
)
from puridentityserver.identity.config import session_sid
from puridentityserver.interfaces.repositories.readers import ClientReader

_CHECK_SESSION_IFRAME_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PurIdentityServer - session state</title>
</head>
<body>
<script>
(function () {
  "use strict";
  function reply(source, origin, message) {
    try {
      source.postMessage(message, origin);
    } catch (error) {}
  }
  window.addEventListener("message", function (event) {
    var message = typeof event.data === "string" ? event.data : "";
    var separator = message.lastIndexOf(" ");
    if (separator <= 0) {
      reply(event.source, event.origin, "error");
      return;
    }
    var client_id = message.substring(0, separator);
    var session_state = message.substring(separator + 1);
    if (!client_id || !session_state || session_state.indexOf(" ") !== -1) {
      reply(event.source, event.origin, "error");
      return;
    }
    var request = new XMLHttpRequest();
    request.open(
      "GET",
      "/check_session?client_id=" + encodeURIComponent(client_id) +
        "&session_state=" + encodeURIComponent(session_state) +
        "&origin=" + encodeURIComponent(event.origin),
      true
    );
    request.onload = function () {
      if (request.status === 200) {
        reply(event.source, event.origin,
          request.responseText === "ok" ? "unchanged" : "changed");
      } else {
        reply(event.source, event.origin, "error");
      }
    };
    request.onerror = function () {
      reply(event.source, event.origin, "error");
    };
    request.send();
  });
})();
</script>
</body>
</html>
"""


def session_management_router(
    usecase: SessionManagementUseCase,
    client_repository: ClientReader,
) -> APIRouter:
    """Construit le routeur du Session Management (iframe + endpoint de statut)."""
    router = APIRouter(tags=["session-management"])

    @router.get(
        "/session_state",
        response_class=HTMLResponse,
        summary="check_session_iframe (OIDC Session Management 1.0 §3.2)",
    )
    async def check_session_iframe() -> str:
        """Page HTML à embarquer en iframe cachée côté RP."""
        return _CHECK_SESSION_IFRAME_PAGE

    @router.get(
        "/check_session",
        response_class=PlainTextResponse,
        summary="Session status (OIDC Session Management 1.0 §3.2)",
    )
    async def check_session(
        request: Request,
        client_id: str = Query(default=""),
        session_state: str = Query(default=""),
        origin: str = Query(default=""),
    ) -> Response:
        """Statut de la session : ``ok`` tant que la valeur correspond toujours.

        Récalcule le ``session_state`` avec le ``sid`` courant de la session
        navigateur (cookie HttpOnly). ``error`` (400) si la demande est
        malformée ou le client inconnu ; ``changed`` quand aucune session
        active ne correspond au ``session_state`` reçu.
        """
        if (
            not client_id
            or not session_state
            or " " in session_state
            or not _is_valid_origin(origin)
        ):
            return PlainTextResponse("error", status_code=400)
        client = await client_repository.find_by_id(client_id)
        if client is None or not client.is_active:
            return PlainTextResponse("error", status_code=400)

        sid = await session_sid(request)
        if not sid:
            return PlainTextResponse("changed", status_code=200)
        current = usecase.verify_session_state(
            client_id=client_id,
            origin=origin,
            session_id=sid,
            session_state=session_state,
        )
        return PlainTextResponse("ok" if current else "changed", status_code=200)

    return router


def _is_valid_origin(origin: str) -> bool:
    """Vérifie qu'``origin`` est une origin HTTP(S) bien formée du RP."""
    return (
        origin.startswith(("http://", "https://"))
        and " " not in origin
        and origin_of_url(origin) == origin
    )
