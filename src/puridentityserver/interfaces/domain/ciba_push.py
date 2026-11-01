"""Port de notification CIBA en mode push (OIDC CIBA 1.0 §10.2, best-effort)."""

from __future__ import annotations

from typing import Protocol


class CibaPushNotifier(Protocol):
    """Notifie par POST JSON un client CIBA en mode ``push`` (CIBA �7.1.1).

    Un seul envoi est tenté, sans redirection ni reprise : un échec est
    toléré, le client conservant la possibilité de récupérer le résultat par
    poll sur `/token`.
    """

    async def notify_push(
        self,
        *,
        url: str,
        client_notification_token: str,
        auth_req_id: str,
        notification: str | None = None,
    ) -> None:
        """POST ``{"auth_req_id": ...}`` avec ``Authorization: Bearer``.

        Ignore silencieusement les échecs réseau ou HTTP : la notification
        ne conditionne jamais la décision déjà appliquée.
        """
        ...
