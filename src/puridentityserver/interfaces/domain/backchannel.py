"""Port de notification back-channel des RPs (OIDC Back-Channel Logout 1.0 §3).

Isolé derrière un protocole : le cas d'utilisation ne connaît pas le
client HTTP utilisé (le POST ``logout_token`` sortant). L'infrastructure
fournit une implémentation sur ``urllib`` (aucune dépendance réseau
runtime ajoutée), remplaçable par un client HTTP dédié.
"""

from __future__ import annotations

from typing import Protocol


class BackchannelNotifier(Protocol):
    """Notifie par POST form une URI de logout back-channel d'un client.

    ``notify`` est fire-and-forget du point de vue du cas d'utilisation :
    son résultat ne conditionne jamais la terminaison de session.
    """

    async def notify(self, *, url: str, logout_token: str) -> None:
        """POST ``logout_token`` en ``application/x-www-form-urlencoded``.

        Ignore silencieusement les échecs réseau : la notification est
        best effort (erreurs ou délais tolérés), la déconnexion de
        l'utilisateur est déjà effective.
        """
        ...


class CibaPingNotifier(Protocol):
    """Notifie par POST JSON le ``notification endpoint`` d'un client (CIBA §10.2).

    Un seul envoi est tenté, sans redirection ni reprise : le résultat de
    la demande reste récupérable par poll (mode ``ping`` inclus).
    """

    async def notify_ping(
        self, *, url: str, client_notification_token: str, auth_req_id: str
    ) -> None:
        """POST ``{"auth_req_id": ...}`` avec ``Authorization: Bearer``.

        Ignore silencieusement les échecs réseau ou HTTP : la
        notification ne conditionne jamais la décision déjà appliquée.
        """
        ...
