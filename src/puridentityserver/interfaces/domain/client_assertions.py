"""Port de vérification des assertions JWT signées par un client (RFC 7523).

Le token endpoint s'appuie sur ce port pour vérifier :

- l'authentification du client par assertion (``client_secret_jwt`` /
  ``private_key_jwt``, RFC 7523 §2.2) : ``iss`` et ``sub`` valent le
  ``client_id``, ``aud`` le token endpoint ;
- le grant ``jwt-bearer`` (RFC 7523 §2.1) : l'assertion délègue un sujet
  (``sub``) au nom duquel les jetons sont demandés.
"""

from __future__ import annotations

from typing import Protocol

from puridentityserver.domain.authorization import Client

CLIENT_ASSERTION_TYPE_URN = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
JWT_BEARER_GRANT_TYPE_URN = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class ClientAssertionVerifier(Protocol):
    """Vérifie la signature et les claims d'une assertion signée par le client."""

    async def verify(
        self,
        *,
        token: str,
        client: Client,
        audience: str,
        require_iss_eq_sub: bool,
    ) -> dict[str, object] | None:
        """Retourne les claims validés de l'assertion, ou ``None`` si invalide.

        ``require_iss_eq_sub`` impose ``iss == sub == client_id`` (usage
        authentification client) ; à ``False``, ``sub`` désigne le sujet
        délégué par le grant jwt-bearer.
        """
        ...
