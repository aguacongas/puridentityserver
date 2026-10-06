"""Port de vérification des assertions JWT signées par un client (RFC 7523).

Le token endpoint s'appuie sur ce port pour vérifier :

- l'authentification du client par assertion (``client_secret_jwt`` /
  ``private_key_jwt``, RFC 7523 §2.2) : ``iss`` et ``sub`` valent le
  ``client_id``, ``aud`` le token endpoint ;
- le grant ``jwt-bearer`` (RFC 7523 §2.1) : l'assertion délègue un sujet
  (``sub``) au nom duquel les jetons sont demandés.

Le backchannel authentication endpoint (OIDC CIBA 1.0 §7.1) accepte
plusieurs valeurs d'``aud`` (issuer, token endpoint ou endpoint CIBA) et
décodent aussi un ``login_hint_token`` signé par le client (§7.1.1).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from puridentityserver.domain.authorization import Client

CLIENT_ASSERTION_TYPE_URN = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
JWT_BEARER_GRANT_TYPE_URN = "urn:ietf:params:oauth:grant-type:jwt-bearer"


@dataclass(frozen=True, slots=True)
class LoginHintTokenResult:
    """Issu du décodage d'un ``login_hint_token`` (OIDC CIBA 1.0 §7.1.1).

    ``claims`` est ``None`` si le jeton est illisible ou sa signature
    invalide ; ``expired`` distingue un jeton signé mais expiré, signalé
    ``expired_login_hint_token`` au client.
    """

    claims: dict[str, object] | None = None
    expired: bool = False


class ClientAssertionVerifier(Protocol):
    """Vérifie la signature et les claims d'une assertion signée par le client."""

    async def verify(
        self,
        *,
        token: str,
        client: Client,
        audience: str | Sequence[str],
        require_iss_eq_sub: bool,
    ) -> dict[str, object] | None:
        """Retourne les claims validés de l'assertion, ou ``None`` si invalide.

        ``audience`` accepte une valeur unique ou un ensemble (CIBA §7.1 :
        issuer, token endpoint et endpoint CIBA sont tous admis comme
        audience du client). ``require_iss_eq_sub`` impose
        ``iss == sub == client_id`` (usage authentification client) ;
        à ``False``, ``sub`` désigne le sujet délégué par le grant
        jwt-bearer.
        """
        ...

    def issuer_of(self, token: str) -> str:
        """Retourne le claim ``iss`` non vérifié de l'assertion, ``""`` si illisible.

        Sert uniquement à déduire le ``client_id`` quand le corps form n'en
        porte pas (formulaire ``private_key_jwt``) : la signature reste
        intégralement vérifiée ensuite par ``verify``.
        """
        ...

    async def decode_login_hint_token(self, *, token: str, client: Client) -> LoginHintTokenResult:
        """Décode un ``login_hint_token`` signé par le client (CIBA §7.1.1).

        La signature est vérifiée avec le matériel du client (secret
        partagé ou JWKS) ; contrairement à une assertion RFC 7523, aucun
        ``iss``/``aud`` n'est exigé (claims déployement-spécifiques). Un
        jeton signé mais expiré retourne ``expired`` — l'appelant répond
        ``expired_login_hint_token``.
        """
        ...
