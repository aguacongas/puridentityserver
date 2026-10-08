"""Ports des request objects (RFC 9101) : lecture ``request_uri`` et ``request`` signé.

Isolés derrière des protocoles : le cas d'utilisation ne connaît ni le
client HTTP qui lit le document JWT référencé (ni les règles de sécurité
appliquées à sa destination : schéma, adresses privées, délais, taille),
ni la vérification cryptographique du ``request`` signé (backchannel
endpoint OIDC CIBA 1.0 §7.1.1, request object FAPI 1.0 Advanced).
L'infrastructure fournit une implémentation sur ``urllib`` (aucune
dépendance réseau runtime ajoutée) et une sur PyJWT.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from puridentityserver.domain.authorization import Client


class RequestObjectFetcher(Protocol):
    """Télécharge le document ``request_uri`` référencé par un client."""

    async def fetch(self, url: str) -> str | None:
        """Retourne le corps du document JWT, ``None`` si le flux est refusé.

        ``None`` couvre les refus de sécurité (destination filtrée,
        schéma non permis) comme les échecs de transport : le cas
        d'utilisation rend alors ``invalid_request_uri`` (RFC 9101 §5.2).
        """
        ...


@dataclass(frozen=True, slots=True)
class SignedRequestObjectResult:
    """Issu de la vérification d'un ``request`` signé (CIBA §7.1.1, JAR).

    ``claims`` est ``None`` si le jeton est refusé : ``reason`` porte alors
    la raison du refus (descriptif renvoyé au client en ``invalid_request``,
    CIBA §13). Sinon ``claims`` contient les claims de demande validés,
    prêts à être fusionnés aux paramètres du formulaire.
    """

    claims: dict[str, object] | None = None
    reason: str = ""


class SignedRequestObjectVerifier(Protocol):
    """Vérifie le ``request`` signé d'une demande (OIDC CIBA 1.0 §7.1.1, FAPI 1.0)."""

    def issuer_of(self, token: str) -> str:
        """Retourne le claim ``iss`` non vérifié du jeton, ``""`` si illisible.

        Sert à résoudre le client dont les JWKS vérifieront la signature ;
        le contrôle de signature lui-même est fait par ``verify``.
        """
        ...

    async def verify(
        self,
        *,
        token: str,
        client: Client,
        issuer: str,
        allowed_algorithms: Sequence[str],
        required_claims: Sequence[str] = ("iss", "aud", "exp", "iat", "nbf", "jti"),
        enforce_jti: bool = True,
    ) -> SignedRequestObjectResult:
        """Vérifie signature, claims temporels et, le cas échéant, anti-replay.

        ``client`` est le client nommé par le claim ``iss`` (dont les JWKS
        servent à vérifier la signature), ``issuer`` la valeur d'``aud``
        attendue et ``allowed_algorithms`` les en-têtes ``alg`` admis
        (algorithme enregistré du client appelant, sinon la liste publiée
        au discovery). ``required_claims`` liste les claims exigés — CIBA
        §7.1.1 pour le backchannel (``jti`` inclus), ``exp``/``nbf``/
        ``scope``/``nonce``/``redirect_uri`` pour un request object FAPI
        (FAPI1-ADV-5.2.2-13 à -18). ``enforce_jti`` exige et mémorise le
        ``jti`` (anti-replay) ; les request objects FAPI ne portent pas de
        ``jti`` et désactivent ce contrôle. ``reason`` explique tout
        refus : algorithme non admis, signature invalide, claim requis
        absent ou hors bornes (``exp``/``nbf``, 60 minutes), ``jti``
        réjoué…
        """
        ...
