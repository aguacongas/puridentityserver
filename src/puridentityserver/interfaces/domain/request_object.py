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


@dataclass(frozen=True, slots=True)
class RequestObjectDecryptionResult:
    """Issu du déchiffrement d'un ``request`` chiffré (OIDC Core 1.0 §10.1).

    ``plaintext`` porte le JWT obtenu (JWE compact déchiffré), prêt à
    rejoindre la chaîne de traitement habituelle — signature, claims,
    exigences fédérées. Il est ``None`` si le document est refusé :
    ``reason`` porte alors la raison du refus, rendue en
    ``invalid_request_object`` par le cas d'utilisation.
    """

    plaintext: str | None = None
    reason: str = ""


class RequestObjectDecrypter(Protocol):
    """Déchiffre le ``request`` présenté en JWE compact (OIDC Core 1.0 §10.1)."""

    async def decrypt(
        self,
        *,
        document: str,
        algorithm: str,
        method: str,
        key_id: str = "",
    ) -> RequestObjectDecryptionResult:
        """Déchiffre ``document`` (JWE compact) avec la clé de l'OP.

        ``algorithm``/``method`` sont les en-têtes ``alg``/``enc`` du
        document, déjà contrôlés par le cas d'utilisation contre la
        configuration publiée au discovery ; ``key_id`` l'en-tête ``kid``
        (``""`` si absent : la clé unique de chiffrement est alors
        utilisée). ``reason`` explique tout refus : clé introuvable,
        matériel RSA absent, algorithme convertible inexistant, violation
        d'intégrité (tag CBC-HMAC ou GCM)…
        """
        ...


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
        jti_namespace: str = "ciba:",
    ) -> SignedRequestObjectResult:
        """Vérifie signature, claims temporels et, le cas échéant, anti-replay.

        ``client`` est le client nommé par le claim ``iss`` (dont les JWKS
        servent à vérifier la signature), ``issuer`` la valeur d'``aud``
        attendue et ``allowed_algorithms`` les en-têtes ``alg`` admis
        (algorithme enregistré du client appelant, sinon la liste publiée
        au discovery). ``required_claims`` liste les claims exigés — CIBA
        §7.1.1 pour le backchannel (``jti`` inclus), ``exp``/``nbf``/
        ``scope``/``nonce``/``redirect_uri`` pour un request object FAPI
        (FAPI1-ADV-5.2.2-13 à -18), ``exp``/``jti`` pour un request object
        fédéré (OpenID Federation 1.1 §12.1.1.1). ``enforce_jti`` exige et
        mémorise le ``jti`` (anti-replay) ; les request objects FAPI et
        standards ne portent pas de ``jti`` et désactivent ce contrôle.
        ``jti_namespace`` sépare les empreintes ``jti`` de chaque famille
        dans le store anti-replay partagé. ``reason`` explique tout
        refus : algorithme non admis, signature invalide, claim requis
        absent ou hors bornes (``exp``/``nbf``, 60 minutes), ``jti``
        réjoué…
        """
        ...
