"""Vérification du ``request`` signé au backchannel endpoint (OIDC CIBA 1.0 §7.1.1).

Le request object (JAR, RFC 9101) est un JWT signé par le client : sa
signature est vérifiée contre ses JWKS enregistrés (``jwks`` embarqués ou
``jwks_uri`` distante), les claims temporels sont bornés — ``iss``, ``aud``,
``exp``, ``iat``, ``nbf`` et ``jti`` sont tous requis (CIBA §7.1.1) et la
durée de vie ``exp - nbf`` est limitée à 60 minutes (FAPI-CIBA-ID1 §5.2.2) —
et le ``jti`` déjà présenté est refusé (anti-replay). Tout refus est rendu
``invalid_request`` côté endpoint (CIBA §13).
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import datetime, timezone

import jwt as pyjwt

from puridentityserver.domain.authorization import Client
from puridentityserver.domain.dpop import DPoPReplay, jti_hash
from puridentityserver.infrastructure.client_assertions import resolve_signing_key
from puridentityserver.interfaces.domain.request_object import (
    SignedRequestObjectResult,
)
from puridentityserver.interfaces.repositories.dpop_replay_repository import (
    DpopReplayRepository,
)

#: Namespace anti-replay des request objects CIBA : les empreintes de ``jti``
#: ne croisent jamais celles des preuves DPoP partageant le même store.
_JTI_NAMESPACE = "ciba:"

#: Durée de vie maximale d'un request object — FAPI-CIBA-ID1 §5.2.2 (9)
#: limite la fenêtre ``nbf`` → ``exp`` à 60 minutes.
MAX_REQUEST_OBJECT_LIFETIME_SECONDS = 3600

#: Claims obligatoires d'un request object CIBA (CIBA §7.1.1).
_REQUIRED_CLAIMS = ("iss", "aud", "exp", "iat", "nbf", "jti")


def _refus(reason: str) -> SignedRequestObjectResult:
    """Refus standard d'un request object (→ ``invalid_request``, CIBA §13)."""
    return SignedRequestObjectResult(reason=reason)


def _timestamp(claims: dict[str, object], name: str) -> int:
    """Timestamp Unix d'un claim requis, ``TypeError``/``ValueError`` si malformé."""
    value = claims[name]
    if isinstance(value, bool):
        raise TypeError(f"claim {name} : booléen non admis")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        return int(value)
    raise TypeError(f"claim {name} : nombre attendu")


class PyJWTSignedRequestObjectVerifier:
    """Implémentation PyJWT du port : signature JWKS + bornes + anti-replay.

    Le ``jti`` validé est mémorisé par son empreinte SHA-256 namespacée
    (``ciba:``) dans le store anti-replay partagé avec les preuves DPoP :
    un ``jti`` déjà présenté est refusé et les deux familles de jetons ne
    se croisent jamais (le store n'est qu'un magasin d'empreintes vues).
    """

    def __init__(self, replays: DpopReplayRepository) -> None:
        """Injection du store anti-replay des ``jti`` (DPoP, table partagée)."""
        self._replays = replays

    def issuer_of(self, token: str) -> str:
        """Retourne le claim ``iss`` non vérifié du jeton, ``""`` si illisible.

        Sert à résoudre le client dont les JWKS vérifieront la signature ;
        le contrôle de signature lui-même est fait par ``verify``.
        """
        try:
            claims = pyjwt.decode(
                token,
                options={
                    "verify_signature": False,  # NOSONAR(S5659) — lecture seule
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except (pyjwt.PyJWTError, ValueError):
            return ""
        issuer = claims.get("iss")
        return issuer if isinstance(issuer, str) else ""

    async def verify(
        self,
        *,
        token: str,
        client: Client,
        issuer: str,
        allowed_algorithms: Sequence[str],
    ) -> SignedRequestObjectResult:
        """Vérifie signature, claims temporels et anti-replay du ``jti``.

        ``client`` est le client nommé par le claim ``iss`` (dont les JWKS
        servent à vérifier la signature), ``issuer`` la valeur d'``aud``
        attendue et ``allowed_algorithms`` les en-têtes ``alg`` admis.
        """
        try:
            header = pyjwt.get_unverified_header(token)  # NOSONAR(S5659)
        except pyjwt.PyJWTError:
            return _refus("JWT attendu (en-tête illisible)")
        algorithm = str(header.get("alg", ""))
        if algorithm not in allowed_algorithms:
            return _refus(f"algorithme de signature non admis : {algorithm!r}")
        key = await self._signing_key(token, client)
        if key is None:
            return _refus("aucune clé du client ne correspond à l'en-tête du jeton")
        claims, reason = _claims(token, key, algorithm, issuer=issuer, client=client)
        if claims is None:
            return _refus(reason)
        try:
            lifetime = _timestamp(claims, "exp") - _timestamp(claims, "nbf")
        except (TypeError, ValueError):
            return _refus("claims exp/nbf invalides (entiers attendus)")
        if lifetime > MAX_REQUEST_OBJECT_LIFETIME_SECONDS:
            return _refus("durée de vie (exp - nbf) supérieure à 60 minutes (FAPI-CIBA-ID1 §5.2.2)")
        return await self._remember_jti(claims)

    async def _signing_key(self, token: str, client: Client) -> object | None:
        """Clé de vérification du jeton parmi les JWKS du client, ``None`` si absente."""
        try:
            return await asyncio.to_thread(resolve_signing_key, token, client.jwks, client.jwks_uri)
        except (pyjwt.PyJWTError, KeyError, OSError, ValueError):
            return None

    async def _remember_jti(self, claims: dict[str, object]) -> SignedRequestObjectResult:
        """Mémorise le ``jti`` du jeton validé ; refuse un ``jti`` déjà présenté."""
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            return _refus("claim jti absent ou vide")
        digest = jti_hash(f"{_JTI_NAMESPACE}{jti}")
        if await self._replays.is_used(digest):
            return _refus("claim jti déjà présenté (anti-replay)")
        exp = datetime.fromtimestamp(_timestamp(claims, "exp"), tz=timezone.utc)
        await self._replays.save(DPoPReplay(jti_hash=digest, expires_at=exp))
        await self._replays.purge_expired()
        return SignedRequestObjectResult(claims=claims)


def _claims(
    token: str,
    key: object,
    algorithm: str,
    *,
    issuer: str,
    client: Client,
) -> tuple[dict[str, object] | None, str]:
    """Décode le JWT signé et contrôle ses claims ; ``(None, raison)`` si refusé."""
    try:
        claims = pyjwt.decode(
            token,
            key,  # type: ignore[arg-type]  # clé JWK (types-PyJWT ne couvre pas le cas client)
            algorithms=[algorithm],
            audience=issuer,
            issuer=client.client_id,
            options={"require": list(_REQUIRED_CLAIMS)},
        )
    except pyjwt.MissingRequiredClaimError as exc:
        return None, f"claim requis absent : {exc}"
    except pyjwt.ExpiredSignatureError:
        return None, "request object expiré (claim exp)"
    except pyjwt.ImmatureSignatureError:
        return None, "request object pas encore valide (claim nbf)"
    except pyjwt.InvalidIssuerError:
        return None, f"claim iss différent du client {client.client_id!r}"
    except pyjwt.InvalidAudienceError:
        return None, "claim aud différent de l'issuer"
    except pyjwt.PyJWTError:
        return None, "signature du request object invalide"
    return claims, ""
