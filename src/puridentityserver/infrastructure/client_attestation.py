"""Vérification des en-têtes d'attestation client (§5, §6.2, §9).

Implémentation PyJWT du port ``interfaces/domain/client_attestation`` :
l'attestation est vérifiée avec les clés publiques de l'attester de
confiance configuré (settings ``client_attestation_issuer`` /
``client_attestation_jwks``), puis la preuve PoP avec la clé ``cnf.jwk``
extraite de l'attestation validée — la clé du PoP est donc toujours
cellule de l'attestation (§5.2 règle 3, §9-7).

Contrôles appliqués (draft-ietf-oauth-attestation-based-client-auth) :

- en-têtes : exactement un ``OAuth-Client-Attestation`` et un
  ``OAuth-Client-Attestation-PoP`` (§9-1) — contrôle porté par
  l'extraction des en-têtes côté API ;
- ``typ`` et ``alg`` asymétrique des deux JWT (§5.1, §5.2, §9-2 à §9-4) ;
- attestation : signature vérifiée contre l'attester de confiance (§9-5),
  ``iss`` = issuer configuré (égalité stricte, §5.1), ``exp``/``cnf``
  présents (``iat`` facultatif au §5.1), ``sub`` = ``client_id`` (§9-13),
  ``cnf.jwk`` sans paramètre privé (§9-6) ;
- PoP : signature vérifiée avec ``cnf.jwk`` (§9-7), ``iss`` = ``client_id``,
  ``aud`` = issuer de l'AS (§9-10), ``iat`` dans une fenêtre raisonnable
  (§9-9), ``jti`` anti-replay (§9-12).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import jwt as pyjwt

from puridentityserver.domain.dpop import DPoPReplay, jti_hash
from puridentityserver.infrastructure.client_assertions import resolve_signing_key
from puridentityserver.infrastructure.dpop import jwk_thumbprint
from puridentityserver.interfaces.domain.client_attestation import (
    CLIENT_ATTESTATION_POP_TYPE,
    CLIENT_ATTESTATION_TYPE,
)
from puridentityserver.interfaces.repositories.dpop_replay_repository import DpopReplayRepository

#: Fenêtre d'acceptation de l'``iat`` du PoP (§5.2 : un ``iat`` « unreasonable »
#: est refusé — la suite de certification fabrique le PoP juste avant chaque
#: requête ; couvre aussi la latence réseau comme pour ``DPOP_IAT_SKEW_SECONDS``).
_ATTESTATION_POP_IAT_SKEW_SECONDS = 300

#: Tolérance d'horloge (``nbf``/``iat`` futurs) — reprise du leeway des assertions.
_LEEWAY_SECONDS = 30

#: Namespace anti-replay des ``jti`` de PoP : cloisonne les empreintes de la
#: table partagée avec les preuves DPoP et les request objects.
_JTI_NAMESPACE = "attest:"

#: Algorithmes de signature asymétriques acceptés (§9-4 : « registered
#: asymmetric digital signature algorithm », ``none`` et HMAC refusés).
_ASYMMETRIC_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)

#: Paramètres JWK signant une clé privée (§9-6 : ``cnf.jwk`` ne doit pas en porter).
_PRIVATE_KEY_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


class PyJWTClientAttestationVerifier:
    """Vérifie la paire attestation/PoP avec les clés de l'attester de confiance."""

    def __init__(
        self,
        *,
        issuer: str,
        as_issuer: str,
        jwks: tuple[dict[str, object], ...],
        replays: DpopReplayRepository,
    ) -> None:
        """Injection des deux issuer en jeu, des clés attester et du store anti-replay.

        ``issuer`` est l'identifiant de l'attester de confiance : il est
        comparé à l'``iss`` de l'attestation en égalité stricte (simple
        comparaison de chaînes, §5.1) — la barre finale éventuelle fait
        donc partie de la valeur attendue. ``as_issuer`` est l'identifiant
        de l'AS (RFC 8414) attendu dans l'``aud`` du PoP ; les deux formes
        (avec et sans barre finale) sont admises car la suite de
        certification reprend l'issuer de sa configuration telle quelle.
        """
        self._attester_issuer = issuer
        self._as_audiences = tuple(dict.fromkeys((as_issuer, as_issuer.rstrip("/"))))
        self._jwks = jwks
        self._replays = replays

    def subject_of(self, attestation: str) -> str:
        """Retourne le ``sub`` non vérifié de l'attestation, ou ``""`` (§6.3).

        Le corps d'une requête peut omettre ``client_id`` : le ``sub`` de
        l'attestation sert alors à localiser le client, au même titre que
        l'``iss`` de la ``client_assertion`` (RFC 7523 §2.2). Aucune
        décision de sécurité sur cette valeur décodée sans vérification :
        ``verify`` contrôle ensuite la signature et ré-clause ``sub`` au
        ``client_id`` retenu (§9-13).
        """
        try:
            claims = pyjwt.decode(attestation, options={"verify_signature": False})
        except (pyjwt.PyJWTError, KeyError, TypeError):
            return ""
        subject = claims.get("sub")
        return subject if isinstance(subject, str) else ""

    def instance_key_of(self, attestation: str) -> str:
        """Retourne l'empreinte RFC 7638 de ``cnf.jwk`` (``""`` si illisible).

        L'empreinte identifie l'instance client (OAuth2-ATCA §10.3) : un
        refresh token émis sous une attestation doit être renouvelé avec la
        même ``cnf.jwk``. Le décodage est non vérifié, comme pour
        ``subject_of`` : la valeur n'est lue qu'après ``verify``, qui a
        contrôlé la signature et l'absence de clé privée (§9-6).
        """
        try:
            claims = pyjwt.decode(attestation, options={"verify_signature": False})
        except (pyjwt.PyJWTError, KeyError, TypeError):
            return ""
        cnf = claims.get("cnf")
        jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
        if not isinstance(jwk, dict):
            return ""
        try:
            return jwk_thumbprint(jwk)
        except (ValueError, KeyError, TypeError):
            return ""

    async def verify(self, *, attestation: str, pop: str, client_id: str) -> str | None:
        """Vérifie l'attestation puis le PoP (§6.1 recommande cet ordre)."""
        if not client_id:
            return "client_id absent de la requête (§9-13)"
        claims, reason = await self._verify_attestation(attestation, client_id)
        if claims is None:
            return reason
        cnf = claims.get("cnf")
        jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
        if not isinstance(jwk, dict):
            return "claim cnf.jwk absente de l'attestation client (§5.1)"
        if _PRIVATE_KEY_MEMBERS & jwk.keys():
            return "cnf.jwk de l'attestation client contient une clé privée (§9-6)"
        return await self._verify_pop(pop, client_id=client_id, cnf_jwk=jwk)

    async def _verify_attestation(
        self, token: str, client_id: str
    ) -> tuple[dict[str, object] | None, str | None]:
        """Décode l'attestation signée par l'attester ; ``(claims, None)`` si valide."""
        algorithm, reason = _signed_header(token, CLIENT_ATTESTATION_TYPE, "attestation client")
        if algorithm is None:
            return None, reason
        try:
            key = await asyncio.to_thread(resolve_signing_key, token, self._jwks, "")
        except (pyjwt.PyJWTError, KeyError, OSError, ValueError):
            return None, "attestation client illisible"
        if key is None:
            return (
                None,
                "aucune clé de l'attester de confiance ne correspond à l'attestation (§9-5)",
            )
        try:
            claims = pyjwt.decode(
                token,
                key,  # type: ignore[arg-type]  # clé JWK (types-PyJWT ne couvre pas ce cas)
                algorithms=[algorithm],
                issuer=self._attester_issuer,
                leeway=_LEEWAY_SECONDS,
                # ``iat`` est facultatif au §5.1 (seul le PoP l'exige) :
                # seul son format est contrôlé par PyJWT s'il est présent.
                options={"require": ["iss", "sub", "exp", "cnf"]},
            )
        except pyjwt.ExpiredSignatureError:
            return None, "attestation client expirée (§5.1)"
        except pyjwt.PyJWTError:
            return None, "attestation client invalide (signature, issuer ou bornes temporelles)"
        if claims.get("sub") != client_id:
            return None, f"sub de l'attestation '{claims.get('sub')}' ≠ client_id (§9-13)"
        return claims, None

    async def _verify_pop(
        self, token: str, *, client_id: str, cnf_jwk: dict[str, object]
    ) -> str | None:
        """Vérifie le PoP avec ``cnf.jwk`` puis mémorise son ``jti`` (anti-replay)."""
        algorithm, reason = _signed_header(token, CLIENT_ATTESTATION_POP_TYPE, "preuve PoP client")
        if algorithm is None:
            return reason
        try:
            key = resolve_signing_key(token, (cnf_jwk,), "")
        except (pyjwt.PyJWTError, KeyError, OSError, ValueError):
            return "cnf.jwk de l'attestation illisible (§9-7)"
        if key is None:
            return "cnf.jwk de l'attestation illisible (§9-7)"
        try:
            claims = pyjwt.decode(
                token,
                key,  # type: ignore[arg-type]  # clé JWK (types-PyJWT ne couvre pas ce cas)
                algorithms=[algorithm],
                audience=self._as_audiences,
                issuer=client_id,
                leeway=_LEEWAY_SECONDS,
                options={"require": ["iss", "aud", "iat", "jti"]},
            )
        except pyjwt.PyJWTError:
            return "preuve PoP client invalide (signature, iss, aud ou bornes temporelles)"
        stale = _iat_rejected(claims)
        if stale is not None:
            return stale
        return await self._remember_jti(claims)

    async def _remember_jti(self, claims: dict[str, object]) -> str | None:
        """Mémorise le ``jti`` du PoP validé ; refuse un ``jti`` déjà présenté (§9-12)."""
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            return "claim jti absente ou vide du PoP (§5.2)"
        digest = jti_hash(f"{_JTI_NAMESPACE}{jti}")
        if await self._replays.is_used(digest):
            return "jti du PoP déjà présenté (anti-replay, §9-12)"
        # L'entrée est purgée au-delà de la fenêtre d'iat encore acceptée.
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=_ATTESTATION_POP_IAT_SKEW_SECONDS + _LEEWAY_SECONDS
        )
        await self._replays.save(DPoPReplay(jti_hash=digest, expires_at=expires_at))
        await self._replays.purge_expired()
        return None


def _signed_header(token: str, expected_typ: str, label: str) -> tuple[str | None, str | None]:
    """Algorithme de l'en-tête JWT contrôlé, ou ``None`` + raison du refus (§9-2 à §9-4)."""
    try:
        header = pyjwt.get_unverified_header(token)
    except (pyjwt.PyJWTError, KeyError):
        return None, f"{label} illisible (en-tête JWT absent ou malformé)"
    typ = header.get("typ")
    if typ != expected_typ:
        return None, f"typ de {label} '{typ}' invalide (attendu '{expected_typ}')"
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm not in _ASYMMETRIC_ALGORITHMS:
        return None, f"alg '{algorithm}' de {label} refusée (signature asymétrique requise, §9-4)"
    return algorithm, None


def _iat_rejected(claims: dict[str, object]) -> str | None:
    """Vérifie que l'``iat`` du PoP est une date passée raisonnable (§9-9).

    Un ``iat`` futur est déjà refusé par PyJWT (même leeway que la
    tolérance d'horloge, ``ImmatureSignatureError``) : seul le retard est
    contrôlé ici, au-delà de la fenêtre ``_ATTESTATION_POP_IAT_SKEW_SECONDS``.
    """
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or isinstance(iat, bool):
        return "claim iat absente ou invalide du PoP (§5.2)"
    now = datetime.now(timezone.utc).timestamp()
    if iat < now - _ATTESTATION_POP_IAT_SKEW_SECONDS:
        return "claim iat du PoP trop ancienne (§9-9)"
    return None
