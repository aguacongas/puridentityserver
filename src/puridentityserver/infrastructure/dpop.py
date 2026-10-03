"""Validation des preuves DPoP via PyJWT (RFC 9449 §4.3).

Implémentation concrète du port ``DpopProofValidator`` : en-tête
``typ``/``alg``/``jwk`` (sans clé privée), signature vérifiée avec la
clé publique transportée par la preuve, claims ``htm``/``htu``/``iat``/
``exp``/``nbf``/``ath``, puis anti-replay du ``jti`` (§11) auprès du
store injecté. La cryptographie (signature JWS, SHA-256) est déléguée à
``PyJWT`` / ``cryptography`` — jamais implémentée à la main.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

import jwt as pyjwt
from jwt.api_jwk import PyJWK

from puridentityserver.domain.dpop import (
    DPOP_IAT_SKEW_SECONDS,
    DPOP_MAX_LIFETIME_SECONDS,
    DPOP_PROOF_TYPE,
    DPoPProof,
    DPoPReplay,
    jti_hash,
)
from puridentityserver.domain.jwks import ASYMMETRIC_ALGORITHMS
from puridentityserver.interfaces.domain.dpop import DpopValidationError
from puridentityserver.interfaces.repositories.dpop_replay_repository import (
    DpopReplayRepository,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

#: Algorithmes JWS acceptés pour une preuve : les familles asymétriques
#: supportées par le serveur (RFC 9449 §4.2 — ``none`` et les algorithmes
#: symétriques HS* y sont explicitement interdits).
_DPOP_ALGORITHMS = frozenset(algorithm.value for algorithm in ASYMMETRIC_ALGORITHMS)

#: Membres JWK révélant une clé privée ou symétrique (RFC 7517 §2 : le
#: proof-of-possession transporte exclusivement la clé **publique**).
_PRIVATE_JWK_MEMBERS = frozenset(("d", "p", "q", "dp", "dq", "qi", "k", "oth"))

#: Courbe attendue par famille ``ES*`` (JWA RFC 7518 §3.1).
_ES_CURVES = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}


class PyJWTDpopProofValidator:
    """Vérifie les preuves DPoP contre la requête HTTP qu'elles autorisent.

    Chaque contrôle de la liste MUST du §4.3 est mené avant toute
    décision ; le ``jti`` n'est mémorisé (anti-replay) qu'une fois la
    preuve intégralement validée, pour qu'une entrée invalide ne puisse
    jamais brûler un ``jti`` légitime.
    """

    def __init__(self, replays: DpopReplayRepository) -> None:
        """Injection du store anti-replay des ``jti`` (RFC 9449 §11)."""
        self._replays = replays

    async def validate(
        self,
        *,
        proof: str,
        htu: str,
        method: str,
        ath: str = "",
    ) -> DPoPProof | DpopValidationError:
        """Valide une preuve puis mémorise son ``jti`` (voir le port)."""
        if not proof:
            return _reject("En-tête DPoP vide ou preuve absente")
        try:
            header = pyjwt.get_unverified_header(proof)  # NOSONAR(S5659)
            claims = pyjwt.decode(
                proof,
                options={
                    "verify_signature": False,  # NOSONAR(S5659) — lecture seule
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_aud": False,
                },
            )
        except pyjwt.PyJWTError:
            return _reject("Preuve DPoP malformée (JWT invalide)")

        header_result = _check_header(header)
        if isinstance(header_result, DpopValidationError):
            return header_result
        alg, jwk = header_result
        checked_jwk = _check_jwk(jwk, alg)
        if isinstance(checked_jwk, DpopValidationError):
            return checked_jwk
        key, thumbprint = checked_jwk

        payload = _check_payload(claims, htu=htu, method=method, ath=ath)
        if isinstance(payload, DpopValidationError):
            return payload

        signature_error = _check_signature(proof, key, alg)
        if signature_error is not None:
            return signature_error

        now = datetime.now(timezone.utc)
        digest = jti_hash(payload.jti)
        if await self._replays.is_used(digest):
            return _reject("Le jti de la preuve DPoP a déjà été présenté (RFC 9449 §11)")
        await self._replays.save(
            DPoPReplay(
                jti_hash=digest,
                expires_at=now + timedelta(seconds=2 * DPOP_IAT_SKEW_SECONDS),
            )
        )
        await self._replays.purge_expired()
        return DPoPProof(
            jkt=thumbprint,
            jti=payload.jti,
            htm=payload.htm,
            htu=payload.htu,
            nonce=payload.nonce,
        )


def jwk_thumbprint(jwk: Mapping[str, object]) -> str:
    """Empreinte RFC 7638 (base64url du SHA-256) d'une clé JWK publique.

    Le JSON canonique retient les membres requis de la famille, triés
    par nom de membre ; l'empreinte est ``base64url(SHA-256(json))``
    sans padding (RFC 7638 §3). Toute autre famille lève ``ValueError``.
    """
    kty = jwk.get("kty")
    required: tuple[str, ...]
    if kty == "RSA":
        required = ("e", "kty", "n")
    elif kty == "EC":
        required = ("crv", "kty", "x", "y")
    elif kty == "OKP":
        required = ("crv", "kty", "x")
    else:
        raise ValueError(f"Famille JWK non prise en charge pour l'empreinte : {kty!r}")
    canonical = json.dumps(
        {name: jwk[name] for name in required}, separators=(",", ":"), sort_keys=True
    )
    digest = hashlib.sha256(canonical.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _reject(description: str) -> DpopValidationError:
    """Rejet standard ``invalid_dpop_proof`` (RFC 9449 §5)."""
    return DpopValidationError(error="invalid_dpop_proof", error_description=description)


def _check_header(header: Mapping[str, Any]) -> tuple[str, dict[str, Any]] | DpopValidationError:
    """Contrôle ``typ``, ``alg`` et ``jwk`` de l'en-tête (RFC 9449 §4.2)."""
    if header.get("typ") != DPOP_PROOF_TYPE:
        return _reject(f"En-tête 'typ' doit valoir '{DPOP_PROOF_TYPE}'")
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in _DPOP_ALGORITHMS:
        return _reject("En-tête 'alg' absent ou algorithme non autorisé pour une preuve DPoP")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        return _reject("En-tête 'jwk' absent ou non objet")
    return alg, jwk


def _check_jwk(jwk: dict[str, Any], alg: str) -> tuple[Any, str] | DpopValidationError:
    """Vérifie la ``jwk`` (publique uniquement) et retourne clé + ``jkt``."""
    if _PRIVATE_JWK_MEMBERS & jwk.keys():
        return _reject("La 'jwk' de la preuve contient une clé privée ou symétrique")
    kty = jwk.get("kty")
    if kty == "RSA" and not alg.startswith(("RS", "PS")):
        return _reject("La 'jwk' (RSA) ne correspond pas à l'algorithme 'alg'")
    if kty == "EC" and not alg.startswith("ES"):
        return _reject("La 'jwk' (EC) ne correspond pas à l'algorithme 'alg'")
    expected_curve = _ES_CURVES.get(alg)
    if expected_curve is not None and jwk.get("crv") != expected_curve:
        return _reject(f"Courbe 'crv' inattendue pour {alg}")
    try:
        key = PyJWK(jwk, algorithm=alg).key
        thumbprint = jwk_thumbprint(jwk)
    except (ValueError, KeyError, TypeError, pyjwt.PyJWTError):
        return _reject("La 'jwk' de la preuve est invalide")
    return key, thumbprint


def _check_payload(
    claims: Mapping[str, Any],
    *,
    htu: str,
    method: str,
    ath: str,
) -> _Payload | DpopValidationError:
    """Contrôle ``jti``/``htm``/``htu``/``iat``/``exp``/``nbf``/``ath`` (§4.3)."""
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        return _reject("Claim 'jti' absente ou vide")
    if claims.get("htm") != method:
        return _reject(f"Claim 'htm' inattendue (attendu '{method}')")
    htu_claim = claims.get("htu")
    if not isinstance(htu_claim, str) or not htu_claim:
        return _reject("Claim 'htu' absente")
    if _strip_query_fragment(htu_claim) != htu:
        return _reject("Claim 'htu' ne correspond pas à l'endpoint appelé")

    now = datetime.now(timezone.utc)
    error = _check_timestamps(claims, now)
    if error is not None:
        return error
    error = _check_ath(claims, ath)
    if error is not None:
        return error

    nonce = claims.get("nonce", "")
    return _Payload(
        jti=jti,
        htm=str(claims.get("htm", "")),
        htu=_strip_query_fragment(htu_claim),
        nonce=nonce if isinstance(nonce, str) else "",
    )


def _check_timestamps(claims: Mapping[str, Any], now: datetime) -> DpopValidationError | None:
    """Valide ``iat`` (±5 min) puis les claims ``exp``/``nbf`` optionnels (RFC 9449 §11.1)."""
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or isinstance(iat, bool):
        return _reject("Claim 'iat' absente ou non numérique")
    iat_moment = datetime.fromtimestamp(iat, tz=timezone.utc)
    if iat_moment > now + timedelta(seconds=DPOP_IAT_SKEW_SECONDS):
        return _reject("Claim 'iat' située dans le futur")
    if iat_moment < now - timedelta(seconds=DPOP_IAT_SKEW_SECONDS):
        return _reject("Claim 'iat' trop ancienne (RFC 9449 §11.1)")
    return _check_optional_times(claims, now)


def _check_optional_times(claims: Mapping[str, Any], now: datetime) -> DpopValidationError | None:
    """Valide ``exp`` et ``nbf``, présents seulement s'ils le sont (RFC 9449 §4.3)."""
    exp = claims.get("exp")
    if exp is not None:
        if not isinstance(exp, (int, float)) or isinstance(exp, bool):
            return _reject("Claim 'exp' non numérique")
        if exp > (now + timedelta(seconds=DPOP_MAX_LIFETIME_SECONDS)).timestamp():
            return _reject("Claim 'exp' démesurée (probablement en millisecondes)")
        if datetime.fromtimestamp(exp, tz=timezone.utc) < now - timedelta(
            seconds=DPOP_IAT_SKEW_SECONDS
        ):
            return _reject("Preuve DPoP expirée (claim 'exp')")

    nbf = claims.get("nbf")
    if nbf is not None:
        if not isinstance(nbf, (int, float)) or isinstance(nbf, bool):
            return _reject("Claim 'nbf' non numérique")
        if datetime.fromtimestamp(nbf, tz=timezone.utc) > now + timedelta(
            seconds=DPOP_IAT_SKEW_SECONDS
        ):
            return _reject("Claim 'nbf' située dans le futur")
    return None


def _check_ath(claims: Mapping[str, Any], ath: str) -> DpopValidationError | None:
    """Contrôle le lien ``ath`` : requis au resource server, interdit ailleurs (§4.3)."""
    provided = claims.get("ath")
    if ath:
        if not isinstance(provided, str) or not provided:
            return _reject("Claim 'ath' absente (requis avec un access token)")
        if provided != ath:
            return _reject("Claim 'ath' ne correspond pas à l'access token présenté")
        return None
    if provided is not None:
        return _reject("La preuve du token endpoint ne doit pas porter de claim 'ath'")
    return None


def _check_signature(
    proof: str,
    key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey,
    alg: str,
) -> DpopValidationError | None:
    """Vérifie la signature JWS de la preuve avec sa propre clé publique (§4.3)."""
    try:
        pyjwt.PyJWS().decode(
            proof,
            key,
            algorithms=[alg],
            options={"verify_exp": False, "verify_nbf": False, "verify_aud": False},
        )
    except pyjwt.PyJWTError:
        return _reject("Signature de la preuve DPoP invalide")
    return None


def _strip_query_fragment(url: str) -> str:
    """Retire la query string et le fragment d'une URL (RFC 9449 §4.3)."""
    return url.partition("?")[0].partition("#")[0]


@dataclass(frozen=True, slots=True)
class _Payload:
    """Claims normalisés d'une preuve validée (``jti``/``htm``/``htu``/``nonce``)."""

    jti: str
    htm: str
    htu: str
    nonce: str = ""
