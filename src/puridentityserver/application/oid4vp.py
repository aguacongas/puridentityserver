"""Cas d'utilisation minimal de la présentation OpenID4VP (slice 0, issue #172/#223 et suivantes).

Cette version crée une demande de présentation signée par l'OP (request object).
La réception de la réponse (`/vp_response`) valide qu'elle porte un `vp_token`
(éventuellement un tableau pour plusieurs présentations) et qu'elle correspond
à une demande émise par l'OP (nonce mémorisé). La vérification cryptographique
fine de la présentation (signature du détenteur, chaîne de certificats, etc.)
est un raffinement ultérieur (#223).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwks import DefaultKeyManager, first_active_key

#: Codes d'erreur de la réception de présentation.
VP_RESPONSE_ERROR = "invalid_request"


class OID4VPVerifierUseCase:
    """Créé une demande de présentation signée par l'OP et reçoit la réponse."""

    def __init__(
        self,
        *,
        issuer: str,
        key_manager: DefaultKeyManager,
        algorithm: JWTAlgorithm,
    ) -> None:
        """Initialise l'émetteur de demandes de présentation."""
        self._issuer = issuer.rstrip("/")
        self._key_manager = key_manager
        self._algorithm = algorithm
        self._nonces: set[str] = set()

    async def create_presentation_request(
        self,
        presentation_definition: dict[str, Any] | None = None,
        response_mode: str = "direct_post",
    ) -> dict[str, Any]:
        """Signe et renvoie une demande de présentation (request object)."""
        key = await first_active_key(self._key_manager, self._algorithm)
        private_key = load_pem_private_key(key.private_key_pem.encode("ascii"), password=None)
        nonce = uuid.uuid4().hex
        self._nonces.add(nonce)
        now = int(datetime.now(timezone.utc).timestamp())
        payload: dict[str, object] = {
            "iss": self._issuer,
            "aud": "wallet",
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            "response_type": "vp_token",
            "response_mode": response_mode,
            "client_id": self._issuer,
        }
        if presentation_definition is not None:
            payload["presentation_definition"] = presentation_definition
        headers = {"typ": "oauth-authz-req+jwt", "kid": key.kid, "alg": self._algorithm.value}
        request = pyjwt.encode(
            payload, private_key, algorithm=self._algorithm.value, headers=headers
        )
        return {
            "request": request,
            "nonce": nonce,
            "response_mode": response_mode,
        }

    def validate_presentation_response(
        self,
        vp_token: str | list[str] | None = None,
    ) -> dict[str, Any] | str:
        """Valide la présence d'un vp_token et le nonce mémorisé.

        Renvoie le dictionnaire de succès (status received) ou une chaîne
        d'erreur (`invalid_request`, `invalid_presentation`) à rendre par la
        couche HTTP. La vérification cryptographique complète reste une
        tranche ultérieure.
        """
        token = _first_token(vp_token)
        if token is None:
            return VP_RESPONSE_ERROR
        claims = _decode_vp_token(token)
        if claims is None:
            return "invalid_presentation"
        nonce = claims.get("nonce") if isinstance(claims, dict) else None
        if not isinstance(nonce, str) or nonce not in self._nonces:
            return "invalid_presentation"
        self._nonces.discard(nonce)
        return {"status": "received"}


def _first_token(vp_token: str | list[str] | None) -> str | None:
    """Extrait le premier vp_token d'une valeur unique ou d'une liste."""
    token = vp_token[0] if isinstance(vp_token, list) and vp_token else vp_token
    return token if isinstance(token, str) and token else None


def _decode_vp_token(token: str) -> dict[str, Any] | None:
    """Decode un vp_token sans verification (slice minimal)."""
    try:
        claims = pyjwt.decode(  # NOSONAR
            token,
            options={"verify_signature": False},  # NOSONAR
        )
    except pyjwt.PyJWTError:
        return None
    return claims if isinstance(claims, dict) else None
