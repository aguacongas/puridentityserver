"""Cas d'utilisation de la présentation OpenID4VP (request + validation direct_post).

La vérification reste volontairement à un slice minimal : le vp_token doit
être un JWT signé par une clé publique embarquée (JWK dans l'en-tête JOSE),
porter l'audience de l'issuer et un nonce précédemment émis, et être non expiré.
La vérification complète du détenteur / de la présentation (chaîne de
certificats, DCQL, présentation intégrale) est une tranche ultérieure.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwks import DefaultKeyManager, first_active_key

#: Algorithms acceptes pour le vp_token auto-porte.
ALLOWED_VP_ALGORITHMS = frozenset({"RS256", "ES256"})

#: Message d'erreur générique de réception de présentation.
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
        """Valide un vp_token signé et son nonce.

        Renvoie ``{"status": "received"}`` en cas de succès, ou une chaîne
        d'erreur (`invalid_request`, `invalid_presentation`) pour la couche HTTP.
        """
        token = _first_token(vp_token)
        if token is None:
            return VP_RESPONSE_ERROR
        claims = _verify_vp_token(token, self._issuer)
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


def _verify_vp_token(token: str, audience: str) -> dict[str, Any] | None:
    """Vérifie la signature et l'audience d'un vp_token portant un JWK."""
    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.PyJWTError:
        return None
    algorithm_name = header.get("alg")
    jwk = header.get("jwk")
    if not isinstance(algorithm_name, str) or algorithm_name not in ALLOWED_VP_ALGORITHMS:
        return None
    if not isinstance(jwk, dict):
        return None
    try:
        algorithm = pyjwt.algorithms.get_default_algorithms().get(algorithm_name)
        if algorithm is None:
            return None
        public_key = algorithm.from_jwk(__import__("json").dumps(jwk))
        claims = pyjwt.decode(
            token,
            public_key,
            algorithms=[algorithm_name],
            audience=audience,
        )
    except (pyjwt.PyJWTError, ValueError, TypeError):
        return None
    return claims if isinstance(claims, dict) else None
