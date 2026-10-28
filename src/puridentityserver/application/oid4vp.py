"""Cas d'usage minimal de la présentation OpenID4VP (slice 0, issue #172/#223).

Cette version crée une demande de présentation signée par l'OP (request object).
La réception/validation de la réponse (`/vp_response`) est traitée dans la
tranche suivante (#223).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.infrastructure.jwks import DefaultKeyManager, first_active_key


class OID4VPVerifierUseCase:
    """Crée une demande de présentation signée par l'OP."""

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

    async def create_presentation_request(
        self,
        presentation_definition: dict[str, Any] | None = None,
        response_mode: str = "direct_post",
    ) -> dict[str, Any]:
        """Signe et renvoie une demande de présentation (request object)."""
        key = await first_active_key(self._key_manager, self._algorithm)
        private_key = load_pem_private_key(key.private_key_pem.encode("ascii"), password=None)
        nonce = uuid.uuid4().hex
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
