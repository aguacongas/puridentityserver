"""Cas d'usage minimal de l'issuance OpenID4VCI (slice 0/1, issue #172/#222).

La version livrée ici émet un credential verifiable SD-JWT à partir d'un
access token valide émis par l'OP. La preuve de possession (``proof_type``),
le consentement et les mécanismes c_nonce / Credential Offer sont traités
dans la tranche d'émission complète (#222).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from pydantic import BaseModel

from puridentityserver.domain.jwks import JWTAlgorithm, KeyPair
from puridentityserver.infrastructure.jwks import DefaultKeyManager, first_active_key
from puridentityserver.interfaces.domain.tokens import TokenManager


class _OID4VCIIssueRequest(BaseModel):
    format: str = "vc+sd-jwt"
    proof: dict[str, Any] | None = None


class OID4VCIIssuerUseCase:
    """Émet un credential verifiable SD-JWT pour l'OP.

    Le vérificateur d'access token doit provenir de la même instance de
    ``PyJWTTokenManager`` ; la clé de signature est la clé active principale.
    """

    def __init__(
        self,
        *,
        issuer: str,
        key_manager: DefaultKeyManager,
        algorithm: JWTAlgorithm,
        token_manager: TokenManager,
    ) -> None:
        """Initialise l'émetteur et mémorise les dépendances cryptographiques."""
        self._issuer = issuer.rstrip("/")
        self._key_manager = key_manager
        self._algorithm = algorithm
        self._token_manager = token_manager

    async def issue_credential(
        self,
        bearer_token: str,
        requested_format: str = "vc+sd-jwt",
    ) -> dict[str, Any] | None:
        """Retourne le JSON de réponse OID4VCI, ou ``None`` si non autorisé."""
        claims = await self._token_manager.validate_access_token(
            token=bearer_token, issuer=self._issuer
        )
        if claims is None:
            return None

        sub = str(claims.get("sub") or claims.get("client_id") or "")
        if not sub:
            return None

        key: KeyPair = await first_active_key(self._key_manager, self._algorithm)
        private_key = load_pem_private_key(key.private_key_pem.encode("ascii"), password=None)
        now = int(datetime.now(timezone.utc).timestamp())
        payload: dict[str, object] = {
            "iss": self._issuer,
            "sub": sub,
            "iat": now,
            "exp": now + 1800,
            "vct": "https://puridentityserver.example/credentials/example",
        }
        headers = {"typ": requested_format, "kid": key.kid, "alg": self._algorithm.value}
        credential = pyjwt.encode(
            payload, private_key, algorithm=self._algorithm.value, headers=headers
        )
        return {
            "credentials": [{"credential": credential}],
            "c_nonce": uuid.uuid4().hex,
            "c_nonce_expires_in": 300,
        }
