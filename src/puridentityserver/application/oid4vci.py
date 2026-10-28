"""Cas d'usage minimal de l'issuance OpenID4VCI (slice 1, issue #172/#222)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from puridentityserver.domain.jwks import JWTAlgorithm, KeyPair
from puridentityserver.infrastructure.jwks import DefaultKeyManager, first_active_key
from puridentityserver.interfaces.domain.tokens import TokenManager


class OID4VCIIssuerUseCase:
    """Émet un credential verifiable SD-JWT pour l'OP.

    La preuve de possession (proof_type JWT) est vérifiée si fournie.
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
        proof_jwt: str | None = None,
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

        binding_jwk: dict[str, Any] | None = None
        if proof_jwt:
            binding_jwk = self._verify_proof(proof_jwt)
            if binding_jwk is None:
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
        if binding_jwk is not None:
            payload["cnf"] = {"jwk": binding_jwk}
        headers = {"typ": requested_format, "kid": key.kid, "alg": self._algorithm.value}
        credential = pyjwt.encode(
            payload, private_key, algorithm=self._algorithm.value, headers=headers
        )
        return {
            "credentials": [{"credential": credential}],
            "c_nonce": uuid.uuid4().hex,
            "c_nonce_expires_in": 300,
        }

    def _verify_proof(self, proof_jwt: str) -> dict[str, Any] | None:
        """Vérifie une preuve JWT OID4VCI (``proof_type=jwt``) et renvoie la JWK."""
        try:
            header = pyjwt.get_unverified_header(proof_jwt)
        except pyjwt.PyJWTError:
            return None
        alg = header.get("alg")
        jwk = header.get("jwk")
        if not isinstance(alg, str) or not isinstance(jwk, dict):
            return None
        if alg not in {"RS256", "ES256"}:
            return None
        algorithm = pyjwt.algorithms.get_default_algorithms().get(alg)
        if algorithm is None:
            return None
        try:
            public_key = algorithm.from_jwk(__import__("json").dumps(jwk))
            pyjwt.decode(
                proof_jwt,
                public_key,
                algorithms=[alg],
                audience=self._issuer,
                options={"verify_exp": True, "verify_nbf": True},
            )
        except (pyjwt.PyJWTError, ValueError, TypeError):
            return None
        return jwk
