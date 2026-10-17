"""Enveloppe JARM signée via PyJWT - implémentation concrète de ``JarmEnvelopeSigner``.

Les claims ``iss`` / ``aud`` / ``exp`` / ``iat`` / ``jti`` encadrent les
paramètres de la réponse d'autorisation (JARM Final 1.0 §3) ; la clé est
celle de l'algorithme demandé, publiée au JWKS sous son ``kid`` (§4).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import cast
from uuid import uuid4

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from puridentityserver.domain.jwks import ASYMMETRIC_ALGORITHMS, JWTAlgorithm
from puridentityserver.infrastructure.jwks import first_active_key
from puridentityserver.interfaces.domain.jwks import KeyManager


class PyJarmEnvelopeSigner:
    """Signe l'enveloppe JARM avec la clé active de l'algorithme (``kid`` inclus)."""

    def __init__(self, key_manager: KeyManager, issuer: str, lifetime_seconds: int = 600) -> None:
        """Injection du gestionnaire de clés, de l'émetteur et de la durée de vie.

        ``lifetime_seconds`` (600 s par défaut) reste sous les 10 minutes
        recommandées par JARM Final 1.0 §4.2 et au-dessus des 10 secondes
        minimales opposées par la suite de certification
        (``ValidateJARMExpRecommendations``).
        """
        self._key_manager = key_manager
        self._issuer = issuer
        self._lifetime_seconds = lifetime_seconds

    async def sign_envelope(
        self, *, audience: str, algorithm: str, params: Mapping[str, str]
    ) -> str:
        """Enveloppe les paramètres dans un JWT signé JARM (JARM Final 1.0 §3).

        Raises:
            ValueError: l'algorithme n'est pas une famille asymétrique
                signable par l'OP (HS*, ``none``).
        """
        jwt_algorithm = JWTAlgorithm._value2member_map_.get(algorithm)
        if jwt_algorithm is None or jwt_algorithm not in ASYMMETRIC_ALGORITHMS:
            raise ValueError(f"Algorithme JARM non signable côté serveur : {algorithm}")
        key_pair = await first_active_key(self._key_manager, jwt_algorithm)
        private_key = load_pem_private_key(key_pair.private_key_pem.encode("ascii"), None)
        now = int(datetime.now(timezone.utc).timestamp())
        claims: dict[str, object] = {
            "iss": self._issuer,
            "aud": audience,
            "exp": now + self._lifetime_seconds,
            "iat": now,
            "jti": uuid4().hex,
            **dict(params),
        }
        return cast(
            str,
            pyjwt.encode(
                claims,
                private_key,
                algorithm=algorithm,
                headers={"kid": key_pair.kid},
            ),
        )
