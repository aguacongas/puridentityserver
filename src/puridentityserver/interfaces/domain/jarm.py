"""Port de signature de l'enveloppe JARM (JWT Secured Authorization Response Mode)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol


class JarmEnvelopeSigner(Protocol):
    """Signature JWS de l'enveloppe JARM (``response_mode=jwt``, JARM Final 1.0 §3)."""

    async def sign_envelope(
        self, *, audience: str, algorithm: str, params: Mapping[str, str]
    ) -> str:
        """Enveloppe les paramètres de réponse d'autorisation dans un JWT signé.

        Les claims portent ``iss`` (émetteur), ``aud`` (``client_id``),
        ``exp`` court, ``iat``, ``jti`` puis les paramètres eux-mêmes
        (``code``, ``error``, ``state``…), l'en-tête JWS étant marqué du
        ``kid`` de la clé employée.

        Args:
            audience: ``aud`` de l'enveloppe, le ``client_id`` destinataire.
            algorithm: algorithme JWS (``authorization_signed_response_alg``
                du client).
            params: paramètres de la réponse d'autorisation à envelopper.

        Returns:
            Le JWT compact JARM signé.
        """
        ...
