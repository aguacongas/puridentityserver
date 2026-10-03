"""Port de validation d'une preuve DPoP (RFC 9449 §4.3).

Le token endpoint, l'endpoint UserInfo et le endpoint PAR s'appuient
sur ce port pour vérifier une preuve ``DPoP`` : en-tête ``typ``/``alg``/
``jwk``, signature, ``htm``, ``htu``, ``iat``/``exp``/``nbf``, ``ath``
(resource server) et anti-replay du ``jti`` (§11).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from puridentityserver.domain.dpop import DPoPProof


@dataclass(frozen=True, slots=True)
class DpopValidationError:
    """Rejet d'une preuve DPoP (RFC 9449 §5 : ``invalid_dpop_proof``).

    Transporte le code d'erreur standard et la description destinée au
    corps de réponse ; l'appelant décide du statut HTTP et de l'éventuel
    en-tête ``WWW-Authenticate``.
    """

    error: str
    error_description: str = ""


class DpopProofValidator(Protocol):
    """Vérifie une preuve DPoP contre la requête HTTP qu'elle autorise."""

    async def validate(
        self,
        *,
        proof: str,
        htu: str,
        method: str,
        ath: str = "",
    ) -> DPoPProof | DpopValidationError:
        """Retourne la preuve validée (``jkt``/``jti``/``htm``/``htu``) ou le rejet.

        ``htu`` est l'URL exacte de l'endpoint appelé (sans query ni
        fragment), ``method`` la méthode HTTP attendue en ``htm``.
        ``ath`` (empreinte ``ath`` attendue) est requis lorsqu'un
        access token est présenté à un resource server ; à vide, le
        claim ``ath`` est au contraire interdit dans la preuve.
        """
        ...
