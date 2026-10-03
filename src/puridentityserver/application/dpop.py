"""Règles DPoP du token endpoint (RFC 9449 §5, §10).

``DpopGrantGuard`` centralise la décision d'émission liée ou non d'un
access token : il applique l'obligation du drapeau ``require_dpop``
(§5.2), fait valider la preuve par le port ``DpopProofValidator`` puis
contrôle le ``dpop_jkt`` attendu (§10). Le résultat distingue le lien
(``cnf.jkt`` + ``token_type=DPoP``) du simple porteur.
"""

from __future__ import annotations

from dataclasses import dataclass

from puridentityserver.domain.authorization import Client
from puridentityserver.interfaces.domain.dpop import (
    DpopProofValidator,
    DpopValidationError,
)


@dataclass(frozen=True, slots=True)
class DpopBinding:
    """Décision d'émission : ``jkt`` de la clé prouvée, lien effectif."""

    jkt: str = ""
    bound: bool = False


@dataclass(frozen=True, slots=True)
class DpopGuardError:
    """Rejet du token endpoint à rejouer en ``TokenError`` (RFC 6749 §5.2)."""

    error: str
    error_description: str = ""


DpopGuardResult = DpopBinding | DpopGuardError


class DpopGrantGuard:
    """Valide la preuve DPoP d'un appel au token endpoint.

    Sans preuve : ``require_dpop`` du client impose ``invalid_request``
    (RFC 9449 §5.2) et une demande liée (``dpop_jkt`` sur le code ou le
    refresh token) exige elle aussi la preuve. Avec preuve : validation
    intégrale du §4.3 via le port injecté, puis comparaison de l'empreinte
    au ``dpop_jkt`` attendu (mismatch → ``invalid_grant``, §10).
    """

    def __init__(self, validator: DpopProofValidator) -> None:
        """Injection du validateur de preuves (port domaine)."""
        self._validator = validator

    async def evaluate(
        self,
        *,
        client: Client,
        proof: str,
        htu: str,
        method: str = "POST",
        bound_jkt: str = "",
    ) -> DpopGuardResult:
        """Décide du lien du token émis pour ``client`` (voir la classe).

        ``bound_jkt`` porte l'empreinte exigée par le support en cours
        (code d'autorisation ou refresh token lié) ; ``htu`` est l'URL
        exacte du token endpoint appelé.
        """
        if not proof:
            return await self._missing_proof(client, bound_jkt=bound_jkt)
        validated = await self._validator.validate(proof=proof, htu=htu, method=method)
        if isinstance(validated, DpopValidationError):
            return DpopGuardError(validated.error, validated.error_description)
        if bound_jkt and validated.jkt != bound_jkt:
            return DpopGuardError(
                "invalid_grant",
                "La preuve DPoP ne correspond pas à la clé liée (dpop_jkt, RFC 9449 §10)",
            )
        return DpopBinding(jkt=validated.jkt, bound=True)

    @staticmethod
    async def _missing_proof(client: Client, *, bound_jkt: str) -> DpopGuardResult:
        """Traite l'absence de preuve : obligation du drapeau, puis liaison."""
        if client.require_dpop:
            return DpopGuardError(
                "invalid_request",
                "Ce client exige une preuve DPoP (RFC 9449 §5.2)",
            )
        if bound_jkt:
            return DpopGuardError(
                "invalid_request",
                "La demande est liée à une clé DPoP : preuve DPoP absente",
            )
        return DpopBinding()
