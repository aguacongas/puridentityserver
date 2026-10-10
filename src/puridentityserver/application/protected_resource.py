"""Cas d'utilisation : resource server intégré (FAPI-R-6.2.1, RFC 6750 §2, RFC 8707).

Ressource protégée de démonstration appelée par la suite de
certification avec l'access token émis par ce serveur : le jeton
présenté est validé (signature, ``iss``, expiration, denylist de
révocation RFC 6749 §5.2) avant de restituer un corps JSON minimal.

Le contrôle d'``aud`` n'est pas opposé : la suite appelle la ressource
sans resource indicator — le ``aud`` du jeton reste alors celui des
resources accordées au client (RFC 8707 §2, comportement RP-side).

Un access token lié à un certificat client mTLS (RFC 8705 §3.3, claim
``cnf.x5t#S256``) n'est accepté que présenté avec ce certificat, lu
depuis le contexte TLS ou les en-têtes du proxy de terminaison. De
même, un access token lié à une clé DPoP (RFC 9449 §5.1, claim
``cnf.jkt``, ``token_type=DPoP``) n'est accepté qu'avec le scheme
``DPoP`` et une preuve correspondante liée au jeton par ``ath`` — le
scheme ``Bearer`` est rejeté (RFC 9449 §7.1).
"""

from __future__ import annotations

from dataclasses import dataclass

from puridentityserver.application.tls_binding import certificate_binding_error
from puridentityserver.domain.authorization import ClientCertificate
from puridentityserver.domain.dpop import access_token_hash
from puridentityserver.domain.revocation import token_hash
from puridentityserver.interfaces.domain.dpop import DpopProofValidator, DpopValidationError
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.repositories.revoked_token_repository import (
    RevokedTokenRepository,
)

#: Challenge ``WWW-Authenticate`` d'une liaison DPoP exigée mais violée (§7.2).
_DPOP_CHALLENGE_INVALID = 'DPoP error="invalid_token"'


@dataclass(frozen=True, slots=True)
class ProtectedResourceConfig:
    """Paramètres du resource server intégré."""

    issuer: str


@dataclass(frozen=True, slots=True)
class ProtectedResourceRequest:
    """Requête de la ressource protégée : jeton présenté (RFC 6750 §2.1).

    ``tls_certificate`` porte le certificat client mTLS présenté, lu par
    le routeur depuis le contexte TLS ou les en-têtes du proxy
    (RFC 8705 §3.3). ``auth_scheme`` reprend le scheme employé
    (``bearer``/``dpop``, insensible à la casse) ; ``dpop_proof``, ``htu``
    et ``htm`` portent la preuve RFC 9449 opposée au jeton lié.
    """

    access_token: str
    tls_certificate: ClientCertificate | None = None
    auth_scheme: str = "bearer"
    dpop_proof: str = ""
    htu: str = ""
    htm: str = "GET"


@dataclass(frozen=True, slots=True)
class ProtectedResourceResponse:
    """Réponse de la ressource protégée quand le jeton est valide."""

    subject: str
    scope: str = ""


@dataclass(frozen=True, slots=True)
class ProtectedResourceError:
    """Erreur de la ressource protégée (RFC 6750 §3).

    Toute présentation de jeton invalide — absent, expiré, révoqué ou
    malformé — vaut ``invalid_token`` avec un challenge ``Bearer`` par
    défaut ; ``challenge`` porte un challenge explicite (scheme ``DPoP``
    pour une liaison RFC 9449 violée, RFC 6750 §3).
    """

    error: str
    error_description: str = ""
    challenge: str = ""


class ProtectedResourceUseCase:
    """Valide l'access token présenté (scheme ``Bearer`` ou ``DPoP``) à la ressource."""

    def __init__(
        self,
        config: ProtectedResourceConfig,
        token_manager: TokenManager,
        revoked_tokens: RevokedTokenRepository,
        *,
        dpop: DpopProofValidator | None = None,
    ) -> None:
        """Injection de la configuration, du validateur de jetons et de la denylist.

        ``dpop`` (RFC 9449 §7.1) vérifie la preuve présentée pour un
        jeton lié ; sans injection, un jeton lié est refusé plutôt
        qu'accepté sans vérification.
        """
        self._config = config
        self._token_manager = token_manager
        self._revoked_tokens = revoked_tokens
        self._dpop = dpop

    async def execute(
        self, request: ProtectedResourceRequest
    ) -> ProtectedResourceResponse | ProtectedResourceError:
        """Valide le jeton présenté et retourne la réponse protégée ou une erreur."""
        claims = await self._token_manager.validate_access_token(
            token=request.access_token, issuer=self._config.issuer
        )
        if claims is None:
            return ProtectedResourceError(
                error="invalid_token",
                error_description="Access token invalide, expiré ou de l'émetteur inattendu",
            )
        if await self._revoked_tokens.is_revoked(token_hash(request.access_token)):
            return ProtectedResourceError(
                error="invalid_token", error_description="Access token révoqué"
            )
        certificate_error = certificate_binding_error(claims, request.tls_certificate)
        if certificate_error:
            return ProtectedResourceError(
                error="invalid_token", error_description=certificate_error
            )
        binding_error = await self._validate_dpop_binding(request, claims)
        if binding_error is not None:
            return binding_error
        return ProtectedResourceResponse(
            subject=str(claims.get("sub", "")),
            scope=str(claims.get("scope", "")),
        )

    async def _validate_dpop_binding(
        self, request: ProtectedResourceRequest, claims: dict[str, object]
    ) -> ProtectedResourceError | None:
        """Contrôle le scheme employé pour un access token lié (RFC 9449 §7.1).

        Un jeton lié (``cnf.jkt``) exige le scheme ``DPoP`` et une preuve
        dont l'empreinte correspond au lien, liée au jeton présenté par
        ``ath`` — le scheme ``Bearer`` est rejeté (§7.1). Un jeton non lié
        reste un jeton porteur : son usage n'est pas restreint. ``None`` :
        la requête peut continuer.
        """
        bound_jkt = _bound_jkt(claims)
        if not bound_jkt:
            return None
        if request.auth_scheme != "dpop":
            return ProtectedResourceError(
                error="invalid_token",
                error_description="Jeton lié à une clé DPoP : scheme 'DPoP' exigé (RFC 9449 §7.1)",
                challenge=_DPOP_CHALLENGE_INVALID,
            )
        if self._dpop is None:
            return ProtectedResourceError(
                error="invalid_token",
                error_description="Validation DPoP indisponible : jeton lié refusé",
                challenge=_DPOP_CHALLENGE_INVALID,
            )
        if not request.dpop_proof:
            return ProtectedResourceError(
                error="invalid_token",
                error_description="Preuve DPoP requise pour ce jeton (RFC 9449 §7.1)",
                challenge=_DPOP_CHALLENGE_INVALID,
            )
        proof = await self._dpop.validate(
            proof=request.dpop_proof,
            htu=request.htu,
            method=request.htm,
            ath=access_token_hash(request.access_token),
        )
        if isinstance(proof, DpopValidationError):
            return ProtectedResourceError(
                error="invalid_dpop_proof",
                error_description=proof.error_description,
                challenge='DPoP error="invalid_dpop_proof"',
            )
        if proof.jkt != bound_jkt:
            return ProtectedResourceError(
                error="invalid_dpop_proof",
                error_description="Preuve DPoP sans la clé liée au jeton (RFC 9449 §7.1)",
                challenge='DPoP error="invalid_dpop_proof"',
            )
        return None


def _bound_jkt(claims: dict[str, object]) -> str:
    """Empreinte liant le jeton à une clé DPoP (claim ``cnf``, RFC 9449 §5.1).

    Retourne la chaîne vide quand le jeton n'est pas lié (claim absente
    ou forme inattendue : un payload corrompu ne peut être un lien valide).
    """
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict):
        return ""
    jkt = cnf.get("jkt")
    return jkt if isinstance(jkt, str) else ""
