"""Cas d'utilisation : endpoint UserInfo (OIDC Core 1.0 §5.3, RFC 6750 §2).

Valide l'access token Bearer, récupère les claims de l'utilisateur via le
``ClaimsProvider`` injecté et filtre ces claims selon les scopes accordés
au jeton (OIDC Core 1.0 §5.4) élargis des claims du member ``userinfo``
du paramètre ``claims`` porté par l'access_token (OIDC Core 1.0 §5.5).

Un access token lié à une clé DPoP (RFC 9449 §5.1, claim ``cnf.jkt``)
n'est accepté que via le scheme ``DPoP`` avec une preuve dont l'empreinte
correspond, liée au jeton par ``ath`` (§7.2) — le scheme ``Bearer`` est
alors rejeté avec un challenge ``DPoP``.
"""

from __future__ import annotations

from dataclasses import dataclass

from puridentityserver.application.claims_request import (
    allowed_scope_claims,
    requested_userinfo_claims,
)
from puridentityserver.domain.dpop import access_token_hash
from puridentityserver.domain.revocation import token_hash
from puridentityserver.interfaces.domain.dpop import DpopProofValidator, DpopValidationError
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.domain.userinfo import ClaimsProvider
from puridentityserver.interfaces.repositories.readers import IdentityResourceReader
from puridentityserver.interfaces.repositories.revoked_token_repository import (
    RevokedTokenRepository,
)


@dataclass(frozen=True, slots=True)
class UserInfoConfig:
    """Paramètres de l'endpoint UserInfo."""

    issuer: str
    userinfo_endpoint: str = ""


@dataclass(frozen=True, slots=True)
class UserInfoRequest:
    """Requête UserInfo : jeton présenté via ``Authorization`` (ou corps form).

    ``auth_scheme`` reprend le scheme employé (``bearer``/``dpop``) ;
    ``dpop_proof``, ``htu`` et ``htm`` portent la preuve RFC 9449 et le
    contexte HTTP qu'elle doit autoriser (§7.1).
    """

    access_token: str
    auth_scheme: str = "bearer"
    dpop_proof: str = ""
    htu: str = ""
    htm: str = "GET"


@dataclass(frozen=True, slots=True)
class UserInfoResponse:
    """Claims utilisateur renvoyés au client, filtrés par scopes accordés."""

    claims: dict[str, object]


@dataclass(frozen=True, slots=True)
class UserInfoError:
    """Erreur UserInfo (RFC 6750 §3).

    ``challenge`` porte la valeur complète de l'en-tête
    ``WWW-Authenticate`` quand elle s'écarte du ``Bearer`` par défaut
    (challenge ``DPoP`` pour un jeton lié, RFC 9449 §7.2).
    """

    error: str
    error_description: str = ""
    challenge: str = ""


class UserInfoUseCase:
    """Valide le token puis résout et filtre les claims de l'utilisateur.

    Le claim ``sub`` est toujours renvoyé ; les autres claims ne sont
    exposés que si le scope correspondant a été accordé au jeton
    (``profile`` → nom/prénom…, ``email`` → email, ``phone`` →
    téléphone, ``address`` → adresse).
    """

    def __init__(
        self,
        config: UserInfoConfig,
        token_manager: TokenManager,
        claims_provider: ClaimsProvider,
        revoked_token_repository: RevokedTokenRepository,
        identity_resources: IdentityResourceReader | None = None,
        *,
        dpop: DpopProofValidator | None = None,
    ) -> None:
        """Injection config, validateur, fournisseur, denylist, registre et DPoP.

        ``dpop`` (RFC 9449) vérifie les preuves présentées au userinfo ;
        sans injection, un access token lié (``cnf.jkt``) est toujours
        rejeté — aucun lien ne pouvant être prouvé sans validateur.
        """
        self._config = config
        self._token_manager = token_manager
        self._claims_provider = claims_provider
        self._blacklist = revoked_token_repository
        self._identity_resources = identity_resources
        self._dpop = dpop

    async def execute(self, request: UserInfoRequest) -> UserInfoResponse | UserInfoError:
        """Traite la requête et retourne les claims filtrés ou une erreur."""
        claims = await self._token_manager.validate_access_token(
            token=request.access_token, issuer=self._config.issuer
        )
        if claims is None:
            return UserInfoError(
                error="invalid_token",
                error_description="Access token invalide, expiré ou de l'émetteur inattendu",
            )

        if await self._blacklist.is_revoked(token_hash(request.access_token)):
            return UserInfoError(error="invalid_token", error_description="Access token révoqué")

        binding_error = await self._validate_dpop_binding(request, claims)
        if binding_error is not None:
            return binding_error

        subject = claims.get("sub")
        if subject is None:
            return UserInfoError(error="invalid_token", error_description="Claim 'sub' manquante")

        allowed = await self._allowed_claims(str(claims.get("scope", "")))
        allowed |= requested_userinfo_claims(claims.get("claims"))
        user_claims = await self._claims_provider.get_claims(str(subject))

        return UserInfoResponse(
            claims={
                "sub": str(subject),
                **{name: value for name, value in user_claims.claims.items() if name in allowed},
            }
        )

    async def _validate_dpop_binding(
        self, request: UserInfoRequest, claims: dict[str, object]
    ) -> UserInfoError | None:
        """Contrôle le scheme employé pour un access token lié (RFC 9449 §7.1-7.2).

        Un jeton lié (``cnf.jkt``) exige le scheme ``DPoP`` et une preuve
        dont l'empreinte correspond au lien, liée au jeton présenté par
        ``ath`` — le scheme ``Bearer`` est rejeté (§7.2). Un jeton non lié
        reste un jeton porteur : son usage n'est pas restreint. ``None`` :
        la requête peut continuer.
        """
        bound_jkt = _bound_jkt(claims)
        if not bound_jkt:
            return None
        if request.auth_scheme != "dpop":
            return UserInfoError(
                error="invalid_token",
                error_description="Jeton lié à une clé DPoP : scheme 'DPoP' exigé (RFC 9449 §7.2)",
                challenge='DPoP error="invalid_token"',
            )
        if self._dpop is None:
            return UserInfoError(
                error="invalid_token",
                error_description="Validation DPoP indisponible : jeton lié refusé",
                challenge='DPoP error="invalid_token"',
            )
        if not request.dpop_proof:
            return UserInfoError(
                error="invalid_token",
                error_description="Preuve DPoP requise pour ce jeton (RFC 9449 §7.1)",
                challenge='DPoP error="invalid_token"',
            )
        proof = await self._dpop.validate(
            proof=request.dpop_proof,
            htu=request.htu,
            method=request.htm,
            ath=access_token_hash(request.access_token),
        )
        if isinstance(proof, DpopValidationError):
            return UserInfoError(
                error="invalid_dpop_proof",
                error_description=proof.error_description,
                challenge='DPoP error="invalid_dpop_proof"',
            )
        if proof.jkt != bound_jkt:
            return UserInfoError(
                error="invalid_dpop_proof",
                error_description="Preuve DPoP sans la clé liée au jeton (RFC 9449 §7.2)",
                challenge='DPoP error="invalid_dpop_proof"',
            )
        return None

    async def _allowed_claims(self, scope: str) -> set[str]:
        """Claims autorisés par le scope accordé, dérivés des IdentityResources.

        Délégué à ``allowed_scope_claims`` (source partagée avec l'id_token
        de ``/authorize``) : chaque scope nommé dans ``scope`` (séparé par
        des espaces, RFC 6749 §3.3) est mis en correspondance avec une
        resource du registre — ses claims deviennent accessibles. ``sub``
        est toujours autorisé (claim réservé d'OpenID Connect). Les claims
        du member ``userinfo`` du paramètre ``claims`` (OIDC Core 1.0 §5.5),
        lus dans le payload de l'access_token, élargissent ensuite cet
        ensemble.
        """
        return await allowed_scope_claims(scope, self._identity_resources)


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
