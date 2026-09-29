"""Cas d'utilisation : endpoint UserInfo (OIDC Core 1.0 §5.3, RFC 6750 §2).

Valide l'access token Bearer, récupère les claims de l'utilisateur via le
``ClaimsProvider`` injecté et filtre ces claims selon les scopes accordés
au jeton (OIDC Core 1.0 §5.4) élargis des claims du member ``userinfo``
du paramètre ``claims`` porté par l'access_token (OIDC Core 1.0 §5.5).
"""

from __future__ import annotations

from dataclasses import dataclass

from puridentityserver.application.claims_request import (
    allowed_scope_claims,
    requested_userinfo_claims,
)
from puridentityserver.domain.revocation import token_hash
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


@dataclass(frozen=True, slots=True)
class UserInfoRequest:
    """Requête UserInfo : token Bearer reçu dans l'en-tête Authorization."""

    access_token: str


@dataclass(frozen=True, slots=True)
class UserInfoResponse:
    """Claims utilisateur renvoyés au client, filtrés par scopes accordés."""

    claims: dict[str, object]


@dataclass(frozen=True, slots=True)
class UserInfoError:
    """Erreur UserInfo (RFC 6750 §3)."""

    error: str
    error_description: str = ""


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
    ) -> None:
        """Injection config, validateur, fournisseur, denylist et registre de resources."""
        self._config = config
        self._token_manager = token_manager
        self._claims_provider = claims_provider
        self._blacklist = revoked_token_repository
        self._identity_resources = identity_resources

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
