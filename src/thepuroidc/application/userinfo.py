"""Cas d'utilisation : endpoint UserInfo (OIDC Core 1.0 §5.3, RFC 6750 §2).

Valide l'access token Bearer, récupère les claims de l'utilisateur via le
``ClaimsProvider`` injecté et filtre ces claims selon les scopes accordés
au jeton (OIDC Core 1.0 §5.4).
"""

from __future__ import annotations

from dataclasses import dataclass

from thepuroidc.domain.authorization import Scope
from thepuroidc.interfaces.domain.tokens import TokenManager
from thepuroidc.interfaces.domain.userinfo import ClaimsProvider


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
    ) -> None:
        """Injection de la configuration, du validateur de jetons et du fournisseur de claims."""
        self._config = config
        self._token_manager = token_manager
        self._claims_provider = claims_provider

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

        subject = claims.get("sub")
        if subject is None:
            return UserInfoError(error="invalid_token", error_description="Claim 'sub' manquante")

        granted_scopes = Scope.from_space_separated(str(claims.get("scope", "")))
        user_claims = self._claims_provider.get_claims(str(subject))

        allowed = set(_CLAIMS_BY_SCOPE[Scope.OPENID])
        for scope in granted_scopes:
            allowed |= _CLAIMS_BY_SCOPE.get(scope, frozenset())

        return UserInfoResponse(
            claims={
                "sub": str(subject),
                **{name: value for name, value in user_claims.claims.items() if name in allowed},
            }
        )


_CLAIMS_BY_SCOPE: dict[Scope, frozenset[str]] = {
    Scope.OPENID: frozenset({"sub"}),
    Scope.PROFILE: frozenset(
        {
            "name",
            "family_name",
            "given_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
        }
    ),
    Scope.EMAIL: frozenset({"email", "email_verified"}),
    Scope.ADDRESS: frozenset({"address"}),
    Scope.PHONE: frozenset({"phone_number", "phone_number_verified"}),
}
