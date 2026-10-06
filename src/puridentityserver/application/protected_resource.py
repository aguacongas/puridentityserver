"""Cas d'utilisation : resource server intégré (FAPI-R-6.2.1, RFC 6750 §2, RFC 8707).

Ressource protégée de démonstration appelée par la suite de
certification avec l'access token émis par ce serveur : le jeton
présenté est validé (signature, ``iss``, expiration, denylist de
révocation RFC 6749 §5.2) avant de restituer un corps JSON minimal.

Le contrôle d'``aud`` n'est pas opposé : la suite appelle la ressource
sans resource indicator — le ``aud`` du jeton reste alors celui des
resources accordées au client (RFC 8707 §2, comportement RP-side).
"""

from __future__ import annotations

from dataclasses import dataclass

from puridentityserver.domain.revocation import token_hash
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.repositories.revoked_token_repository import (
    RevokedTokenRepository,
)


@dataclass(frozen=True, slots=True)
class ProtectedResourceConfig:
    """Paramètres du resource server intégré."""

    issuer: str


@dataclass(frozen=True, slots=True)
class ProtectedResourceRequest:
    """Requête de la ressource protégée : jeton Bearer présenté (RFC 6750 §2.1)."""

    access_token: str


@dataclass(frozen=True, slots=True)
class ProtectedResourceResponse:
    """Réponse de la ressource protégée quand le jeton est valide."""

    subject: str
    scope: str = ""


@dataclass(frozen=True, slots=True)
class ProtectedResourceError:
    """Erreur de la ressource protégée (RFC 6750 §3).

    Toute présentation de jeton invalide — absent, expiré, révoqué ou
    malformé — vaut ``invalid_token`` avec un challenge ``Bearer``.
    """

    error: str
    error_description: str = ""


class ProtectedResourceUseCase:
    """Valide l'access token Bearer présenté à la ressource protégée."""

    def __init__(
        self,
        config: ProtectedResourceConfig,
        token_manager: TokenManager,
        revoked_tokens: RevokedTokenRepository,
    ) -> None:
        """Injection de la configuration, du validateur de jetons et de la denylist."""
        self._config = config
        self._token_manager = token_manager
        self._revoked_tokens = revoked_tokens

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
        return ProtectedResourceResponse(
            subject=str(claims.get("sub", "")),
            scope=str(claims.get("scope", "")),
        )
