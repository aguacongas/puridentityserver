"""Cas d'utilisation : introspection de jeton (RFC 7662).

L'endpoint ``/introspect`` permet à un resource server authentifié comme
client confidentiel de connaître l'état d'un token. Tout token inconnu,
expiré ou mal signé renvoie ``active: false`` sans jamais lever d'erreur
serveur (RFC 7662 §2) ; l'appelant non autorisé est rejeté (RFC 7662
§2.1) pour éviter le balayage de tokens.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from puridentityserver.application.client_auth import authenticate_confidential_client
from puridentityserver.domain.revocation import token_hash
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.repositories.client_repository import ClientRepository
from puridentityserver.interfaces.repositories.revoked_token_repository import (
    RevokedTokenRepository,
)


@dataclass(frozen=True, slots=True)
class IntrospectConfig:
    """Paramètres de l'endpoint d'introspection."""

    issuer: str


@dataclass(frozen=True, slots=True)
class IntrospectRequest:
    """Requête : token à inspecter et authentification du client appelant."""

    token: str
    client_id: str
    client_secret: str = ""


@dataclass(frozen=True, slots=True)
class IntrospectResponse:
    """Réponse RFC 7662 : ``active`` et, si actif, les métadonnées du token."""

    active: bool
    claims: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IntrospectError:
    """Erreur d'introspection (format RFC 6749 §5.2 + statut HTTP attendu)."""

    error: str
    error_description: str = ""
    status_code: int = 401


class IntrospectUseCase:
    """Authentifie l'appelant puis valide le token via le ``TokenManager``.

    Le jeton est validé comme à l'endpoint UserInfo (signature JWKS,
    émetteur ``iss``, expiration ``exp``). Les métadonnées renvoyées
    suivent RFC 7662 §2.2 : ``scope``, ``client_id`` (l'audience du
    token), ``username`` (le ``sub`` faute de claim plus lisible),
    ``token_type``, ``iat`` et ``exp``.
    """

    def __init__(
        self,
        config: IntrospectConfig,
        client_repository: ClientRepository,
        token_manager: TokenManager,
        revoked_token_repository: RevokedTokenRepository,
    ) -> None:
        """Injection de la configuration, du registre clients et du validateur de jetons."""
        self._config = config
        self._clients = client_repository
        self._token_manager = token_manager
        self._blacklist = revoked_token_repository

    async def execute(self, request: IntrospectRequest) -> IntrospectResponse | IntrospectError:
        """Traite la requête : ``active`` (200) ou erreur d'authentification."""
        if not request.token:
            return IntrospectError(
                error="invalid_request",
                error_description="Paramètre 'token' manquant ou vide",
                status_code=400,
            )

        if not await authenticate_confidential_client(
            self._clients, request.client_id, request.client_secret
        ):
            return IntrospectError(
                error="invalid_client",
                error_description="Client d'introspection inconnu, désactivé ou secret invalide",
            )

        claims = await self._token_manager.validate_access_token(
            token=request.token, issuer=self._config.issuer
        )
        if claims is None:
            return IntrospectResponse(active=False)
        if await self._blacklist.is_revoked(token_hash(request.token)):
            return IntrospectResponse(active=False)
        return IntrospectResponse(active=True, claims=self._select_claims(claims))

    @staticmethod
    def _select_claims(claims: dict[str, object]) -> dict[str, object]:
        """Retient les membres RFC 7662 §2.2 présents dans le JWT inspecté."""
        selected: dict[str, object] = {}
        for name in ("iss", "sub", "aud", "exp", "iat", "scope"):
            if name in claims:
                selected[name] = claims[name]
        if isinstance(claims.get("aud"), str):
            selected["client_id"] = claims["aud"]
        if "preferred_username" in claims:
            selected["username"] = claims["preferred_username"]
        elif "sub" in claims:
            selected["username"] = claims["sub"]
        selected["token_type"] = "Bearer"  # ruff: ignore[hardcoded-password-string]  (RFC 6750 §5.1, pas un secret)
        return selected
