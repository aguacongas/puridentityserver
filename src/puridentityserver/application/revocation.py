"""Cas d'utilisation : révocation de jeton (RFC 7009).

``POST /revoke`` permet à un client autorisé (confidentiel, comme pour
l'introspection) d'invalider un access token avant son expiration
naturelle. Le jeton est placé (sous forme d'empreinte SHA-256) dans un
denylist vérifié ensuite par ``/introspect`` et ``/userinfo``.

Conformément à RFC 7009 §2.2, un token inconnu, déjà expiré ou invalide
n'est jamais traité comme une erreur : la réponse reste 200 sans corps
(la révocation ne doit pas révéler la validité d'un jeton).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from puridentityserver.application.client_auth import authenticate_confidential_client
from puridentityserver.domain.revocation import RevokedToken, token_hash
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.repositories.client_repository import ClientRepository
from puridentityserver.interfaces.repositories.revoked_token_repository import (
    RevokedTokenRepository,
)


@dataclass(frozen=True, slots=True)
class RevocationConfig:
    """Paramètres de l'endpoint de révocation."""

    issuer: str


@dataclass(frozen=True, slots=True)
class RevocationRequest:
    """Requête : token à révoquer et authentification du client appelant."""

    token: str
    client_id: str
    client_secret: str = ""


@dataclass(frozen=True, slots=True)
class RevocationSuccess:
    """Réponse de succès (RFC 7009 §2.2) : HTTP 200, corps vide."""

    purged: int = 0


@dataclass(frozen=True, slots=True)
class RevocationError:
    """Erreur de révocation (format RFC 6749 §5.2 + statut HTTP attendu)."""

    error: str
    error_description: str = ""
    status_code: int = 401


class RevocationUseCase:
    """Authentifie l'appelant puis place le jeton au denylist.

    Le token est d'abord validé pour connaître son ``exp`` (nécessaire à
    la purge du denylist) ; s'il est invalide ou déjà expiré, la
    révocation est un succès sans effet (RFC 7009 §2.2).
    """

    def __init__(
        self,
        config: RevocationConfig,
        client_repository: ClientRepository,
        token_manager: TokenManager,
        revoked_token_repository: RevokedTokenRepository,
    ) -> None:
        """Injection de la configuration, du registre clients, du validateur et du denylist."""
        self._config = config
        self._clients = client_repository
        self._token_manager = token_manager
        self._blacklist = revoked_token_repository

    async def execute(self, request: RevocationRequest) -> RevocationSuccess | RevocationError:
        """Traite la requête : succès silencieux (200) ou erreur."""
        if not request.token:
            return RevocationError(
                error="invalid_request",
                error_description="Paramètre 'token' manquant ou vide",
                status_code=400,
            )

        if not await authenticate_confidential_client(
            self._clients, request.client_id, request.client_secret
        ):
            return RevocationError(
                error="invalid_client",
                error_description="Client de révocation inconnu, désactivé ou secret invalide",
            )

        purged = await self._blacklist.purge_expired()
        claims = await self._token_manager.validate_access_token(
            token=request.token, issuer=self._config.issuer
        )
        if claims is None:
            return RevocationSuccess(purged=purged)

        expires_at = self._expiry(claims)
        if expires_at is None or expires_at <= datetime.now(timezone.utc):
            return RevocationSuccess(purged=purged)

        await self._blacklist.save(
            RevokedToken(token_hash=token_hash(request.token), expires_at=expires_at)
        )
        return RevocationSuccess(purged=purged)

    @staticmethod
    def _expiry(claims: dict[str, object]) -> datetime | None:
        """Convertit le claim ``exp`` du jeton en date UTC, ou ``None``."""
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)):
            return None
        return datetime.fromtimestamp(int(exp), tz=timezone.utc)
