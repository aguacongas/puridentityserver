"""Use case de Pushed Authorization Request (RFC 9126).

Le client pousse les paramètres d'autorisation au serveur via ``POST /par``
et reçoit un ``request_uri`` opaque à usage unique, qu'il transmet ensuite
à l'endpoint d'autorisation (/authorize?request_uri=...&client_id=...).

Les ditches de validation et de rejet sont réutilisées depuis
``application.authorize`` pour garantir une cohérence stricte avec le flow
standard, indépendamment de la couche HTTP.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from puridentityserver.application.authorize import (
    AuthorizeError,
    AuthorizeRequest,
    validate_authorization_request,
)
from puridentityserver.application.client_auth import CLIENT_UNKNOWN_ERROR, verify_client_secret
from puridentityserver.application.scope_registry import ScopeRegistry
from puridentityserver.domain.authorization import Client, ClientType, PushedAuthorization
from puridentityserver.interfaces.repositories.client_repository import ClientRepository
from puridentityserver.interfaces.repositories.pushed_authorization_repository import (
    PushedAuthorizationRepository,
)


@dataclass(frozen=True, slots=True)
class PushedAuthorizationConfig:
    """Configuration des requêtes poussées (RFC 9126 §2)."""

    ttl_seconds: int = 90


@dataclass(frozen=True, slots=True)
class PushResult:
    """Réponse réussie de ``POST /par``."""

    request_uri: str
    expires_in: int


@dataclass(frozen=True, slots=True)
class PushError:
    """Erreur de ``POST /par`` (RFC 9126 §2.3)."""

    error: str
    error_description: str = ""
    status_code: int = 400


class PushedAuthorizationUseCase:
    """Gère le cycle de vie des requêtes d'autorisation poussées.

    ``push()`` valide les paramètres (réutilisant le validateur standard),
    puis ``resolve()`` consomme le ``request_uri`` au moment du redirect
    vers ``/authorize``.
    """

    def __init__(
        self,
        par_config: PushedAuthorizationConfig,
        client_repository: ClientRepository,
        pushed_repository: PushedAuthorizationRepository,
        scope_registry: ScopeRegistry | None = None,
    ) -> None:
        """Prépare le use case avec ses dépendances de configuration et stockage."""
        self._config = par_config
        self._clients = client_repository
        self._pushed = pushed_repository
        self._scope_registry = scope_registry

    async def _authenticate_client(self, client_id: str, client_secret: str) -> Client | PushError:
        """Authentifie le client du push ; retourne ``PushError`` ``invalid_client`` sinon.

        * ``client_secret`` présent → client confidentiel attendu, sinon
          ``invalid_client`` (401).
        * ``client_secret`` absent → client public, ``client_id`` seul suffit.
        """
        client = await self._clients.find_by_id(client_id)
        if client is None or not client.is_active:
            return PushError(
                error="invalid_client",
                error_description=CLIENT_UNKNOWN_ERROR,
                status_code=401,
            )
        if not client_secret:
            return client
        if client.client_type is not ClientType.CONFIDENTIAL:
            return PushError(
                error="invalid_client",
                error_description="client_secret fourni mais le client n'est pas confidentiel",
                status_code=401,
            )
        if not verify_client_secret(client, client_secret):
            return PushError(
                error="invalid_client",
                error_description="client_secret invalide",
                status_code=401,
            )
        return client

    async def push(self, params: dict[str, str]) -> PushResult | PushError:
        """Authentifie le client et persiste la requête poussée.

        La méthode accepte les paramètres de la demande d'autorisation
        (``response_type``, ``redirect_uri``, ``scope``, etc.) ainsi que
        ``client_id`` et éventuellement ``client_secret``. Le paramètre
        ``request_uri``, s'il est fourni, est rejeté conformément à la
        RFC 9126 §2 (interdiction d'inclure ``request_uri`` dans le push).

        Paramètres invalides → propagation de l'erreur du validateur
        standard (``invalid_request``, ``invalid_scope``…).
        """
        client_id = params.get("client_id", "")
        client_secret = params.get("client_secret", "")
        request_uri = params.get("request_uri", "")

        if request_uri:
            return PushError(
                error="invalid_request",
                error_description="request_uri ne doit pas être inclus dans la requête "
                "de push (RFC 9126 §2)",
                status_code=400,
            )

        authenticated = await self._authenticate_client(client_id, client_secret)
        if isinstance(authenticated, PushError):
            return authenticated

        authorize_request = AuthorizeRequest(
            response_type=params.get("response_type", ""),
            client_id=client_id,
            redirect_uri=params.get("redirect_uri", ""),
            scope=params.get("scope", ""),
            state=params.get("state", ""),
            nonce=params.get("nonce", ""),
            code_challenge=params.get("code_challenge", ""),
            code_challenge_method=params.get("code_challenge_method", "S256"),
            response_mode=params.get("response_mode", "query"),
        )

        validated = await validate_authorization_request(
            authorize_request, self._clients, self._scope_registry
        )
        if isinstance(validated, AuthorizeError):
            return PushError(
                error=validated.error,
                error_description=validated.error_description,
                status_code=401 if validated.error == "invalid_client" else 400,
            )

        reference = secrets.token_urlsafe(32)
        request_uri = f"urn:ietf:params:oauth:request_uri:{reference}"
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self._config.ttl_seconds)

        pushed = PushedAuthorization(
            request_uri=request_uri,
            client_id=client_id,
            params={k: v for k, v in params.items() if k not in {"client_secret"}},
            expires_at=expires_at,
        )
        await self._pushed.save(pushed)

        return PushResult(
            request_uri=request_uri,
            expires_in=self._config.ttl_seconds,
        )

    async def resolve(self, request_uri: str, client_id: str) -> AuthorizeRequest | PushError:
        """Résout le ``request_uri`` pour ``/authorize`` (consommation unique).

        Retourne la requête d'autorisation reconstruite, ou ``PushError``
        (``invalid_request``) en cas de référence inconnue, expirée, déjà
        consommée ou associée à un autre ``client_id``. Le ``request_uri``
        consommé (ou dont l'usage est refusé) est détruit (RFC 9126 §4).
        """
        pushed = await self._pushed.find_by_request_uri(request_uri)
        if pushed is None:
            return PushError(
                error="invalid_request",
                error_description="request_uri inconnu ou expiré",
                status_code=400,
            )

        now = datetime.now(timezone.utc)
        if pushed.expires_at <= now:
            await self._pushed.delete(request_uri)
            return PushError(
                error="invalid_request",
                error_description="request_uri expiré",
                status_code=400,
            )

        if pushed.is_consumed:
            await self._pushed.delete(request_uri)
            return PushError(
                error="invalid_request",
                error_description="request_uri déjà utilisé",
                status_code=400,
            )

        if pushed.client_id != client_id:
            return PushError(
                error="invalid_request",
                error_description="client_id ne correspond pas à la requête poussée",
                status_code=400,
            )

        await self._pushed.consume(request_uri)
        await self._pushed.delete(request_uri)

        return AuthorizeRequest(
            response_type=pushed.params.get("response_type", ""),
            client_id=pushed.params.get("client_id", client_id),
            redirect_uri=pushed.params.get("redirect_uri", ""),
            scope=pushed.params.get("scope", ""),
            state=pushed.params.get("state", ""),
            nonce=pushed.params.get("nonce", ""),
            code_challenge=pushed.params.get("code_challenge", ""),
            code_challenge_method=pushed.params.get("code_challenge_method", "S256"),
            response_mode=pushed.params.get("response_mode", "query"),
        )
