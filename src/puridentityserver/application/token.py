"""Cas d'utilisation : endpoint de jetons (RFC 6749, RFC 7636, RFC 8628).

Traite quatre grant types :

- ``authorization_code`` (RFC 6749 §4.1.3 + RFC 7636) : échange le code
  d'autorisation reçu sur ``/authorize`` ; le client confidentiel doit
  présenter son ``client_secret``, le client public son ``code_verifier``
  PKCE.
- ``refresh_token`` (RFC 6749 §6) : renouvelle l'access token à partir
  d'un refresh token opaque. Le jeton est **rotatif** : chaque usage
  consomme l'ancien (rejeté s'il est réutilisé) et en émet un nouveau.
  Le scope demandé doit rester un sous-ensemble de celui accordé.
- ``client_credentials`` (RFC 6749 §4.4) : le client lui-même devient le
  ``subject`` du jeton (pas d'utilisateur final). Réservé aux clients
  confidentiels ; aucun ``id_token`` ni ``refresh_token`` n'est émis.
- ``urn:ietf:params:oauth:grant-type:device_code`` (RFC 8628 §3.4) :
  poll du client après autorisation de l'appareil. Tant que l'utilisateur
  n'a pas validé, la réponse est ``authorization_pending`` (ou
  ``slow_down`` si le client pole trop vite) ; une fois approuvée, la
  session est consommée et l'access token (id/refresh selon les scopes)
  est émis pour le ``subject`` de l'utilisateur.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe

from puridentityserver.application.client_auth import (
    CLIENT_UNKNOWN_ERROR,
    verify_client_secret,
)
from puridentityserver.application.scope_registry import ScopeRegistry
from puridentityserver.domain.authorization import (
    AuthorizationCode,
    Client,
    ClientType,
    DeviceAuthorizationStatus,
    RefreshToken,
    Scope,
    resolve_lifetime_seconds,
)
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.domain.revocation import token_hash
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.repositories.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from puridentityserver.interfaces.repositories.device_authorization_repository import (
    DeviceAuthorizationRepository,
)
from puridentityserver.interfaces.repositories.readers import ClientReader
from puridentityserver.interfaces.repositories.refresh_token_repository import (
    RefreshTokenRepository,
)


@dataclass(frozen=True, slots=True)
class TokenConfig:
    """Paramètres de l'endpoint de jetons."""

    issuer: str
    signing_algorithm: JWTAlgorithm = JWTAlgorithm.RS256
    access_token_ttl_seconds: int = 3600
    refresh_token_ttl_seconds: int = 2592000


@dataclass(slots=True)
class TokenRequest:
    """Paramètres fournis par le client à l'endpoint ``/token``."""

    grant_type: str
    code: str = ""
    redirect_uri: str = ""
    client_id: str = ""
    client_secret: str = ""
    code_verifier: str = ""
    refresh_token: str = ""
    device_code: str = ""
    scope: str = ""


@dataclass(frozen=True, slots=True)
class TokenResponse:
    """Réponse OAuth 2.0 du token endpoint (RFC 6749 §5.1)."""

    access_token: str
    id_token: str
    token_type: str = "Bearer"  # ruff: ignore[hardcoded-password-string]  (valeur standard OAuth, pas un secret)
    expires_in: int = 3600
    scope: str = ""
    refresh_token: str = ""


@dataclass(frozen=True, slots=True)
class TokenError:
    """Erreur du token endpoint (RFC 6749 §5.2)."""

    error: str
    error_description: str = ""


class TokenUseCase:
    """Valide l'échange (code ou refresh) et émet les jetons signés.

    L'authentification du client se fait via ``client_secret`` pour un
    client confidentiel, ou via ``code_verifier`` PKCE pour un client
    public. Le port ``TokenManager`` signe ``id_token`` et
    ``access_token`` avec la première clé active de l'algorithme.
    """

    def __init__(
        self,
        config: TokenConfig,
        client_repository: ClientReader,
        code_repository: AuthorizationCodeRepository,
        token_manager: TokenManager,
        refresh_tokens: RefreshTokenRepository,
        device_codes: DeviceAuthorizationRepository | None = None,
        scope_registry: ScopeRegistry | None = None,
    ) -> None:
        """Injection de la configuration, des repositories et de l'émetteur de jetons."""
        self._config = config
        self._clients = client_repository
        self._codes = code_repository
        self._token_manager = token_manager
        self._refresh_tokens = refresh_tokens
        self._device_codes = device_codes
        self._scope_registry = scope_registry

    async def execute(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Traite le grant type demandé et retourne les jetons ou une erreur."""
        if request.grant_type == "authorization_code":
            return await self._exchange_code(request)
        if request.grant_type == "refresh_token":
            return await self._refresh(request)
        if request.grant_type == "client_credentials":
            return await self._client_credentials(request)
        if request.grant_type == "urn:ietf:params:oauth:grant-type:device_code":
            return await self._device_code(request)
        return self._error("unsupported_grant_type")

    async def _exchange_code(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Échange un code d'autorisation à usage unique contre des jetons."""
        auth_code = await self._codes.find_by_code(request.code)
        if auth_code is None or auth_code.is_consumed:
            return self._error("invalid_grant", "Code d'autorisation invalide ou déjà consommé")

        now = datetime.now(timezone.utc)
        if auth_code.expires_at < now:
            return self._error("invalid_grant", "Code d'autorisation expiré")

        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error("invalid_client", CLIENT_UNKNOWN_ERROR)

        if auth_code.redirect_uri != request.redirect_uri:
            return self._error("invalid_grant", "redirect_uri ne correspond pas")

        authenticated = self._authenticate_client(client, request)
        if authenticated is not None:
            return authenticated
        if client.client_type == ClientType.PUBLIC and not auth_code.code_challenge:
            return self._error("invalid_grant", "Les clients publics doivent utiliser PKCE")
        if auth_code.code_challenge and not self._verify_pkce(auth_code, request.code_verifier):
            return self._error("invalid_grant", "Échec de la vérification PKCE")

        await self._codes.consume(auth_code.code)

        refresh_token = ""
        if Scope.OFFLINE_ACCESS in auth_code.scopes:
            refresh_token = await self._issue_refresh_token(
                client, auth_code.subject, auth_code.scopes, now
            )
        id_token, access_token, token_ttl = await self._issue_tokens(
            client, auth_code.subject, auth_code.scopes, nonce=auth_code.nonce, now=now
        )
        return self._success(id_token, access_token, token_ttl, auth_code.scopes, refresh_token)

    async def _refresh(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Renouvelle les jetons à partir d'un refresh token opque (rotation)."""
        if not request.refresh_token:
            return self._error("invalid_grant", "Paramètre refresh_token manquant")

        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error("invalid_client", CLIENT_UNKNOWN_ERROR)

        authenticated = self._authenticate_client(client, request)
        if authenticated is not None:
            return authenticated

        stored = await self._refresh_tokens.find_by_token_hash(token_hash(request.refresh_token))
        if stored is None or stored.client_id != request.client_id:
            return self._error("invalid_grant", "Refresh token invalide ou d'un autre client")
        if stored.is_consumed:
            return self._error("invalid_grant", "Refresh token déjà utilisé (rotation)")
        if stored.expires_at < datetime.now(timezone.utc):
            return self._error("invalid_grant", "Refresh token expiré")

        scopes = stored.scopes
        if request.scope:
            requested = Scope.from_space_separated(request.scope)
            if requested - stored.scopes:
                return self._error("invalid_scope", "Portée demandée jamais accordée au jeton")
            scopes = requested

        now = datetime.now(timezone.utc)
        await self._refresh_tokens.consume(stored.token_hash)
        refresh_token = await self._issue_refresh_token(client, stored.subject, scopes, now)
        id_token, access_token, token_ttl = await self._issue_tokens(
            client, stored.subject, scopes, nonce="", now=now
        )
        return self._success(id_token, access_token, token_ttl, scopes, refresh_token)

    async def _client_credentials(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Émet un access token au nom du client lui-même (RFC 6749 §4.4).

        Le client est à la fois présentateur et ``subject`` du jeton :
        aucun utilisateur final, donc ni ``id_token`` ni ``refresh_token``.
        Seuls les clients confidentiels (authentifiés par ``client_secret``)
        peuvent utiliser ce grant ; le scope demandé reste limité à celui
        enregistré pour le client.
        """
        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error("invalid_client", CLIENT_UNKNOWN_ERROR)
        if client.client_type != ClientType.CONFIDENTIAL:
            return self._error(
                "invalid_client", "Le grant client_credentials exige un client confidentiel"
            )
        if not verify_client_secret(client, request.client_secret):
            return self._error("invalid_client", "Secret client invalide")

        scopes = client.scopes
        if request.scope:
            requested = Scope.from_space_separated(request.scope)
            if requested - client.scopes:
                return self._error("invalid_scope", "Portée jamais enregistrée pour le client")
            scopes = requested

        if self._scope_registry is not None:
            unknown = await self._scope_registry.unknown_scopes(scopes)
            if unknown:
                return self._error(
                    "invalid_scope", "Scope(s) non enregistré(s) : " + ", ".join(unknown)
                )

        now = datetime.now(timezone.utc)
        access_token, token_ttl = await self._issue_access_token(
            client, subject=client.client_id, scopes=scopes, now=now
        )
        return self._success("", access_token, token_ttl, scopes)

    async def _device_code(  # ruff: ignore[complex-structure] — le poll gère 6 états (RFC 8628 §3.4)
        self, request: TokenRequest
    ) -> TokenResponse | TokenError:
        """Poll l'état de la session appareil et émet les jetons une fois approuvée.

        Tant que l'utilisateur n'a pas validé l'appareil sur la page de
        vérification, la réponse est ``authorization_pending`` (RFC 8628
        §3.4). Un poll plus rapide que l'``interval`` retourne
        ``slow_down`` et augmente l'intervalle. Une fois ``APPROVED``, la
        session est consommée et les jetons sont émis pour le ``subject``
        de l'utilisateur ; ``DENIED`` et l'expiration produisent
        respectivement ``access_denied`` et ``expired_token``.
        """
        if self._device_codes is None:
            return self._error("unsupported_grant_type")
        if not request.device_code:
            return self._error("invalid_grant", "Paramètre device_code manquant")

        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error("invalid_client", CLIENT_UNKNOWN_ERROR)

        authenticated = self._authenticate_client(client, request)
        if authenticated is not None:
            return authenticated

        stored = await self._device_codes.find_by_device_code_hash(token_hash(request.device_code))
        if stored is None or stored.client_id != request.client_id:
            return self._error("invalid_grant", "Device code invalide ou d'un autre client")
        if stored.expires_at < datetime.now(timezone.utc):
            await self._device_codes.delete(stored.device_code_hash)
            return self._error("expired_token", "Device code expiré")

        if stored.status == DeviceAuthorizationStatus.DENIED:
            return self._error("access_denied", "Appareil refusé par l'utilisateur")

        now = datetime.now(timezone.utc)
        if stored.status == DeviceAuthorizationStatus.APPROVED:
            await self._device_codes.delete(stored.device_code_hash)
            refresh_token = ""
            if Scope.OFFLINE_ACCESS in stored.scopes:
                refresh_token = await self._issue_refresh_token(
                    client, stored.subject, stored.scopes, now
                )
            id_token, access_token, token_ttl = await self._issue_tokens(
                client, stored.subject, stored.scopes, nonce="", now=now
            )
            return self._success(id_token, access_token, token_ttl, stored.scopes, refresh_token)

        if (
            stored.last_polled_at is not None
            and (now - stored.last_polled_at).total_seconds() < stored.interval
        ):
            await self._device_codes.save(
                replace(stored, interval=stored.interval + 5, last_polled_at=now)
            )
            return self._error("slow_down", "Polling trop rapide : augmentez l'intervalle")
        await self._device_codes.save(replace(stored, last_polled_at=now))
        return self._error("authorization_pending", "En attente de l'autorisation de l'utilisateur")

    def _authenticate_client(self, client: Client, request: TokenRequest) -> TokenError | None:
        """Vérifie l'authentification du client ; retourne l'erreur éventuelle."""
        if client.client_type == ClientType.CONFIDENTIAL and not verify_client_secret(
            client, request.client_secret
        ):
            return self._error("invalid_client", "Secret client invalide")
        return None

    async def _issue_tokens(
        self,
        client: Client,
        subject: str,
        scopes: frozenset[Scope],
        *,
        nonce: str,
        now: datetime,
    ) -> tuple[str, str, int]:
        """Émet et retourne l'``id_token``, l'``access_token`` et la TTL effective."""
        token_ttl = resolve_lifetime_seconds(
            client.access_token_lifetime_seconds, self._config.access_token_ttl_seconds
        )
        expires_at = now + timedelta(seconds=token_ttl)
        issued_at = int(now.timestamp())
        expires_epoch = int(expires_at.timestamp())

        id_token = await self._token_manager.create_id_token(
            algorithm=self._config.signing_algorithm,
            issuer=self._config.issuer,
            subject=subject,
            audience=client.client_id,
            nonce=nonce,
            expires_at=expires_epoch,
            issued_at=issued_at,
            scopes=scopes,
        )
        audience = await self._resolve_audience(client, scopes)
        access_token = await self._token_manager.create_access_token(
            algorithm=self._config.signing_algorithm,
            issuer=self._config.issuer,
            subject=subject,
            audience=audience,
            expires_at=expires_epoch,
            issued_at=issued_at,
            scopes=scopes,
        )
        return id_token, access_token, token_ttl

    async def _issue_access_token(
        self,
        client: Client,
        *,
        subject: str,
        scopes: frozenset[Scope],
        now: datetime,
    ) -> tuple[str, int]:
        """Émet et retourne un ``access_token`` et sa TTL effective."""
        token_ttl = resolve_lifetime_seconds(
            client.access_token_lifetime_seconds, self._config.access_token_ttl_seconds
        )
        expires_at = now + timedelta(seconds=token_ttl)
        issued_at = int(now.timestamp())
        expires_epoch = int(expires_at.timestamp())
        audience = await self._resolve_audience(client, scopes)
        access_token = await self._token_manager.create_access_token(
            algorithm=self._config.signing_algorithm,
            issuer=self._config.issuer,
            subject=subject,
            audience=audience,
            expires_at=expires_epoch,
            issued_at=issued_at,
            scopes=scopes,
        )
        return access_token, token_ttl

    async def _resolve_audience(self, client: Client, scopes: frozenset[Scope]) -> str | list[str]:
        """Audience d'un access token : resources protégées accordées, sinon client."""
        if self._scope_registry is None:
            return client.client_id
        return await self._scope_registry.audiences_for(client.client_id, scopes)

    async def _issue_refresh_token(
        self,
        client: Client,
        subject: str,
        scopes: frozenset[Scope],
        now: datetime,
    ) -> str:
        """Génère, persiste (empreinte) et retourne un nouveau refresh token opque."""
        ttl = resolve_lifetime_seconds(
            client.refresh_token_lifetime_seconds, self._config.refresh_token_ttl_seconds
        )
        value = token_urlsafe(48)
        await self._refresh_tokens.save(
            RefreshToken(
                token_hash=token_hash(value),
                client_id=client.client_id,
                subject=subject,
                scopes=scopes,
                expires_at=now + timedelta(seconds=ttl),
            )
        )
        return value

    def _success(
        self,
        id_token: str,
        access_token: str,
        token_ttl: int,
        scopes: frozenset[Scope],
        refresh_token: str = "",
    ) -> TokenResponse:
        """Construit une réponse de succès (avec ou sans id_token/refresh token)."""
        return TokenResponse(
            access_token=access_token,
            id_token=id_token,
            expires_in=token_ttl,
            scope=" ".join(sorted(scope.value for scope in scopes)),
            refresh_token=refresh_token,
        )

    @staticmethod
    def _verify_pkce(auth_code: AuthorizationCode, code_verifier: str) -> bool:
        """Vérifie le ``code_verifier`` contre le ``code_challenge`` du code.

        ``S256``:  ``base64url(sha256(code_verifier)) == code_challenge``
        ``plain``: ``code_verifier == code_challenge``
        """
        if not code_verifier:
            return False
        if auth_code.code_challenge_method.upper() == "S256":
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
            return expected == auth_code.code_challenge
        return code_verifier == auth_code.code_challenge

    def _error(self, error: str, description: str = "") -> TokenError:
        """Construit une réponse d'erreur du token endpoint (RFC 6749 §5.2)."""
        return TokenError(error=error, error_description=description)
