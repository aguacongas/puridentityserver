"""Cas d'utilisation : endpoint de jetons (RFC 6749 §4.1.3, RFC 7636)."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from thepuroidc.domain.authorization import AuthorizationCode, Client, ClientType
from thepuroidc.domain.jwks import JWTAlgorithm
from thepuroidc.interfaces.domain.tokens import TokenManager
from thepuroidc.interfaces.repositories.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from thepuroidc.interfaces.repositories.client_repository import ClientRepository


@dataclass(frozen=True, slots=True)
class TokenConfig:
    """Paramètres de l'endpoint de jetons."""

    issuer: str
    signing_algorithm: JWTAlgorithm = JWTAlgorithm.RS256
    access_token_ttl_seconds: int = 3600


@dataclass(slots=True)
class TokenRequest:
    """Paramètres fournis par le client à l'endpoint ``/token``."""

    grant_type: str
    code: str
    redirect_uri: str
    client_id: str
    client_secret: str = ""
    code_verifier: str = ""


@dataclass(frozen=True, slots=True)
class TokenResponse:
    """Réponse OAuth 2.0 de type Authorization Code (RFC 6749 §5.1)."""

    access_token: str
    id_token: str
    token_type: str = "Bearer"  # ruff: ignore[hardcoded-password-string]  (valeur standard OAuth, pas un secret)
    expires_in: int = 3600
    scope: str = ""


@dataclass(frozen=True, slots=True)
class TokenError:
    """Erreur du token endpoint (RFC 6749 §5.2)."""

    error: str
    error_description: str = ""


class TokenUseCase:
    """Valide l'échange d'un code d'autorisation et émet les jetons.

    L'authentification du client peut se faire via ``client_secret``
    (confidentiel) ou ``code_verifier`` PKCE (public). Le port
    ``TokenManager`` signe ``id_token`` et ``access_token`` avec la
    première clé active de l'algorithme de signature.
    """

    def __init__(
        self,
        config: TokenConfig,
        client_repository: ClientRepository,
        code_repository: AuthorizationCodeRepository,
        token_manager: TokenManager,
    ) -> None:
        """Injection de la configuration, des repositories et de l'émetteur de jetons."""
        self._config = config
        self._clients = client_repository
        self._codes = code_repository
        self._token_manager = token_manager

    async def execute(self, request: TokenRequest) -> TokenResponse | TokenError:
        """Traite l'échange du code et retourne les jetons ou une erreur."""
        if request.grant_type != "authorization_code":
            return self._error("unsupported_grant_type")

        auth_code = await self._codes.find_by_code(request.code)
        if auth_code is None or auth_code.is_consumed:
            return self._error("invalid_grant", "Code d'autorisation invalide ou déjà consommé")

        now = datetime.now(timezone.utc)
        if auth_code.expires_at < now:
            return self._error("invalid_grant", "Code d'autorisation expiré")

        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error("invalid_client", "Client inconnu ou désactivé")

        if auth_code.redirect_uri != request.redirect_uri:
            return self._error("invalid_grant", "redirect_uri ne correspond pas")

        if client.client_type == ClientType.CONFIDENTIAL and not self._verify_client_secret(
            client, request.client_secret
        ):
            return self._error("invalid_client", "Secret client invalide")
        if client.client_type == ClientType.PUBLIC and not auth_code.code_challenge:
            return self._error("invalid_grant", "Les clients publics doivent utiliser PKCE")
        if auth_code.code_challenge and not self._verify_pkce(auth_code, request.code_verifier):
            return self._error("invalid_grant", "Échec de la vérification PKCE")

        await self._codes.consume(auth_code.code)

        subject = auth_code.subject  # vide si requête anonyme, UUID si login
        expires_at = now + timedelta(seconds=self._config.access_token_ttl_seconds)
        issued_at = int(now.timestamp())
        expires_epoch = int(expires_at.timestamp())

        id_token = await self._token_manager.create_id_token(
            algorithm=self._config.signing_algorithm,
            issuer=self._config.issuer,
            subject=subject,
            audience=request.client_id,
            nonce=auth_code.nonce,
            expires_at=expires_epoch,
            issued_at=issued_at,
            scopes=auth_code.scopes,
        )
        access_token = await self._token_manager.create_access_token(
            algorithm=self._config.signing_algorithm,
            issuer=self._config.issuer,
            subject=subject,
            audience=request.client_id,
            expires_at=expires_epoch,
            issued_at=issued_at,
            scopes=auth_code.scopes,
        )
        return TokenResponse(
            access_token=access_token,
            id_token=id_token,
            expires_in=self._config.access_token_ttl_seconds,
            scope=" ".join(sorted(scope.value for scope in auth_code.scopes)),
        )

    @staticmethod
    def _verify_client_secret(client: Client, secret: str) -> bool:
        """Vérifie le hash du secret client fourni (comparaison constante)."""
        computed = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        import hmac

        return hmac.compare_digest(computed, client.client_secret_hash)

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
