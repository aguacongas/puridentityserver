"""Cas d'utilisation : endpoint d'autorisation (RFC 6749 §4.1)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe

from thepuroidc.domain.authorization import (
    AuthorizationCode,
    ResponseMode,
    Scope,
)
from thepuroidc.interfaces.repositories.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from thepuroidc.interfaces.repositories.client_repository import ClientRepository


@dataclass(frozen=True, slots=True)
class AuthorizeConfig:
    """Paramètres de l'endpoint d'autorisation."""

    code_ttl_seconds: int = 600
    signing_algorithm: str = "RS256"


@dataclass(slots=True)
class AuthorizeRequest:
    """Paramètres fournis par le client à l'endpoint ``/authorize``."""

    response_type: str
    client_id: str
    redirect_uri: str
    scope: str
    subject: str = ""
    state: str = ""
    nonce: str = ""
    code_challenge: str = ""
    code_challenge_method: str = "S256"
    response_mode: ResponseMode = ResponseMode.QUERY


@dataclass(frozen=True, slots=True)
class AuthorizeRedirect:
    """Résultat d'une autorisation : redirection vers ``redirect_uri``."""

    redirect_uri: str
    code: str
    state: str
    response_mode: ResponseMode


@dataclass(frozen=True, slots=True)
class AuthorizeError:
    """Erreur à communiquer au client en ``redirect_uri?error=...``."""

    error: str
    error_description: str
    redirect_uri: str = ""
    state: str = ""


AuthorizeResult = AuthorizeRedirect | AuthorizeError


class AuthorizeUseCase:
    """Valide la demande d'autorisation et émet un code d'autorisation.

    Reçoit un ``AuthorizeRequest`` et retourne soit un redirect léger
    portant le ``code`` vers ``redirect_uri``, soit un redirect d'erreur.
    """

    def __init__(
        self,
        config: AuthorizeConfig,
        client_repository: ClientRepository,
        code_repository: AuthorizationCodeRepository,
    ) -> None:
        """Injection de la configuration et des repositories clients/codes."""
        self._config = config
        self._clients = client_repository
        self._codes = code_repository

    async def execute(self, request: AuthorizeRequest) -> AuthorizeResult:
        """Traite la demande d'autorisation et retourne le redirect ou l'erreur."""
        if request.response_type != "code":
            return self._error(
                "unsupported_response_type", request.state, redirect_uri=request.redirect_uri
            )

        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error(
                "invalid_client",
                request.state,
                redirect_uri=request.redirect_uri,
            )

        if request.redirect_uri not in client.redirect_uris:
            return self._error(
                "invalid_redirect_uri",
                request.state,
                redirect_uri=request.redirect_uri,
            )

        scopes = Scope.from_space_separated(request.scope)
        if Scope.OPENID not in scopes:
            return self._error(
                "invalid_scope",
                request.state,
                redirect_uri=request.redirect_uri,
                description="Le scope 'openid' est requis",
            )

        if request.code_challenge and request.code_challenge_method not in ("S256", "plain"):
            return self._error(
                "invalid_request",
                request.state,
                redirect_uri=request.redirect_uri,
                description="code_challenge_method doit être 'S256' ou 'plain'",
            )

        code = self._generate_code(request, scopes)
        await self._codes.save(code)

        return AuthorizeRedirect(
            redirect_uri=self._build_redirect_uri(request.redirect_uri, code.code, request.state),
            code=code.code,
            state=request.state,
            response_mode=request.response_mode,
        )

    def _generate_code(
        self, request: AuthorizeRequest, scopes: frozenset[Scope]
    ) -> AuthorizationCode:
        """Génère un code d'autorisation à durée de vie limitée."""
        now = datetime.now(timezone.utc)
        return AuthorizationCode(
            code=token_urlsafe(32),
            client_id=request.client_id,
            redirect_uri=request.redirect_uri,
            subject=request.subject,
            scopes=scopes,
            code_challenge=request.code_challenge,
            code_challenge_method=request.code_challenge_method,
            nonce=request.nonce,
            expires_at=now + timedelta(seconds=self._config.code_ttl_seconds),
        )

    def _build_redirect_uri(self, redirect_uri: str, code: str, state: str) -> str:
        """Construit l'URL de retour avec le code et l'état dans la query string."""
        parts = [
            redirect_uri.rstrip("/"),
            "?",
            f"code={code}",
        ]
        if state:
            parts.append(f"&state={state}")
        return "".join(parts)

    def _error(
        self, error: str, state: str, description: str = "", redirect_uri: str = ""
    ) -> AuthorizeError:
        """Construit une réponse d'erreur OAuth (RFC 6749 §4.1.2.1)."""
        return AuthorizeError(
            error=error,
            error_description=description,
            redirect_uri=redirect_uri,
            state=state,
        )
