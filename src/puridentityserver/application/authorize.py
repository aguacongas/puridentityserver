"""Cas d'utilisation : endpoint d'autorisation (RFC 6749, OIDC Core 1.0).

Traite les sept ``response_type`` du standard OpenID Connect :

===============================  ===========================================
``response_type``                Grants issus (OIDC Core 1.0)
===============================  ===========================================
``code``                         Authorization Code (§3.1 + RFC 6749 §4.1)
``id_token``                     Implicit (§3.2.2)
``token``                        Implicit (OAuth 2.0, RFC 6749 §4.2)
``id_token token``               Implicit (§3.2)
``code id_token``                Hybrid (§3.3.2)
``code token``                   Hybrid (§3.3)
``code id_token token``          Hybrid (§3.3)
===============================  ===========================================

Les jetons émis sur ``/authorize`` (implicit/hybrid) sont retournés dans le
**fragment** de l'URL de redirection (jamais dans la query string, RFC 6749
§4.2.2) ; le ``nonce`` est requis dès qu'un ``id_token`` est émis. En hybrid,
l'``id_token`` porte ``c_hash`` (empreinte du code) et ``at_hash`` (empreinte
de l'access token) pour lier les trois artefacts (OIDC Core 1.0 §3.3.2.11).
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe

from puridentityserver.domain.authorization import (
    AuthorizationCode,
    Client,
    ResponseMode,
    Scope,
    resolve_lifetime_seconds,
)
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.interfaces.domain.tokens import TokenManager
from puridentityserver.interfaces.repositories.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from puridentityserver.interfaces.repositories.client_repository import ClientRepository

_VALID_RESPONSE_TYPES = frozenset(
    (
        frozenset({"code"}),
        frozenset({"id_token"}),
        frozenset({"token"}),
        frozenset({"id_token", "token"}),
        frozenset({"code", "id_token"}),
        frozenset({"code", "token"}),
        frozenset({"code", "id_token", "token"}),
    )
)


@dataclass(frozen=True, slots=True)
class AuthorizeConfig:
    """Paramètres de l'endpoint d'autorisation."""

    code_ttl_seconds: int = 600
    access_token_ttl_seconds: int = 3600
    signing_algorithm: JWTAlgorithm = JWTAlgorithm.RS256
    issuer: str = ""


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
    response_mode: str = ""


@dataclass(frozen=True, slots=True)
class AuthorizeRedirect:
    """Résultat d'une autorisation : redirection vers ``redirect_uri``."""

    redirect_uri: str
    code: str
    state: str
    response_mode: ResponseMode
    id_token: str = ""
    access_token: str = ""
    expires_in: int = 0


@dataclass(frozen=True, slots=True)
class AuthorizeError:
    """Erreur communiquée au client dans la redirection ``redirect_uri``."""

    error: str
    error_description: str
    redirect_uri: str = ""
    state: str = ""
    response_mode: ResponseMode = ResponseMode.QUERY


AuthorizeResult = AuthorizeRedirect | AuthorizeError


class AuthorizeUseCase:
    """Valide la demande d'autorisation puis émet code et/ou jetons.

    Selon le ``response_type`` demandé (OIDC Core 1.0 §3.1.2.1) : le code
    d'autorisation est enregistré s'il est demandé (hybrid), l'access token
    et/ou l'id_token sont émis depuis ``/authorize`` pour les flows implicit
    et hybrid. La réponse est placée dans le fragment de la ``redirect_uri``
    dès qu'un jeton est retourné.
    """

    def __init__(
        self,
        config: AuthorizeConfig,
        client_repository: ClientRepository,
        code_repository: AuthorizationCodeRepository,
        token_manager: TokenManager,
    ) -> None:
        """Injection de la configuration, des repositories et de l'émetteur de jetons."""
        self._config = config
        self._clients = client_repository
        self._codes = code_repository
        self._token_manager = token_manager

    async def execute(self, request: AuthorizeRequest) -> AuthorizeResult:
        """Traite la demande d'autorisation et retourne le redirect ou l'erreur."""
        response_types = frozenset(request.response_type.split())
        has_tokens = bool(response_types & frozenset(("id_token", "token")))
        error_mode = self._error_mode(request.response_mode, has_tokens)

        if not response_types or response_types not in _VALID_RESPONSE_TYPES:
            return self._error(
                "unsupported_response_type",
                request.state,
                redirect_uri=request.redirect_uri,
                response_mode=error_mode,
            )

        wants_code = "code" in response_types
        wants_id_token = "id_token" in response_types
        wants_token = "token" in response_types
        response_mode = self._resolve_mode(request.response_mode, has_tokens)
        if response_mode is None:
            return self._error(
                "invalid_request",
                request.state,
                redirect_uri=request.redirect_uri,
                description="'query' est interdit quand des jetons sont retournés "
                "(OIDC Core 1.0 §3.1.2.1)",
                response_mode=error_mode,
            )
        error_mode = response_mode

        client = await self._clients.find_by_id(request.client_id)
        if client is None or not client.is_active:
            return self._error(
                "invalid_client",
                request.state,
                redirect_uri=request.redirect_uri,
                response_mode=error_mode,
            )

        if request.redirect_uri not in client.redirect_uris:
            return self._error(
                "invalid_redirect_uri",
                request.state,
                redirect_uri=request.redirect_uri,
                response_mode=error_mode,
            )

        scopes = Scope.from_space_separated(request.scope)
        if Scope.OPENID not in scopes:
            return self._error(
                "invalid_scope",
                request.state,
                redirect_uri=request.redirect_uri,
                description="Le scope 'openid' est requis",
                response_mode=error_mode,
            )

        if request.code_challenge and request.code_challenge_method not in ("S256", "plain"):
            return self._error(
                "invalid_request",
                request.state,
                redirect_uri=request.redirect_uri,
                description="code_challenge_method doit être 'S256' ou 'plain'",
                response_mode=error_mode,
            )

        if wants_id_token and not request.nonce:
            return self._error(
                "invalid_request",
                request.state,
                redirect_uri=request.redirect_uri,
                description="nonce requis (OIDC Core 1.0 §3.2.2.10)",
                response_mode=error_mode,
            )

        code = ""
        if wants_code:
            code = await self._issue_code(request, scopes, client)

        id_token = ""
        access_token = ""
        expires_in = 0
        if wants_id_token or wants_token:
            id_token, access_token, expires_in = await self._issue_tokens(
                request, scopes, client, code, wants_id_token, wants_token
            )

        params = self._build_success_params(
            code=code,
            id_token=id_token,
            access_token=access_token,
            expires_in=expires_in,
            scopes=scopes if wants_token else frozenset(),
            state=request.state,
        )
        return AuthorizeRedirect(
            redirect_uri=self._build_redirect_uri(request.redirect_uri, response_mode, params),
            code=code,
            state=request.state,
            response_mode=response_mode,
            id_token=id_token,
            access_token=access_token,
            expires_in=expires_in,
        )

    async def _issue_code(
        self, request: AuthorizeRequest, scopes: frozenset[Scope], client: Client
    ) -> str:
        """Émet et persiste un code d'autorisation (code flow ou hybrid)."""
        code_ttl = resolve_lifetime_seconds(
            client.authorization_code_lifetime_seconds, self._config.code_ttl_seconds
        )
        now = datetime.now(timezone.utc)
        code = AuthorizationCode(
            code=token_urlsafe(32),
            client_id=request.client_id,
            redirect_uri=request.redirect_uri,
            subject=request.subject,
            scopes=scopes,
            code_challenge=request.code_challenge,
            code_challenge_method=request.code_challenge_method,
            nonce=request.nonce,
            expires_at=now + timedelta(seconds=code_ttl),
        )
        await self._codes.save(code)
        return code.code

    async def _issue_tokens(
        self,
        request: AuthorizeRequest,
        scopes: frozenset[Scope],
        client: Client,
        code: str,
        wants_id_token: bool,
        wants_token: bool,
    ) -> tuple[str, str, int]:
        """Émet id_token et/ou access token depuis ``/authorize`` (implicit/hybrid)."""
        token_ttl = resolve_lifetime_seconds(
            client.access_token_lifetime_seconds, self._config.access_token_ttl_seconds
        )
        now = datetime.now(timezone.utc)
        issued_at = int(now.timestamp())
        expires_epoch = int((now + timedelta(seconds=token_ttl)).timestamp())

        at_hash = ""
        access_token = ""
        if wants_token:
            access_token = await self._token_manager.create_access_token(
                algorithm=self._config.signing_algorithm,
                issuer=self._config.issuer,
                subject=request.subject,
                audience=client.client_id,
                expires_at=expires_epoch,
                issued_at=issued_at,
                scopes=scopes,
            )
            at_hash = _hash_artefact(access_token, self._config.signing_algorithm)

        id_token = ""
        if wants_id_token:
            id_token = await self._token_manager.create_id_token(
                algorithm=self._config.signing_algorithm,
                issuer=self._config.issuer,
                subject=request.subject,
                audience=client.client_id,
                nonce=request.nonce,
                expires_at=expires_epoch,
                issued_at=issued_at,
                scopes=scopes,
                at_hash=at_hash,
                c_hash=_hash_artefact(code, self._config.signing_algorithm) if code else "",
            )
        return id_token, access_token, token_ttl

    def _build_success_params(
        self,
        *,
        code: str,
        id_token: str,
        access_token: str,
        expires_in: int,
        scopes: frozenset[Scope],
        state: str,
    ) -> list[str]:
        """Assemble les paramètres de succès de la redirection (RFC 6749 §4.1.2, §4.2.2)."""
        params: list[str] = []
        if code:
            params.append(f"code={code}")
        if access_token:
            params.append(f"access_token={access_token}")
            params.append("token_type=Bearer")
            params.append(f"expires_in={expires_in}")
            params.append("scope=" + " ".join(sorted(scope.value for scope in scopes)))
        if id_token:
            params.append(f"id_token={id_token}")
        if state:
            params.append(f"state={state}")
        return params

    def _build_redirect_uri(
        self, redirect_uri: str, response_mode: ResponseMode, params: list[str]
    ) -> str:
        """Construit l'URL de retour : query (query string) ou fragment (#...)."""
        separator = "#" if response_mode is ResponseMode.FRAGMENT else "?"
        return f"{redirect_uri.rstrip('/')}{separator}{'&'.join(params)}"

    def _resolve_mode(self, requested: str, has_tokens: bool) -> ResponseMode | None:
        """Détermine le mode de réponse ; ``None`` signale une combinaison interdite.

        Le fragment s'impose dès qu'un jeton est retourné : la query string
        exposerait le jeton (historique, Referer). Un ``response_mode=query``
        explicite combiné à des jetons est donc refusé (RFC 6749 §4.2.2,
        OIDC Core 1.0 §3.1.2.1).
        """
        if requested == ResponseMode.FRAGMENT.value:
            return ResponseMode.FRAGMENT
        if requested == ResponseMode.QUERY.value:
            return None if has_tokens else ResponseMode.QUERY
        return ResponseMode.FRAGMENT if has_tokens else ResponseMode.QUERY

    def _error_mode(self, requested: str, has_tokens: bool) -> ResponseMode:
        """Mode d'encodage des réponses d'erreur (RFC 6749 §4.2.2.1, OIDC §3.2.2.6).

        Les erreurs des flows retournant des jetons vont dans le fragment ; les
        autres dans la query string. Une combinaison ``query`` + jetons (interdite)
        retombe aussi sur le fragment.
        """
        resolved = self._resolve_mode(requested, has_tokens)
        return resolved if resolved is not None else ResponseMode.FRAGMENT

    def _error(
        self,
        error: str,
        state: str,
        description: str = "",
        redirect_uri: str = "",
        response_mode: ResponseMode = ResponseMode.QUERY,
    ) -> AuthorizeError:
        """Construit une réponse d'erreur OAuth (RFC 6749 §4.1.2.1, §4.2.2.1)."""
        return AuthorizeError(
            error=error,
            error_description=description,
            redirect_uri=redirect_uri,
            state=state,
            response_mode=response_mode,
        )


def _hash_artefact(value: str, algorithm: JWTAlgorithm) -> str:
    """Empreinte OIDC ``at_hash`` / ``c_hash`` (OIDC Core 1.0 §3.3.2.11).

    Moitié gauche du digest SHA-2 (256/384/512 selon l'algorithme JWS) de la
    valeur, encodée base64url sans padding : le client peut ainsi vérifier le
    lien entre l'id_token et l'access token / le code d'autorisation.
    """
    digest = hashlib.new(f"sha{algorithm.value[-3:]}", value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")
