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

from puridentityserver.application.id_token_encryption import encrypt_id_token_for_client
from puridentityserver.application.id_token_material import resolve_id_token_material
from puridentityserver.application.scope_registry import ScopeRegistry
from puridentityserver.application.session_management import (
    SessionManagementUseCase,
    origin_of_url,
)
from puridentityserver.domain.authorization import (
    AuthorizationCode,
    Client,
    ResponseMode,
    Scope,
    resolve_lifetime_seconds,
)
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.interfaces.domain.secrets import SecretCipher
from puridentityserver.interfaces.domain.tokens import (
    IdTokenEncrypter,
    JWEUnavailableError,
    TokenManager,
)
from puridentityserver.interfaces.repositories.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from puridentityserver.interfaces.repositories.readers import ClientReader

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
    secret_cipher: SecretCipher | None = None
    id_token_encrypter: IdTokenEncrypter | None = None


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
    prompt: str = ""
    session_id: str = ""


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


@dataclass(frozen=True, slots=True)
class ValidatedAuthorization:
    """Demande d'autorisation validée : client résolu + paramètres normalisés."""

    client: Client
    response_types: frozenset[str]
    has_tokens: bool
    wants_code: bool
    wants_id_token: bool
    wants_token: bool
    response_mode: ResponseMode


async def validate_authorization_request(
    request: AuthorizeRequest,
    client_repository: ClientReader,
    scope_registry: ScopeRegistry | None = None,
) -> ValidatedAuthorization | AuthorizeError:
    """Valide une demande d'autorisation (OIDC Core 1.0 §3.1.2.1).

    Partagée entre l'endpoint ``/authorize`` et le endpoint PAR
    (RFC 9126 §2.1) : le ``response_type`` doit être supporté, le client
    connu et actif, la ``redirect_uri`` enregistrée, le scope ``openid``
    requis, et PKCE / ``nonce`` contrôlés. Lorsqu'un ``ScopeRegistry`` est
    fourni, chaque scope demandé doit être enregistré (IdentityResource ou
    ApiResource), sinon la demande est rejetée en ``invalid_scope``.
    Retourne le bundle validé (client + mode de réponse) ou l'erreur à
    renvoyer au client.
    """
    response_types = frozenset(request.response_type.split())
    has_tokens = bool(response_types & frozenset(("id_token", "token")))
    error_mode = _error_response_mode(request.response_mode, has_tokens)

    if not response_types or response_types not in _VALID_RESPONSE_TYPES:
        return _authorize_error(
            "unsupported_response_type",
            request,
            response_mode=error_mode,
        )

    wants_code = "code" in response_types
    wants_id_token = "id_token" in response_types
    wants_token = "token" in response_types
    response_mode = _resolve_response_mode(request.response_mode, has_tokens)
    if response_mode is None:
        return _authorize_error(
            "invalid_request",
            request,
            description="'query' est interdit quand des jetons sont retournés "
            "(OIDC Core 1.0 §3.1.2.1)",
            response_mode=error_mode,
        )

    client = await client_repository.find_by_id(request.client_id)
    if client is None or not client.is_active:
        return _authorize_error(
            "invalid_client",
            request,
            response_mode=response_mode,
        )

    if request.redirect_uri not in client.redirect_uris:
        return _authorize_error(
            "invalid_redirect_uri",
            request,
            response_mode=response_mode,
        )

    scopes = Scope.from_space_separated(request.scope)
    if Scope.OPENID not in scopes:
        return _authorize_error(
            "invalid_scope",
            request,
            description="Le scope 'openid' est requis",
            response_mode=response_mode,
        )

    if scope_registry is not None:
        unknown = await scope_registry.unknown_scopes(scopes)
        if unknown:
            return _authorize_error(
                "invalid_scope",
                request,
                description="Scope(s) non enregistré(s) : " + ", ".join(unknown),
                response_mode=response_mode,
            )

    if request.code_challenge and request.code_challenge_method not in ("S256", "plain"):
        return _authorize_error(
            "invalid_request",
            request,
            description="code_challenge_method doit être 'S256' ou 'plain'",
            response_mode=response_mode,
        )

    if wants_id_token and not request.nonce:
        return _authorize_error(
            "invalid_request",
            request,
            description="nonce requis (OIDC Core 1.0 §3.2.2.10)",
            response_mode=response_mode,
        )

    return ValidatedAuthorization(
        client=client,
        response_types=response_types,
        has_tokens=has_tokens,
        wants_code=wants_code,
        wants_id_token=wants_id_token,
        wants_token=wants_token,
        response_mode=response_mode,
    )


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
        client_repository: ClientReader,
        code_repository: AuthorizationCodeRepository,
        token_manager: TokenManager,
        scope_registry: ScopeRegistry | None = None,
        session_management: SessionManagementUseCase | None = None,
    ) -> None:
        """Injection de la configuration, des repositories et de l'émetteur de jetons."""
        self._config = config
        self._clients = client_repository
        self._codes = code_repository
        self._token_manager = token_manager
        self._scope_registry = scope_registry
        self._session_management = session_management

    async def execute(self, request: AuthorizeRequest) -> AuthorizeResult:
        """Traite la demande d'autorisation et retourne le redirect ou l'erreur."""
        validated = await validate_authorization_request(
            request, self._clients, self._scope_registry
        )
        if isinstance(validated, AuthorizeError):
            return validated

        scopes = Scope.from_space_separated(request.scope)
        code = ""
        if validated.wants_code:
            code = await self._issue_code(request, scopes, validated.client)

        id_token = ""
        access_token = ""
        expires_in = 0
        if validated.wants_id_token or validated.wants_token:
            issued = await self._issue_tokens(
                request,
                scopes,
                validated.client,
                code,
                validated.wants_id_token,
                validated.wants_token,
            )
            if isinstance(issued, AuthorizeError):
                return issued
            id_token, access_token, expires_in = issued

        params = self._build_success_params(
            code=code,
            id_token=id_token,
            access_token=access_token,
            expires_in=expires_in,
            scopes=scopes if validated.wants_token else frozenset(),
            state=request.state,
            session_state=self._resolve_session_state(request),
        )
        return AuthorizeRedirect(
            redirect_uri=self._build_redirect_uri(
                request.redirect_uri, validated.response_mode, params
            ),
            code=code,
            state=request.state,
            response_mode=validated.response_mode,
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
            session_id=request.session_id,
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
    ) -> tuple[str, str, int] | AuthorizeError:
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
            audience = await self._resolve_audience(client, scopes)
            access_token = await self._token_manager.create_access_token(
                algorithm=self._config.signing_algorithm,
                issuer=self._config.issuer,
                subject=request.subject,
                audience=audience,
                expires_at=expires_epoch,
                issued_at=issued_at,
                scopes=scopes,
            )
            at_hash = _hash_artefact(access_token, self._config.signing_algorithm)

        id_token = ""
        if wants_id_token:
            material = await resolve_id_token_material(
                client, self._config.signing_algorithm, self._config.secret_cipher
            )
            if material is None:
                return _authorize_error(
                    "invalid_client",
                    request,
                    description="Secret du client indisponible pour la signature HS*",
                )
            id_token_algorithm, shared_secret = material
            id_token = await self._token_manager.create_id_token(
                algorithm=id_token_algorithm,
                issuer=self._config.issuer,
                subject=request.subject,
                audience=client.client_id,
                nonce=request.nonce,
                session_id=request.session_id,
                expires_at=expires_epoch,
                issued_at=issued_at,
                scopes=scopes,
                at_hash=at_hash,
                c_hash=(_hash_artefact(code, id_token_algorithm) if code else ""),
                shared_secret=shared_secret,
            )
            try:
                id_token = await encrypt_id_token_for_client(
                    id_token=id_token,
                    client=client,
                    secret_cipher=self._config.secret_cipher,
                    encrypter=self._config.id_token_encrypter,
                )
            except JWEUnavailableError:
                return _authorize_error(
                    "invalid_client",
                    request,
                    description="Matériel de chiffrement d'id_token indisponible",
                )
        return id_token, access_token, token_ttl

    async def _resolve_audience(self, client: Client, scopes: frozenset[Scope]) -> str | list[str]:
        """Audience d'un access token : resources protégées accordées, sinon client."""
        if self._scope_registry is None:
            return client.client_id
        return await self._scope_registry.audiences_for(client.client_id, scopes)

    def _build_success_params(
        self,
        *,
        code: str,
        id_token: str,
        access_token: str,
        expires_in: int,
        scopes: frozenset[Scope],
        state: str,
        session_state: str = "",
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
        if session_state:
            params.append(f"session_state={session_state}")
        if state:
            params.append(f"state={state}")
        return params

    def _resolve_session_state(self, request: AuthorizeRequest) -> str:
        """Valeur ``session_state`` de la réponse (OIDC Session Management 1.0 §2).

        Présente uniquement quand une session utilisateur est active (cookie
        ``opbs``) : l'origin de la ``redirect_uri`` sert d'origin RP (RFC 6454
        §4). Sans use case injecté, aucun paramètre n'est ajouté.
        """
        if self._session_management is None or not request.session_id:
            return ""
        return self._session_management.create_session_state(
            client_id=request.client_id,
            origin=origin_of_url(request.redirect_uri),
            session_id=request.session_id,
        )

    def _build_redirect_uri(
        self, redirect_uri: str, response_mode: ResponseMode, params: list[str]
    ) -> str:
        """Construit l'URL de retour : query (query string) ou fragment (#...)."""
        separator = "#" if response_mode is ResponseMode.FRAGMENT else "?"
        return f"{redirect_uri.rstrip('/')}{separator}{'&'.join(params)}"


def _resolve_response_mode(requested: str, has_tokens: bool) -> ResponseMode | None:
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


def _error_response_mode(requested: str, has_tokens: bool) -> ResponseMode:
    """Mode d'encodage des réponses d'erreur (RFC 6749 §4.2.2.1, OIDC §3.2.2.6).

    Les erreurs des flows retournant des jetons vont dans le fragment ; les
    autres dans la query string. Une combinaison ``query`` + jetons (interdite)
    retombe aussi sur le fragment.
    """
    resolved = _resolve_response_mode(requested, has_tokens)
    return resolved if resolved is not None else ResponseMode.FRAGMENT


def _authorize_error(
    error: str,
    request: AuthorizeRequest,
    description: str = "",
    response_mode: ResponseMode = ResponseMode.QUERY,
) -> AuthorizeError:
    """Construit une réponse d'erreur OAuth (RFC 6749 §4.1.2.1, §4.2.2.1)."""
    return AuthorizeError(
        error=error,
        error_description=description,
        redirect_uri=request.redirect_uri,
        state=request.state,
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
