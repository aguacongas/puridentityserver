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
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe

from puridentityserver.application.claims_request import (
    ClaimsRequest,
    parse_claims_parameter,
    requested_userinfo_payload,
    resolve_requested_claims,
    scope_claims_for_subject,
)
from puridentityserver.application.id_token_encryption import encrypt_id_token_for_client
from puridentityserver.application.id_token_material import resolve_id_token_material
from puridentityserver.application.resource_indicators import (
    is_resource_uri,
    parse_resource_parameter,
    resource_audience,
)
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
from puridentityserver.interfaces.domain.userinfo import ClaimsProvider
from puridentityserver.interfaces.repositories.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from puridentityserver.interfaces.repositories.readers import ClientReader, IdentityResourceReader

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

_DP_JKT_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")  # thumbprint RFC 7638 (RFC 9449 §4.2)


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
    max_age: int = -1  # -1 absent, -2 invalide, sinon âge max en secondes (§3.1.2.1)
    session_id: str = ""
    auth_time: int = 0
    acr_values: str = ""  # valeurs ACR demandées, séparées par des espaces (§3.1.2.1)
    claims: str = ""  # paramètre claims brut (OIDC Core 1.0 §5.5)
    dpop_jkt: str = ""  # empreinte de la clé DPoP liant le code (RFC 9449 §4.2)
    resource: str = ""  # resource indicators RFC 8707 (URI uniques ou tableau JSON compact)


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
    """Erreur communiquée au client dans la redirection ``redirect_uri``.

    ``redirectable`` à ``False`` signale une erreur qui ne doit **jamais**
    repartir en redirection : ``redirect_uri`` non enregistrée ou
    ``client_id`` invalide, que la RFC 6749 §4.1.2.1 interdit de suivre au
    profit d'une information affichée à l'utilisateur par le user agent.
    """

    error: str
    error_description: str
    redirect_uri: str = ""
    state: str = ""
    response_mode: ResponseMode = ResponseMode.QUERY
    redirectable: bool = True


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


async def _parameter_error(
    request: AuthorizeRequest,
    scope_registry: ScopeRegistry | None,
    response_mode: ResponseMode,
) -> AuthorizeError | None:
    """Rejette ``max_age`` négatif, ``claims``/``dpop_jkt``/``resource`` malformés, ou ``None``.

    ``claims`` doit être un objet JSON (OIDC Core 1.0 §5.5.1) ; toute autre
    forme — tableau, scalaire, JSON invalide — vaut ``invalid_request``.
    ``dpop_jkt`` doit être l'empreinte thumbprint RFC 7638 d'une clé publique
    (43 caractères base64url, RFC 9449 §4.2) ; tout autre format vaut
    ``invalid_request``. ``code_challenge_method`` doit être ``S256`` ou
    ``plain`` (RFC 7636 §4.3). Le contrôle ``resource`` (RFC 8707) est
    délégué à :func:`_resource_error`.
    """
    if request.max_age < -1:
        return _authorize_error(
            "invalid_request",
            request,
            description="max_age doit être un entier positif (OIDC Core 1.0 §3.1.2.1)",
            response_mode=response_mode,
        )
    if request.claims and parse_claims_parameter(request.claims) is None:
        return _authorize_error(
            "invalid_request",
            request,
            description="claims doit être un objet JSON valide (OIDC Core 1.0 §5.5.1)",
            response_mode=response_mode,
        )
    if request.dpop_jkt and not _DP_JKT_PATTERN.fullmatch(request.dpop_jkt):
        return _authorize_error(
            "invalid_request",
            request,
            description="dpop_jkt doit être une empreinte RFC 7638 (43 caractères base64url)",
            response_mode=response_mode,
        )
    if request.code_challenge and request.code_challenge_method not in ("S256", "plain"):
        return _authorize_error(
            "invalid_request",
            request,
            description="code_challenge_method doit être 'S256' ou 'plain' (RFC 7636 §4.3)",
            response_mode=response_mode,
        )
    return await _resource_error(request, scope_registry, response_mode)


async def _resource_error(
    request: AuthorizeRequest,
    scope_registry: ScopeRegistry | None,
    response_mode: ResponseMode,
) -> AuthorizeError | None:
    """Contrôle le paramètre ``resource`` (RFC 8707 §2.1-§2.2).

    Chaque resource indicator doit être une URI absolue sans fragment,
    dont l'``ApiResource.indicator`` correspondant est enregistré. Toute
    URI malformée ou inconnue vaut ``invalid_target`` (RFC 8707 §2.2) ;
    la ``redirect_uri`` étant déjà vérifiée à ce stade, l'erreur peut
    être renvoyée dans la redirection.
    """
    resources = parse_resource_parameter(request.resource)
    if not resources:
        return None
    malformed = [uri for uri in resources if not is_resource_uri(uri)]
    if malformed:
        return _authorize_error(
            "invalid_target",
            request,
            description="resource doit être une URI absolue sans fragment (RFC 8707 §2.1) : "
            + ", ".join(malformed),
            response_mode=response_mode,
        )
    if scope_registry is not None:
        unknown = await scope_registry.unknown_resources(resources)
        if unknown:
            return _authorize_error(
                "invalid_target",
                request,
                description="Resource non enregistrée (RFC 8707 §2.2) : " + ", ".join(unknown),
                response_mode=response_mode,
            )
    return None


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

    if response_types not in _VALID_RESPONSE_TYPES:
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
        return _query_mode_forbidden_error(request, error_mode)

    client = await client_repository.find_by_id(request.client_id)
    if client is None or not client.is_active:
        # client_id absent/inconnu : la redirect_uri ne peut pas être
        # vérifiée, donc aucune redirection n'est de confiance (RFC 6749 §4.1.2.1)
        return _authorize_error(
            "invalid_client",
            request,
            response_mode=response_mode,
            redirectable=False,
        )

    if request.redirect_uri not in client.redirect_uris:
        return _authorize_error(
            "invalid_redirect_uri",
            request,
            response_mode=response_mode,
            redirectable=False,
        )

    if client.fapi_enabled:
        fapi_error = _fapi_profile_error(request, client, response_types, response_mode)
        if fapi_error is not None:
            return fapi_error

    param_error = await _parameter_error(request, scope_registry, response_mode)
    if param_error is not None:
        return param_error

    scopes = Scope.from_space_separated(request.scope)
    scope_error = await _scope_profile_error(scopes, scope_registry, request, response_mode)
    if scope_error is not None:
        return scope_error

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


async def _scope_profile_error(
    scopes: frozenset[Scope],
    scope_registry: ScopeRegistry | None,
    request: AuthorizeRequest,
    response_mode: ResponseMode,
) -> AuthorizeError | None:
    """Contrôle ``openid`` requis et scopes inconnus (OIDC Core 1.0 §3.1.2.1).

    ``None`` si chaque scope demandé est enregistré ; sinon ``invalid_scope``
    portant le scope fautif ou l'absence d'``openid``.
    """
    if Scope.OPENID not in scopes:
        return _authorize_error(
            "invalid_scope",
            request,
            description="Le scope 'openid' est requis",
            response_mode=response_mode,
        )
    return await _unknown_scope_error(scopes, scope_registry, request, response_mode)


def _fapi_profile_error(
    request: AuthorizeRequest,
    client: Client,
    response_types: frozenset[str],
    response_mode: ResponseMode,
) -> AuthorizeError | None:
    """Contrôle le profil FAPI 1.0 Advanced du client (``fapi_enabled``).

    Seul le flow hybride ``code id_token`` est admis sans JARM
    (FAPI1-ADV-5.2.2-2) : ``code`` seul est refusé
    ``unsupported_response_type``. Un ``code_challenge`` déclaré doit
    employer ``S256`` — ``plain`` est rejeté (FAPI1-ADV-5.2.2-18) ;
    l'obligation PKCE elle-même ne vaut qu'en PAR, appliquée au push.
    """
    if not _is_fapi_flow(response_types):
        return _authorize_error(
            "unsupported_response_type",
            request,
            description="FAPI1-Advanced n'admet que le flow hybride "
            "'code id_token' (FAPI1-ADV-5.2.2-2)",
            response_mode=response_mode,
        )
    if request.code_challenge and request.code_challenge_method != "S256":
        return _authorize_error(
            "invalid_request",
            request,
            description="code_challenge_method doit être 'S256' pour un client "
            "FAPI1 (FAPI1-ADV-5.2.2-18)",
            response_mode=response_mode,
        )
    return None


def _is_fapi_flow(response_types: frozenset[str]) -> bool:
    """True si ``response_types`` est le flow hybride exigé par FAPI 1.0 Advanced.

    Seul ``code id_token`` est admis sans JARM (FAPI1-ADV-5.2.2-2) :
    ``code`` seul (flow authorization code) comme ``token`` pur sont refusés
    ``unsupported_response_type`` — le profil JARM (``response_mode=jwt``)
    n'est pas retenu.
    """
    return response_types == frozenset(("code", "id_token"))


def _query_mode_forbidden_error(
    request: AuthorizeRequest, error_mode: ResponseMode
) -> AuthorizeError:
    """``response_mode=query`` interdit dès qu'un jeton est retourné (§3.1.2.1)."""
    return _authorize_error(
        "invalid_request",
        request,
        description="'query' est interdit quand des jetons sont retournés (OIDC Core 1.0 §3.1.2.1)",
        response_mode=error_mode,
    )


async def _unknown_scope_error(
    scopes: frozenset[Scope],
    scope_registry: ScopeRegistry | None,
    request: AuthorizeRequest,
    response_mode: ResponseMode,
) -> AuthorizeError | None:
    """Scopes tous enregistrés au registre (IdentityResource/ApiResource)."""
    if scope_registry is None:
        return None
    unknown = await scope_registry.unknown_scopes(scopes)
    if not unknown:
        return None
    return _authorize_error(
        "invalid_scope",
        request,
        description="Scope(s) non enregistré(s) : " + ", ".join(unknown),
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
        *,
        claims_provider: ClaimsProvider | None = None,
        identity_resources: IdentityResourceReader | None = None,
    ) -> None:
        """Injection de la configuration, des repositories et de l'émetteur de jetons.

        ``claims_provider`` / ``identity_resources`` alimentent les claims
        ajoutés à l'id_token : les claims des scopes accordés en
        ``response_type=id_token`` (OIDC Core 1.0 §5.4 — aucun UserInfo
        possible sans access_token) et le member ``id_token`` du paramètre
        ``claims`` (§5.5). Sans injection, l'id_token garde son payload
        standard minimal.
        """
        self._config = config
        self._clients = client_repository
        self._codes = code_repository
        self._token_manager = token_manager
        self._scope_registry = scope_registry
        self._session_management = session_management
        self._claims_provider = claims_provider
        self._identity_resources = identity_resources

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
            auth_time=request.auth_time,
            acr=first_acr_value(request.acr_values),
            claims=request.claims,
            dpop_jkt=request.dpop_jkt,
            resource_uris=parse_resource_parameter(request.resource),
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
        """Émet id_token et/ou access token depuis ``/authorize`` (implicit/hybrid).

        L'id_token reprend le claim ``acr`` (première valeur ``acr_values``
        demandée) et, selon le ``response_type`` :

        - ``response_type=id_token`` seul : les claims des scopes accordés
          sont ajoutés au payload — sans access_token, aucun UserInfo ne
          rendra ces claims (OIDC Core 1.0 §5.4) ;
        - tout type contenant ``id_token`` : les claims du member
          ``id_token`` du paramètre ``claims`` (§5.5) ;

        l'access_token embarque les noms de claims du member ``userinfo``
        (§5.5) que ``/userinfo`` relira pour élargir son filtrage.
        """
        claims_request = parse_claims_parameter(request.claims) if request.claims else None
        token_ttl = resolve_lifetime_seconds(
            client.access_token_lifetime_seconds, self._config.access_token_ttl_seconds
        )
        now = datetime.now(timezone.utc)
        issued_at = int(now.timestamp())
        expires_epoch = int((now + timedelta(seconds=token_ttl)).timestamp())

        at_hash = ""
        access_token = ""
        if wants_token:
            audience = await self._resolve_audience(client, scopes, request.resource)
            access_token = await self._token_manager.create_access_token(
                algorithm=self._config.signing_algorithm,
                issuer=self._config.issuer,
                subject=request.subject,
                audience=audience,
                expires_at=expires_epoch,
                issued_at=issued_at,
                scopes=scopes,
                additional_claims=(
                    requested_userinfo_payload(claims_request) if claims_request else None
                ),
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
                at_hash=at_hash,
                c_hash=(_hash_artefact(code, id_token_algorithm) if code else ""),
                s_hash=(_hash_artefact(request.state, id_token_algorithm) if request.state else ""),
                auth_time=request.auth_time,
                shared_secret=shared_secret,
                additional_claims=await self._additional_id_token_claims(
                    request, code=code, wants_token=wants_token, claims_request=claims_request
                ),
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

    async def _additional_id_token_claims(
        self,
        request: AuthorizeRequest,
        *,
        code: str,
        wants_token: bool,
        claims_request: ClaimsRequest | None,
    ) -> dict[str, object] | None:
        """Claims complémentaires de l'id_token émis par ``/authorize``.

        Porte d'abord le claim ``acr`` (première valeur ``acr_values``
        demandée, OIDC Core 1.0 §2) quand elle est non vide, puis fusionne
        les claims du member ``id_token`` du paramètre ``claims``
        (OIDC Core 1.0 §5.5.1) avec, pour un ``response_type=id_token``
        **seul** — ni code ni access_token, donc sans UserInfo possible —,
        les claims des scopes accordés (OIDC Core 1.0 §5.4). ``None`` quand
        rien n'est à ajouter, pour ne pas altérer le payload standard.
        """
        additional: dict[str, object] = {}
        acr = first_acr_value(request.acr_values)
        if acr:
            additional["acr"] = acr
        if claims_request is not None:
            additional.update(
                await resolve_requested_claims(
                    claims_request.id_token, request.subject, self._claims_provider
                )
            )
        pure_id_token = not code and not wants_token
        if pure_id_token:
            additional.update(
                await scope_claims_for_subject(
                    request.scope,
                    request.subject,
                    self._claims_provider,
                    self._identity_resources,
                )
            )
        return additional or None

    async def _resolve_audience(
        self, client: Client, scopes: frozenset[Scope], resource: str = ""
    ) -> str | list[str]:
        """Audience d'un access token : resources ciblées (RFC 8707), sinon registre, sinon client.

        Un ``resource`` présent prend la priorité sur le calcul par
        scopes : l'``aud`` porte alors les URI ciblées (chaîne pour une
        seule, liste sinon), après validation de :func:`_resource_error`.
        """
        resources = parse_resource_parameter(resource)
        if resources:
            return resource_audience(resources)
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
    redirectable: bool = True,
) -> AuthorizeError:
    """Construit une réponse d'erreur OAuth (RFC 6749 §4.1.2.1, §4.2.2.1)."""
    return AuthorizeError(
        error=error,
        error_description=description,
        redirect_uri=request.redirect_uri,
        state=request.state,
        response_mode=response_mode,
        redirectable=redirectable,
    )


def _hash_artefact(value: str, algorithm: JWTAlgorithm) -> str:
    """Empreinte OIDC ``at_hash`` / ``c_hash`` / ``s_hash`` (OIDC Core 1.0 §3.3.2.11).

    Moitié gauche du digest SHA-2 (256/384/512 selon l'algorithme JWS) de la
    valeur, encodée base64url sans padding : le client peut ainsi vérifier le
    lien entre l'id_token et l'access token / le code d'autorisation / le
    ``state`` (FAPI1-ADV-5.2.2.1-5).
    ``alg=none`` n'a pas d'empreinte définie (le lien repose sur la
    signature) : la chaîne vide fait omettre le claim.
    """
    if algorithm is JWTAlgorithm.NONE:
        return ""
    digest = hashlib.new(f"sha{algorithm.value[-3:]}", value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")


def parse_max_age(value: str) -> int:
    """Parse le paramètre ``max_age`` (OIDC Core 1.0 §3.1.2.1).

    ``-1`` : paramètre absent (aucune contrainte) ; ``-2`` : valeur non
    entière ou négative, à laquelle ``validate_authorization_request``
    répond par ``invalid_request`` ; ``0`` et plus : l'âge maximal accepté
    de la dernière authentification (``0`` impose une reconnexion
    immédiate, quel que soit l'âge de la session).
    """
    if not value:
        return -1
    try:
        parsed = int(value)
    except ValueError:
        return -2
    return parsed if parsed >= 0 else -2


def first_acr_value(acr_values: str) -> str:
    """Première valeur ``acr_values`` demandée (OIDC Core 1.0 §3.1.2.1).

    Le paramètre porte une liste de valeurs séparées par des espaces ;
    l'OP retourne dans le claim ``acr`` celle qu'il déclare atteinte, ici
    la première demandée — le check ``ValidateIdTokenACRClaimAgainstAcrValuesRequest``
    de la suite exige une valeur **appartenant** à la liste demandée.
    Retourne ``""`` si le paramètre est absent : aucun claim ``acr`` n'est
    alors émis.
    """
    return next(iter(acr_values.split()), "")
